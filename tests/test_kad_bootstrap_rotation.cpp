//
// test_kad_bootstrap_rotation.cpp
//
// Deterministic Kad2 bootstrap retry and response bounds tests.
// Synthetic RFC 5737 endpoints only; no live network dependencies.
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//

#include "test_framework.h"
#include "../Envy/KadBootstrapRotation.h"
#include <cstring>
#include <vector>

namespace
{
KadContact MakeBootstrapContact(size_t index)
{
	KadId id = {};
	id[0] = static_cast<unsigned char>(1u + (index / 255u));
	id[15] = static_cast<unsigned char>(1u + (index % 255u));
	KadContact contact(id, 0xc0000201u + static_cast<uint32_t>(index % 200u),
	                   static_cast<uint16_t>(10000u + index / 200u));
	contact.version = 8;
	return contact;
}

std::vector<KadContact> Candidates(size_t count)
{
	std::vector<KadContact> out;
	for (size_t i = 0; i < count; ++i)
		out.push_back(MakeBootstrapContact(i));
	return out;
}

bool SameEndpoint(const KadContact& a, const KadContact& b)
{
	return a.ip == b.ip && a.udpPort == b.udpPort;
}

bool test_rotation_beyond_prefix()
{
	KadBootstrapRotation policy;
	const auto candidates = Candidates(21);
	for (size_t cycle = 0; cycle < 7; ++cycle)
	{
		const auto batch = policy.Select(candidates, static_cast<uint32_t>(cycle * 30000u));
		if (batch.contacts.size() != KadBootstrapRotation::MaxBatch)
			return false;
		for (size_t j = 0; j < batch.contacts.size(); ++j)
		{
			if (!SameEndpoint(batch.contacts[j], candidates[cycle * 3 + j]))
				return false;
		}
	}
	const auto wrapped = policy.Select(candidates, 210000u);
	return wrapped.contacts.size() == 3 && SameEndpoint(wrapped.contacts[0], candidates[0]);
}

bool test_exhaustion_and_recovery()
{
	KadBootstrapRotation policy;
	const auto candidates = Candidates(2);
	const auto initial = policy.Select(candidates, 0);
	if (initial.contacts.size() != 2)
		return false;
	for (const auto& c : initial.contacts)
		policy.Sent(c.ip, c.udpPort, 0);
	const auto pending = policy.Select(candidates, 1000);
	if (!pending.contacts.empty() || pending.deferred != 2)
		return false;
	for (const auto& c : initial.contacts)
	{
		if (!policy.TimedOut(c.ip, c.udpPort, 30001))
			return false;
	}
	if (!policy.Select(candidates, 90000).contacts.empty())
		return false;
	return policy.Select(candidates, 90001).contacts.size() == 2;
}

bool test_exponential_bounded_backoff()
{
	KadBootstrapRotation policy;
	const auto candidate = MakeBootstrapContact(0);
	const std::vector<KadContact> all = {candidate};
	policy.Sent(candidate.ip, candidate.udpPort, 0);
	if (!policy.TimedOut(candidate.ip, candidate.udpPort, 30001))
		return false;
	if (!policy.Select(all, 90000).contacts.empty())
		return false;
	if (policy.Select(all, 90001).contacts.size() != 1)
		return false;
	policy.Sent(candidate.ip, candidate.udpPort, 90001);
	if (!policy.TimedOut(candidate.ip, candidate.udpPort, 120002))
		return false;
	return policy.Select(all, 240001).contacts.empty() &&
	       policy.Select(all, 240002).contacts.size() == 1 &&
	       KadBootstrapRotation::Delay(100) == KadBootstrapRotation::BackoffCapMs &&
	       KadBootstrapRotation::Delay(0) == 0 &&
	       KadBootstrapRotation::Delay(1) == 60000 &&
	       KadBootstrapRotation::Delay(2) == 120000;
}

bool test_pending_cannot_reenter_without_timeout()
{
	KadBootstrapRotation policy;
	const KadContact candidate = MakeBootstrapContact(0);
	const std::vector<KadContact> all = {candidate};
	policy.Sent(candidate.ip, candidate.udpPort, 0);
	// Elapsed time does not implicitly complete or cancel the request.
	if (!policy.Select(all, 600000).contacts.empty())
		return false;
	if (!policy.TimedOut(candidate.ip, candidate.udpPort, 600000))
		return false;
	if (!policy.Select(all, 659999).contacts.empty())
		return false;
	return policy.Select(all, 660000).contacts.size() == 1;
}

bool test_success_clears_penalty()
{
	KadBootstrapRotation policy;
	const auto c = MakeBootstrapContact(0);
	const std::vector<KadContact> all = {c};
	policy.Sent(c.ip, c.udpPort, 0);
	if (!policy.TimedOut(c.ip, c.udpPort, 30001))
		return false;
	policy.Accepted(c.ip, c.udpPort, c.udpPort, 30002);
	return policy.Tracked() == 1 && policy.Select(all, 30002).contacts.empty() &&
	       policy.Select(all, KadBootstrapRotation::AcceptWindowMs).contacts.size() == 1;
}

bool test_wraparound_timing()
{
	KadBootstrapRotation policy;
	const auto c = MakeBootstrapContact(0);
	const std::vector<KadContact> all = {c};
	const uint64_t start = 0xfffffff0u;
	policy.Sent(c.ip, c.udpPort, start);
	if (!policy.Select(all, start + 2000u).contacts.empty())
		return false;
	const uint64_t timeout = start + 30001u;
	if (!policy.TimedOut(c.ip, c.udpPort, timeout))
		return false;
	return policy.Select(all, timeout + 59999u).contacts.empty() &&
	       policy.Select(all, timeout + 60000u).contacts.size() == 1 &&
	       !KadBootstrapRotation::Elapsed(start + 1u, start + 60000u) &&
	       KadBootstrapRotation::Elapsed(start + 60000u, start + 60000u);
}

bool test_invalid_and_empty_candidates()
{
	KadBootstrapRotation policy;
	if (!policy.Select({}, 0).contacts.empty())
		return false;
	auto all = Candidates(4);
	all[0].udpPort = 0;
	all[1].ip = 0;
	std::memset(all[2].id, 0, KAD_ID_SIZE);
	const auto batch = policy.Select(all, 0);
	return batch.invalid == 3 && batch.contacts.size() == 1 &&
	       SameEndpoint(batch.contacts[0], all[3]) &&
	       !policy.TimedOut(all[3].ip, all[3].udpPort, 30000);
}

bool test_bounded_state()
{
	KadBootstrapRotation policy;
	const auto candidates = Candidates(KadBootstrapRotation::MaxTrackedEndpoints + 52);
	for (const auto& c : candidates)
		policy.Sent(c.ip, c.udpPort, 0);
	if (policy.Tracked() != KadBootstrapRotation::MaxTrackedEndpoints)
		return false;

	KadBootstrapRotation iterating;
	size_t visited = 0;
	while (visited < candidates.size())
	{
		const auto batch = iterating.Select(candidates, static_cast<uint32_t>(visited * 30000u));
		if (batch.contacts.empty())
			return false;
		for (size_t i = 0; i < batch.contacts.size(); ++i)
		{
			if (!SameEndpoint(batch.contacts[i], candidates[visited + i]))
				return false;
		}
		visited += batch.contacts.size();
	}
	return visited == candidates.size();
}

bool test_bounded_state_preserves_pending_request()
{
	KadBootstrapRotation policy;
	const auto candidates = Candidates(KadBootstrapRotation::MaxTrackedEndpoints + 1);
	policy.Sent(candidates[0].ip, candidates[0].udpPort, 0);
	for (size_t i = 1; i < KadBootstrapRotation::MaxTrackedEndpoints; ++i)
		policy.Sent(candidates[i].ip, candidates[i].udpPort, i);
	for (size_t i = 1; i < KadBootstrapRotation::MaxTrackedEndpoints; ++i)
	{
		if (!policy.TimedOut(candidates[i].ip, candidates[i].udpPort,
		                     i + KadBootstrapRotation::RequestTimeoutMs))
			return false;
	}
	policy.Sent(candidates.back().ip, candidates.back().udpPort,
	            KadBootstrapRotation::RequestTimeoutMs + KadBootstrapRotation::MaxTrackedEndpoints);
	if (policy.Tracked() != KadBootstrapRotation::MaxTrackedEndpoints)
		return false;

	const std::vector<KadContact> pending = { candidates[0] };
	return policy.Select(pending, 600000u).contacts.empty() &&
	       policy.TimedOut(candidates[0].ip, candidates[0].udpPort, 600000u);
}

bool test_response_framing_and_correlation_policy()
{
	// Exactly framed lists are fully usable.
	if (KadBootstrapUsableContacts(21, 0) != 0 ||
	    KadBootstrapUsableContacts(46, 1) != 1 ||
	    KadBootstrapUsableContacts(521, KadBootstrapMaxResponseContacts) !=
	        KadBootstrapMaxResponseContacts)
		return false;
	// A body too short for the fixed header yields nothing.
	if (KadBootstrapUsableContacts(20, 0) != 0 || KadBootstrapUsableContacts(20, 5) != 0)
		return false;
	// eMule/aMule keep the framed prefix of a short list instead of discarding
	// the whole response, so a partial contact is dropped but the rest stands.
	if (KadBootstrapUsableContacts(45, 1) != 0 || KadBootstrapUsableContacts(70, 2) != 1 ||
	    KadBootstrapUsableContacts(520, KadBootstrapMaxResponseContacts) !=
	        static_cast<size_t>(KadBootstrapMaxResponseContacts) - 1u)
		return false;
	// An over-counted list is clamped to the local bound, never trusted.
	if (KadBootstrapUsableContacts(546, static_cast<uint16_t>(KadBootstrapMaxResponseContacts + 1u)) !=
	        KadBootstrapMaxResponseContacts ||
	    KadBootstrapUsableContacts(100000, 0xffffu) != KadBootstrapMaxResponseContacts)
		return false;
	// Trailing bytes beyond the announced list stay ignored.
	return KadBootstrapUsableContacts(600, 1) == 1;
}

bool test_cold_start_batch_is_smaller_and_still_rotates()
{
	KadBootstrapRotation policy;
	const auto candidates = Candidates(7);
	const auto first = policy.Select(candidates, 0, KadBootstrapRotation::MaxColdStartBatch);
	if (first.contacts.size() != KadBootstrapRotation::MaxColdStartBatch ||
	    !SameEndpoint(first.contacts[0], candidates[0]))
		return false;
	// The cursor keeps advancing on the short cycle, so a cold start still walks
	// past the leading cache entries instead of re-sampling them.
	const auto second = policy.Select(candidates, 4000, KadBootstrapRotation::MaxColdStartBatch);
	if (second.contacts.size() != 2 || !SameEndpoint(second.contacts[0], candidates[2]))
		return false;
	// A caller cannot exceed the hard batch bound or ask for an empty batch.
	return policy.Select(candidates, 8000, 99).contacts.size() == KadBootstrapRotation::MaxBatch &&
	       policy.Select(candidates, 12000, 0).contacts.size() == 1;
}

bool test_accept_window_matches_sender_ip_on_any_port()
{
	KadBootstrapRotation policy;
	const auto c = MakeBootstrapContact(0);
	// Never correlate a response we did not ask for.
	if (policy.WasRequested(c.ip, 0))
		return false;
	policy.Sent(c.ip, c.udpPort, 1000);
	// Correlated for 180 s on any UDP source port, as eMule/aMule do.
	if (!policy.WasRequested(c.ip, 1000) || !policy.WasRequested(c.ip, 1000 + 179999u))
		return false;
	if (policy.WasRequested(c.ip, 1000 + KadBootstrapRotation::AcceptWindowMs))
		return false;
	// A different IP is never correlated by a neighbour's request.
	if (policy.WasRequested(c.ip + 1u, 1000))
		return false;
	// A late answer still clears the penalty for every port of that IP.
	policy.Accepted(c.ip, c.udpPort, c.udpPort, 30002);
	return policy.Tracked() == 1 && !policy.WasRequested(c.ip, 30002);
}

bool test_accept_window_is_tick_wrap_safe()
{
	KadBootstrapRotation policy;
	const auto c = MakeBootstrapContact(0);
	const uint64_t start = 0xffff0000u;
	policy.Sent(c.ip, c.udpPort, start);
	return policy.WasRequested(c.ip, start + 179999u) &&
	       !policy.WasRequested(c.ip, start + KadBootstrapRotation::AcceptWindowMs);
}

bool test_accepted_clears_only_the_answering_ip()
{
	KadBootstrapRotation policy;
	const auto a = MakeBootstrapContact(0);
	KadContact sameIpOtherPort = a;
	sameIpOtherPort.udpPort = static_cast<uint16_t>(a.udpPort + 1u);
	const auto b = MakeBootstrapContact(1);
	policy.Sent(a.ip, a.udpPort, 0);
	policy.Sent(sameIpOtherPort.ip, sameIpOtherPort.udpPort, 0);
	policy.Sent(b.ip, b.udpPort, 0);
	if (policy.Tracked() != 3)
		return false;
	policy.Accepted(a.ip, a.udpPort, a.udpPort, 1);
	return policy.Tracked() == 3 && policy.WasRequested(a.ip, 1) && policy.WasRequested(b.ip, 1) &&
	       policy.TimedOut(a.ip, sameIpOtherPort.udpPort, 30000);
}
} // namespace

void register_kad_bootstrap_rotation_tests(TestSuite& suite)
{
	suite.add_test("kad_bootstrap_rotation_beyond_prefix", test_rotation_beyond_prefix);
	suite.add_test("kad_bootstrap_exhaustion_recovery", test_exhaustion_and_recovery);
	suite.add_test("kad_bootstrap_exponential_backoff", test_exponential_bounded_backoff);
	suite.add_test("kad_bootstrap_success_resets_penalty", test_success_clears_penalty);
	suite.add_test("kad_bootstrap_pending_never_reselected", test_pending_cannot_reenter_without_timeout);
	suite.add_test("kad_bootstrap_wraparound", test_wraparound_timing);
	suite.add_test("kad_bootstrap_invalid_candidates", test_invalid_and_empty_candidates);
	suite.add_test("kad_bootstrap_bounded_tracking", test_bounded_state);
	suite.add_test("kad_bootstrap_bounded_tracking_keeps_pending", test_bounded_state_preserves_pending_request);
	suite.add_test("kad_bootstrap_response_bounds", test_response_framing_and_correlation_policy);
	suite.add_test("kad_bootstrap_cold_start_batch", test_cold_start_batch_is_smaller_and_still_rotates);
	suite.add_test("kad_bootstrap_accept_window_any_port", test_accept_window_matches_sender_ip_on_any_port);
	suite.add_test("kad_bootstrap_accept_window_wraparound", test_accept_window_is_tick_wrap_safe);
	suite.add_test("kad_bootstrap_accept_clears_one_ip", test_accepted_clears_only_the_answering_ip);
}
