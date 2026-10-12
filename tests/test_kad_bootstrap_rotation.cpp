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
	policy.Accepted(c.ip, c.udpPort);
	return policy.Tracked() == 0 && policy.Select(all, 30002).contacts.size() == 1;
}

bool test_wraparound_timing()
{
	KadBootstrapRotation policy;
	const auto c = MakeBootstrapContact(0);
	const std::vector<KadContact> all = {c};
	const uint32_t start = 0xfffffff0u;
	policy.Sent(c.ip, c.udpPort, start);
	if (!policy.Select(all, start + 2000u).contacts.empty())
		return false;
	const uint32_t timeout = start + 30001u;
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
	{
		const uint32_t now = static_cast<uint32_t>(i);
		policy.Sent(candidates[i].ip, candidates[i].udpPort, now);
		if (!policy.TimedOut(candidates[i].ip, candidates[i].udpPort,
		                     now + KadBootstrapRotation::RequestTimeoutMs + 1u))
			return false;
	}
	policy.Sent(candidates.back().ip, candidates.back().udpPort,
	            static_cast<uint32_t>(KadBootstrapRotation::MaxTrackedEndpoints));
	if (policy.Tracked() != KadBootstrapRotation::MaxTrackedEndpoints)
		return false;

	const std::vector<KadContact> pending = { candidates[0] };
	return policy.Select(pending, 600000u).contacts.empty() &&
	       policy.TimedOut(candidates[0].ip, candidates[0].udpPort, 600000u);
}

bool test_response_framing_and_correlation_policy()
{
	if (!KadBootstrapResponseLengthValid(21, 0) ||
	    !KadBootstrapResponseLengthValid(46, 1) ||
	    !KadBootstrapResponseLengthValid(521, KadBootstrapMaxResponseContacts))
		return false;
	if (KadBootstrapResponseLengthValid(20, 0) ||
	    KadBootstrapResponseLengthValid(45, 1) ||
	    KadBootstrapResponseLengthValid(520, KadBootstrapMaxResponseContacts) ||
	    KadBootstrapResponseLengthValid(546, KadBootstrapMaxResponseContacts + 1u))
		return false;

	KadBootstrapRotation policy;
	const auto c = MakeBootstrapContact(0);
	const std::vector<KadContact> all = {c};
	policy.Sent(c.ip, c.udpPort, 0);
	// A truncated response does not clear pending state.
	if (KadBootstrapResponseLengthValid(45, 1) ||
	    !policy.Select(all, 1000).contacts.empty())
		return false;
	policy.Accepted(c.ip, c.udpPort);
	return policy.Select(all, 1000).contacts.size() == 1;
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
}
