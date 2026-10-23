// Deterministic tests of the production bootstrap handler and request lifecycle.
// Only the packet storage, clock and contact-admission boundary are adapters.
// This file is part of Envy (getenvy.com) (C) 2016-2026
// SPDX-License-Identifier: AGPL-3.0-or-later

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include "test_framework.h"
#include "../Envy/KadBootstrapRotation.h"
#include "../Envy/KadOutstandingRequest.h"
#include <set>
#include <stdexcept>
#include <utility>

#pragma comment(lib, "ws2_32.lib")

namespace
{
uint64_t testNow = 1000;
uint64_t KadNowMs() { return testNow; }
constexpr size_t KAD2_MAX_OUTSTANDING_REQUESTS = 10;
constexpr uint64_t KAD2_REQUEST_TIMEOUT = 30000;

class CEDPacket
{
public:
	std::vector<BYTE> body;
	size_t position = 0;
	size_t GetRemaining() const { return body.size() - position; }
	void Read(void* out, size_t count)
	{
		if (count > GetRemaining())
			throw std::runtime_error("bootstrap read past packet boundary");
		std::memcpy(out, body.data() + position, count);
		position += count;
	}
	BYTE ReadByte()
	{
		BYTE value;
		Read(&value, 1);
		return value;
	}
	WORD ReadShortLE()
	{
		const WORD low = ReadByte();
		return static_cast<WORD>(low | (static_cast<WORD>(ReadByte()) << 8));
	}
	DWORD ReadLongLE()
	{
		const DWORD low = ReadShortLE();
		return low | (static_cast<DWORD>(ReadShortLE()) << 16);
	}
};

// Compile the same method bodies and request metadata as CKademlia, without
// linking the application singleton, UI, sockets or real peer security policy.
class CKademlia
{
public:
	KadBootstrapRotation m_bootstrapRotation;
	std::map<DWORD, KadOutstandingRequest> m_outstandingRequests;
	uint32_t m_bootstrapMalformed = 0, m_bootstrapPartial = 0, m_bootstrapRejected = 0;
	uint32_t m_bootstrapContactsRefused = 0, m_bootstrapBlocked = 0;
	uint32_t m_bootstrapResponses = 0, m_bootstrapAccepted = 0, m_bootstrapTimeouts = 0;
	std::vector<KadContact> admitted;
	// When set, admission is the production routing table (address policy, per-IP
	// and per-/24 diversity, bin capacity) instead of the always-admit adapter.
	Kad2RoutingTable* table = nullptr;
	bool UpdateContact(const KadContact& c, KadContactSource source, bool verified)
	{
		if (verified)
			throw std::runtime_error("bootstrap must not mark contacts verified");
		if (table != nullptr)
		{
			KadContactUpdate update;
			update.source = source;
			update.markAlive = source == KadContactSource::Observed;
			update.nowMs = KadNowMs();
			if (!table->AddContact(c, update))
				return false;
		}
		admitted.push_back(c);
		return true;
	}
	void OnBootstrapResponse(const SOCKADDR_IN*, CEDPacket*);
	DWORD AddOutstandingRequest(KadRequestType, const SOCKADDR_IN&);
	DWORD AddOutstandingRequest(KadRequestType, const SOCKADDR_IN&, const KadId&);
	bool IsRequestOutstanding(DWORD, KadRequestType, const SOCKADDR_IN&);
	bool IsRequestOutstanding(DWORD, KadRequestType, const SOCKADDR_IN&, const KadId&);
	bool MatchOutstandingRequest(DWORD, KadRequestType, const SOCKADDR_IN&, const unsigned char*);
	void RemoveOutstandingRequest(DWORD);
	void CleanupExpiredRequests();
};

#include "../Envy/KademliaBootstrap.inl"

SOCKADDR_IN Endpoint(uint16_t port = 4672, uint32_t ip = 0xc0000201u)
{
	SOCKADDR_IN addr = {};
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(ip);
	addr.sin_port = htons(port);
	return addr;
}

CEDPacket Reply(size_t framed = 0, uint16_t announced = 0, size_t trailing = 0)
{
	CEDPacket packet;
	packet.body.resize(KadBootstrapResponseHeaderBytes + framed * KadBootstrapContactBytes + trailing);
	packet.body[0] = 1; // Synthetic non-zero responder ID.
	packet.body[16] = 0x36;
	packet.body[17] = 0x12;
	packet.body[18] = 8;
	packet.body[19] = static_cast<BYTE>(announced);
	packet.body[20] = static_cast<BYTE>(announced >> 8);
	for (size_t i = 0; i < framed; ++i)
	{
		const size_t offset = KadBootstrapResponseHeaderBytes + i * KadBootstrapContactBytes;
		packet.body[offset] = static_cast<BYTE>(i + 2);
		packet.body[offset + 16] = static_cast<BYTE>(i + 1);
		packet.body[offset + 19] = 0xcb; // RFC 5737: 203.0.0.x fixture only.
		packet.body[offset + 20] = 0x40;
		packet.body[offset + 21] = 0x12;
		packet.body[offset + 24] = 8;
	}
	return packet;
}

// True when the reply was accepted as an answer, whether fully framed (counted as
// a valid response) or partial (counted apart): exactly one of the two moved.
bool Respond(CKademlia& kad, const SOCKADDR_IN& from, CEDPacket packet = Reply())
{
	const uint32_t before = kad.m_bootstrapResponses + kad.m_bootstrapPartial;
	kad.OnBootstrapResponse(&from, &packet);
	return kad.m_bootstrapResponses + kad.m_bootstrapPartial == before + 1;
}

bool test_expected_port()
{
	testNow = 1000;
	CKademlia kad;
	const auto addr = Endpoint();
	const auto unrelated = kad.AddOutstandingRequest(KAD_REQUEST_HELLO, addr);
	kad.AddOutstandingRequest(KAD_REQUEST_BOOTSTRAP, addr);
	return Respond(kad, addr) && kad.m_outstandingRequests.size() == 1 &&
	       kad.m_outstandingRequests.count(unrelated) == 1 && kad.admitted.size() == 1;
}

bool test_changed_port()
{
	testNow = 1000;
	CKademlia kad;
	kad.AddOutstandingRequest(KAD_REQUEST_BOOTSTRAP, Endpoint());
	return Respond(kad, Endpoint(6000)) && kad.m_outstandingRequests.empty() &&
	       !Respond(kad, Endpoint(6000)) && !Respond(kad, Endpoint()) &&
	       kad.m_bootstrapResponses == 1 && kad.m_bootstrapTimeouts == 0;
}

bool test_unsolicited()
{
	testNow = 1000;
	CKademlia kad;
	kad.AddOutstandingRequest(KAD_REQUEST_BOOTSTRAP, Endpoint());
	return !Respond(kad, Endpoint(4672, 0xc0000202u)) && kad.admitted.empty() &&
	       kad.m_outstandingRequests.size() == 1;
}

bool test_independent_ports_and_duplicates()
{
	testNow = 1000;
	CKademlia kad;
	kad.AddOutstandingRequest(KAD_REQUEST_BOOTSTRAP, Endpoint());
	const auto other = kad.AddOutstandingRequest(KAD_REQUEST_BOOTSTRAP, Endpoint(5000));
	if (Respond(kad, Endpoint(6000)) || kad.m_outstandingRequests.size() != 2)
		return false; // Ambiguous fallback must not guess which request to consume.
	if (!Respond(kad, Endpoint()) || kad.m_outstandingRequests.count(other) != 1)
		return false;
	if (Respond(kad, Endpoint()) || kad.m_outstandingRequests.count(other) != 1)
		return false; // Duplicate of the first reply cannot consume the second.
	KadId id = { 1 };
	const KadContact candidate(id, 0xc0000201u, 5000);
	if (!kad.m_bootstrapRotation.Select({ candidate }, testNow).contacts.empty())
		return false;
	return Respond(kad, Endpoint(5000)) && kad.m_outstandingRequests.empty() &&
	       !Respond(kad, Endpoint(5000)) && kad.m_bootstrapResponses == 2;
}

bool test_completed_port_cannot_consume_other_request()
{
	testNow = 1000;
	CKademlia kad;
	kad.AddOutstandingRequest(KAD_REQUEST_BOOTSTRAP, Endpoint());
	if (!Respond(kad, Endpoint(6000)))
		return false;
	const auto other = kad.AddOutstandingRequest(KAD_REQUEST_BOOTSTRAP, Endpoint(5000));
	if (Respond(kad, Endpoint(6000)) || Respond(kad, Endpoint()) ||
	    kad.m_outstandingRequests.count(other) != 1)
		return false;
	return Respond(kad, Endpoint(7000)) && kad.m_outstandingRequests.empty();
}

bool test_capacity_age_crosses_32bit_boundary()
{
	testNow = 0xfffffff0ull;
	CKademlia kad;
	const auto oldest = kad.AddOutstandingRequest(KAD_REQUEST_BOOTSTRAP, Endpoint());
	testNow += 1000;
	for (uint16_t port = 5000; port < 5010; ++port)
		kad.AddOutstandingRequest(KAD_REQUEST_HELLO, Endpoint(port));
	return kad.m_outstandingRequests.size() == KAD2_MAX_OUTSTANDING_REQUESTS &&
	       kad.m_outstandingRequests.count(oldest) == 0 && kad.m_bootstrapTimeouts == 0 &&
	       !Respond(kad, Endpoint());
}

bool test_partial_first_contact_keeps_responder()
{
	testNow = 1000;
	CKademlia kad;
	kad.AddOutstandingRequest(KAD_REQUEST_BOOTSTRAP, Endpoint());
	return Respond(kad, Endpoint(), Reply(0, 1, 24)) && kad.admitted.size() == 1 &&
	       kad.m_bootstrapPartial == 1 && kad.m_bootstrapResponses == 0 &&
	       kad.m_outstandingRequests.empty();
}

bool test_other_pending_still_times_out()
{
	testNow = 1000;
	CKademlia kad;
	kad.AddOutstandingRequest(KAD_REQUEST_BOOTSTRAP, Endpoint());
	kad.AddOutstandingRequest(KAD_REQUEST_BOOTSTRAP, Endpoint(5000));
	if (!Respond(kad, Endpoint()))
		return false;
	testNow += KAD2_REQUEST_TIMEOUT;
	kad.CleanupExpiredRequests();
	KadId id = { 1 };
	const KadContact candidate(id, 0xc0000201u, 5000);
	return kad.m_bootstrapTimeouts == 1 && kad.m_outstandingRequests.empty() &&
	       kad.m_bootstrapRotation.Select({ candidate }, testNow).contacts.empty();
}

bool test_late_reply()
{
	testNow = 1000;
	CKademlia kad;
	kad.AddOutstandingRequest(KAD_REQUEST_BOOTSTRAP, Endpoint());
	testNow += KAD2_REQUEST_TIMEOUT;
	kad.CleanupExpiredRequests();
	if (!kad.m_outstandingRequests.empty() || kad.m_bootstrapTimeouts != 1)
		return false;
	testNow = 180999;
	return Respond(kad, Endpoint(6000)) && !Respond(kad, Endpoint(6000));
}

bool test_expired_reply()
{
	testNow = 1000;
	CKademlia kad;
	kad.AddOutstandingRequest(KAD_REQUEST_BOOTSTRAP, Endpoint());
	testNow += KadBootstrapRotation::AcceptWindowMs;
	return !Respond(kad, Endpoint()) && !Respond(kad, Endpoint(6000)) &&
	       kad.m_outstandingRequests.empty() && kad.m_bootstrapTimeouts == 1;
}

bool test_capacity_eviction_is_cancellation()
{
	testNow = 1000;
	CKademlia kad;
	const auto first = kad.AddOutstandingRequest(KAD_REQUEST_BOOTSTRAP, Endpoint());
	for (uint16_t port = 5000; port < 5010; ++port)
	{
		++testNow;
		kad.AddOutstandingRequest(KAD_REQUEST_HELLO, Endpoint(port));
	}
	KadId id = { 1 };
	const KadContact candidate(id, 0xc0000201u, 4672);
	return kad.m_outstandingRequests.size() == KAD2_MAX_OUTSTANDING_REQUESTS &&
	       kad.m_outstandingRequests.count(first) == 0 && kad.m_bootstrapTimeouts == 0 &&
	       !Respond(kad, Endpoint()) &&
	       kad.m_bootstrapRotation.Select({ candidate }, testNow).contacts.size() == 1;
}

bool test_evicted_reply_cannot_consume_independent_request()
{
	testNow = 1000;
	CKademlia kad;
	const auto evicted = kad.AddOutstandingRequest(KAD_REQUEST_BOOTSTRAP, Endpoint());
	++testNow;
	const auto independent = kad.AddOutstandingRequest(KAD_REQUEST_BOOTSTRAP, Endpoint(5000));
	for (uint16_t port = 7000; port < 7009; ++port)
	{
		++testNow;
		kad.AddOutstandingRequest(KAD_REQUEST_HELLO, Endpoint(port, 0xc0000202u));
	}
	if (kad.m_outstandingRequests.count(evicted) != 0 ||
	    kad.m_outstandingRequests.count(independent) != 1 || kad.m_bootstrapTimeouts != 0)
		return false;
	// The cancelled peer's reply port was never observed. Neither its original
	// port nor an unknown alternate port can safely use the remaining IP credit.
	if (Respond(kad, Endpoint()) || Respond(kad, Endpoint(6000)) ||
	    kad.m_outstandingRequests.count(independent) != 1)
		return false;
	return Respond(kad, Endpoint(5000)) && kad.m_outstandingRequests.count(independent) == 0;
}

bool test_explicit_cancel_and_real_timeout()
{
	testNow = 1000;
	CKademlia kad;
	const auto request = kad.AddOutstandingRequest(KAD_REQUEST_BOOTSTRAP, Endpoint());
	kad.RemoveOutstandingRequest(request);
	if (Respond(kad, Endpoint()) || kad.m_bootstrapTimeouts != 0)
		return false;
	kad.AddOutstandingRequest(KAD_REQUEST_BOOTSTRAP, Endpoint());
	testNow += KAD2_REQUEST_TIMEOUT - 1;
	kad.CleanupExpiredRequests();
	if (kad.m_outstandingRequests.empty() || kad.m_bootstrapTimeouts != 0)
		return false;
	++testNow;
	kad.CleanupExpiredRequests();
	return kad.m_outstandingRequests.empty() && kad.m_bootstrapTimeouts == 1;
}

bool LongIdle(uint64_t gap)
{
	testNow = 1000;
	CKademlia kad;
	kad.AddOutstandingRequest(KAD_REQUEST_BOOTSTRAP, Endpoint());
	testNow += KAD2_REQUEST_TIMEOUT;
	kad.CleanupExpiredRequests();
	testNow += gap;
	if (Respond(kad, Endpoint()))
		return false;
	KadId id = { 1 };
	const KadContact candidate(id, 0xc0000201u, 4672);
	return kad.m_bootstrapRotation.Select({ candidate }, testNow).contacts.size() == 1 &&
	       kad.m_bootstrapRotation.Tracked() == 0;
}

bool test_long_idle_half_cycle() { return LongIdle((uint64_t{ 1 } << 31) + 1000); }
bool test_long_idle_full_cycle() { return LongIdle((uint64_t{ 1 } << 32) + 1000); }

bool test_pending_full_cycle()
{
	testNow = 1000;
	CKademlia kad;
	kad.AddOutstandingRequest(KAD_REQUEST_BOOTSTRAP, Endpoint());
	testNow += (uint64_t{ 1 } << 32) + 1;
	return !Respond(kad, Endpoint()) && kad.m_outstandingRequests.empty() &&
	       kad.m_bootstrapTimeouts == 1;
}

bool test_crosses_32bit_clock_boundary()
{
	testNow = 0xfffffff0ull;
	CKademlia kad;
	kad.AddOutstandingRequest(KAD_REQUEST_BOOTSTRAP, Endpoint());
	testNow += 1000;
	return Respond(kad, Endpoint(6000)) && kad.m_outstandingRequests.empty();
}

bool test_truncated_header_preserves_request()
{
	testNow = 1000;
	CKademlia kad;
	kad.AddOutstandingRequest(KAD_REQUEST_BOOTSTRAP, Endpoint());
	for (size_t length = 0; length < KadBootstrapResponseHeaderBytes; ++length)
	{
		auto packet = Reply();
		packet.body.resize(length);
		if (Respond(kad, Endpoint(), packet) || kad.m_outstandingRequests.size() != 1)
			return false;
	}
	return kad.m_bootstrapMalformed == KadBootstrapResponseHeaderBytes && Respond(kad, Endpoint());
}

bool test_partial_contacts_keep_framed_prefix()
{
	testNow = 1000;
	CKademlia kad;
	kad.AddOutstandingRequest(KAD_REQUEST_BOOTSTRAP, Endpoint());
	if (!Respond(kad, Endpoint(6000), Reply(1, 2, 24)) || kad.admitted.size() != 2 ||
	    kad.m_bootstrapPartial != 1 || kad.m_bootstrapResponses != 0 || !kad.m_outstandingRequests.empty())
		return false;
	return kad.admitted[0].id[0] == 2 && kad.admitted[0].udpPort == 4672 &&
	       kad.admitted[1].udpPort == 6000 && !Respond(kad, Endpoint(6000), Reply(1, 2, 24));
}

bool test_receive_cap_and_trailing_bytes()
{
	testNow = 1000;
	CKademlia kad;
	kad.AddOutstandingRequest(KAD_REQUEST_BOOTSTRAP, Endpoint());
	return Respond(kad, Endpoint(), Reply(21, 21, 10)) && kad.admitted.size() == 21 &&
	       kad.m_bootstrapPartial == 1 && kad.m_bootstrapResponses == 0;
}

void Feed(CKademlia& kad, const SOCKADDR_IN& from, CEDPacket packet)
{
	kad.OnBootstrapResponse(&from, &packet);
}

// A datagram nobody asked for must not move any "answered" counter, whatever its
// framing; otherwise any UDP sender could inflate the diagnostics.
bool test_unsolicited_never_counts_as_answer()
{
	testNow = 1000;
	CKademlia kad;
	const auto pending = kad.AddOutstandingRequest(KAD_REQUEST_BOOTSTRAP, Endpoint());
	const auto stranger = Endpoint(4672, 0xc0000209u);
	for (int i = 0; i < 250; ++i)
	{
		Feed(kad, stranger, Reply(0, 20, 0));  // announces 20, carries none
		Feed(kad, stranger, Reply(1, 2, 24));  // short list
		Feed(kad, stranger, Reply(25, 25, 0)); // above the local bound
		Feed(kad, stranger, Reply(3, 3, 0));   // clean
	}
	return kad.m_bootstrapResponses == 0 && kad.m_bootstrapPartial == 0 &&
	       kad.m_bootstrapRejected == 1000 && kad.m_bootstrapMalformed == 0 && kad.admitted.empty() &&
	       kad.m_outstandingRequests.count(pending) == 1;
}

// Only a fully framed reply within the local bound is a valid response. A short or
// over-counted one is still used (the references keep the framed prefix, and the
// request is consumed) but is counted apart, never as valid.
bool test_partial_replies_are_not_valid_responses()
{
	struct Case
	{
		size_t framed;
		uint16_t announced;
		size_t trailing;
		bool partial;
		size_t admitted; // contacts read plus the responder itself
	};
	const Case cases[] = {
		{ 0, 0, 0, false, 1 },     // empty, complete
		{ 3, 3, 0, false, 4 },     // clean
		{ 20, 20, 10, false, 21 }, // at the bound, trailing bytes ignored
		{ 0, 4, 0, true, 1 },      // header only, list absent: the responder alone
		{ 1, 2, 24, true, 2 },     // one whole contact, one cut short
		{ 3, 5, 0, true, 4 },      // short list
		{ 25, 25, 0, true, 21 },   // fully framed but above the local bound of 20
		{ 0, 0xffff, 0, true, 1 }  // absurd announcement, nothing carried
	};
	for (const Case& c : cases)
	{
		testNow = 1000;
		CKademlia kad;
		kad.AddOutstandingRequest(KAD_REQUEST_BOOTSTRAP, Endpoint());
		if (!Respond(kad, Endpoint(), Reply(c.framed, c.announced, c.trailing)))
			return false;
		if (kad.m_bootstrapPartial != (c.partial ? 1u : 0u) ||
		    kad.m_bootstrapResponses != (c.partial ? 0u : 1u) || kad.admitted.size() != c.admitted)
			return false;
		// Consumed in both cases: nothing left in flight, and a repeat is rejected.
		if (!kad.m_outstandingRequests.empty() || Respond(kad, Endpoint()) || kad.m_bootstrapRejected != 1)
			return false;
	}
	return true;
}

// A partial reply must leave the rotation exactly as a complete one does.
bool test_partial_reply_consumes_like_a_complete_one()
{
	const auto after = [](CEDPacket packet)
	{
		testNow = 1000;
		CKademlia kad;
		kad.AddOutstandingRequest(KAD_REQUEST_BOOTSTRAP, Endpoint());
		testNow += KAD2_REQUEST_TIMEOUT;
		kad.CleanupExpiredRequests(); // a genuine timeout: the endpoint is now in backoff
		testNow += 1000;
		const auto from = Endpoint();
		kad.OnBootstrapResponse(&from, &packet); // late but inside the window
		KadId id = { 1 };
		const KadContact candidate(id, 0xc0000201u, 4672);
		return std::make_pair(kad.m_bootstrapResponses + kad.m_bootstrapPartial,
		                      kad.m_bootstrapRotation.Select({ candidate }, testNow).contacts.size());
	};
	const auto complete = after(Reply(2, 2, 0));
	const auto partial = after(Reply(0, 9, 0));
	return complete.first == 1 && partial.first == 1 && complete.second == partial.second;
}

struct ColdStartRun
{
	size_t sent = 0;
	size_t peakInFlight = 0;
	size_t oversized = 0; // a batch larger than the limit it was asked for
	size_t blocked = 0;   // cycles where the full budget allowed nothing
	uint64_t fullCoverageMs = 0;
};

// A cold start where no peer answers, through the production request lifecycle:
// AddOutstandingRequest registers the request with the retry policy and
// CleanupExpiredRequests expires it into backoff. Only the few lines of
// CKademlia::Bootstrap that bound the batch, select and send are repeated here.
ColdStartRun SilentColdStart(size_t cacheSize, uint64_t tickMs, uint64_t horizonMs)
{
	CKademlia kad;
	std::vector<KadContact> cache;
	for (size_t i = 0; i < cacheSize; ++i)
	{
		KadId id = {};
		id[0] = 1;
		id[1] = static_cast<unsigned char>(i & 0xffu);
		id[2] = static_cast<unsigned char>(i >> 8);
		cache.emplace_back(id, 0xc0000201u + static_cast<uint32_t>(i), uint16_t{ 4672 });
	}
	std::set<uint32_t> contacted;
	ColdStartRun run;
	const uint64_t start = 1000;
	for (uint64_t now = start; now < start + horizonMs; now += tickMs)
	{
		testNow = now;
		kad.CleanupExpiredRequests();
		const size_t limit = KadBootstrapBatchLimit(KadBootstrapRotation::MaxColdStartBatch,
		                                            kad.m_outstandingRequests.size(),
		                                            KAD2_MAX_OUTSTANDING_REQUESTS);
		if (limit == 0)
		{
			++run.blocked;
			continue;
		}
		const auto batch = kad.m_bootstrapRotation.Select(cache, now, limit);
		if (batch.contacts.size() > limit)
			++run.oversized;
		for (const KadContact& c : batch.contacts)
		{
			if (kad.AddOutstandingRequest(KAD_REQUEST_BOOTSTRAP, Endpoint(c.udpPort, c.ip)) == 0)
				continue;
			contacted.insert(c.ip);
			++run.sent;
		}
		run.peakInFlight = std::max(run.peakInFlight, kad.m_outstandingRequests.size());
		if (run.fullCoverageMs == 0 && contacted.size() == cacheSize)
			run.fullCoverageMs = now - start;
	}
	return run;
}

bool test_cold_start_covers_the_cache_within_the_budget()
{
	// The periodic caller runs once per six one-second timer ticks (about 6 s, never
	// closer than 5 s). 50 cached peers, none answering, ten minutes.
	const ColdStartRun r = SilentColdStart(50, 6000, 600000);
	// Bounded: the budget is never exceeded, a batch never outgrows its limit, and
	// the total stays below the one request per two seconds of the references.
	if (r.peakInFlight > KAD2_MAX_OUTSTANDING_REQUESTS - 1 || r.oversized != 0 ||
	    r.sent > 600000u / 2000u)
		return false;
	// Nothing is selected and left untried: the whole cache gets a first request in
	// under three and a half minutes. Selecting first and cutting the send loop on
	// the budget took over seven minutes here.
	return r.fullCoverageMs != 0 && r.fullCoverageMs <= 210000;
}

bool test_cold_start_rate_is_set_by_the_budget_not_the_tick()
{
	const ColdStartRun six = SilentColdStart(50, 6000, 600000);
	const ColdStartRun five = SilentColdStart(50, 5000, 600000);
	const ColdStartRun large = SilentColdStart(200, 6000, 600000);
	// A slightly shorter tick changes nothing: nine slots held for 30 s cap the rate
	// at 0.3 requests/s whatever the cycle.
	const size_t spread = six.sent > five.sent ? six.sent - five.sent : five.sent - six.sent;
	if (spread * 10 > six.sent)
		return false;
	// Sustained cold-start rate: above 0.2 and at most 0.3 requests/s, under the
	// references' 0.5. A larger cache stays bounded the same way.
	return six.sent >= 120 && six.sent <= 180 && large.peakInFlight <= KAD2_MAX_OUTSTANDING_REQUESTS - 1 &&
	       large.oversized == 0 && large.sent <= 180;
}
// Unsolicited and ambiguous replies are correlation rejections; contacts that a
// correlated reply carried but routing refused are a different outcome. Neither
// may be reported as the other, and neither is a timeout.
bool test_outcomes_are_counted_apart()
{
	testNow = 1000;
	CKademlia kad;
	Kad2RoutingTable table;
	KadId own = { 0x7f };
	table.Initialize(own);
	kad.table = &table;
	kad.AddOutstandingRequest(KAD_REQUEST_BOOTSTRAP, Endpoint());

	// Uncorrelated: a stranger answers a request nobody sent it.
	Feed(kad, Endpoint(4672, 0xc0000209u), Reply(3, 3, 0));
	if (kad.m_bootstrapRejected != 1 || kad.m_bootstrapContactsRefused != 0 ||
	    kad.m_bootstrapTimeouts != 0 || !kad.admitted.empty() || table.GetTotalContacts() != 0)
		return false;

	// Correlated, but one /24 floods the table: a valid response with refused contacts.
	if (!Respond(kad, Endpoint(), Reply(20, 20, 0)))
		return false;
	return kad.m_bootstrapResponses == 1 && kad.m_bootstrapRejected == 1 &&
	       kad.m_bootstrapContactsRefused > 0 && kad.m_bootstrapTimeouts == 0 &&
	       kad.m_bootstrapAccepted == kad.admitted.size() &&
	       kad.m_bootstrapAccepted + kad.m_bootstrapContactsRefused == 21;
}

// A reply that lists 20 contacts in one /24 must not fill the routing table from
// that network, and every contact it does admit stays an unverified candidate.
bool test_reply_cannot_fill_table_from_one_subnet()
{
	testNow = 1000;
	CKademlia kad;
	Kad2RoutingTable table;
	KadId own = { 0x7f };
	table.Initialize(own);
	kad.table = &table;
	kad.AddOutstandingRequest(KAD_REQUEST_BOOTSTRAP, Endpoint());
	if (!Respond(kad, Endpoint(), Reply(20, 20, 0)))
		return false;

	size_t sameSubnet = 0;
	bool anyVerified = false;
	std::vector<KadContact> held;
	table.GetContactsForBootstrap(held, static_cast<int>(KAD_MAX_CONTACTS));
	for (const KadContact& c : held)
	{
		if ((c.ip & 0xffffff00u) == 0xcb000000u)
			++sameSubnet;
		anyVerified = anyVerified || c.verified || c.receivedHello;
	}
	// The responder sits in another /24 and is admitted next to the capped group.
	return sameSubnet >= 1 && sameSubnet <= KAD_MAX_CONTACTS_SUBNET_GLOBAL &&
	       table.GetTotalContacts() == sameSubnet + 1 && !anyVerified &&
	       kad.m_outstandingRequests.empty();
}

// A bootstrap registration the retry policy refuses sends nothing, so it must show
// up in the aggregate status line instead of leaving every counter at zero.
bool test_refused_registration_is_counted()
{
	testNow = 1000;
	CKademlia kad;
	if (kad.AddOutstandingRequest(KAD_REQUEST_BOOTSTRAP, Endpoint()) == 0 || kad.m_bootstrapBlocked != 0)
		return false;
	// Still in flight: a second registration for the same endpoint is refused.
	if (kad.AddOutstandingRequest(KAD_REQUEST_BOOTSTRAP, Endpoint()) != 0 || kad.m_bootstrapBlocked != 1)
		return false;
	// Answered, inside the 180 s window: refused again, replay protection intact.
	if (!Respond(kad, Endpoint()) || kad.AddOutstandingRequest(KAD_REQUEST_BOOTSTRAP, Endpoint()) != 0)
		return false;
	return kad.m_bootstrapBlocked == 2 && kad.m_outstandingRequests.empty();
}

// Replies that fail correlation (spoofed source, wrong IP, ambiguous port) leave
// the genuine requests pending, so they still age into real timeouts and backoff.
bool test_spoofed_replies_do_not_hide_a_timeout()
{
	testNow = 1000;
	CKademlia kad;
	const auto pending = kad.AddOutstandingRequest(KAD_REQUEST_BOOTSTRAP, Endpoint());
	const auto second = kad.AddOutstandingRequest(KAD_REQUEST_BOOTSTRAP, Endpoint(5000));
	Feed(kad, Endpoint(4672, 0xc0000209u), Reply(2, 2, 0)); // other IP, requested port
	Feed(kad, Endpoint(9, 0xc0000209u), Reply(2, 2, 0));    // other IP, other port
	Feed(kad, Endpoint(6000), Reply(2, 2, 0));              // right IP, two candidates
	if (kad.m_bootstrapRejected != 3 || kad.m_outstandingRequests.size() != 2 ||
	    kad.m_outstandingRequests.count(pending) != 1 || kad.m_outstandingRequests.count(second) != 1 ||
	    !kad.admitted.empty() || kad.m_bootstrapResponses != 0 || kad.m_bootstrapPartial != 0)
		return false;
	testNow += KAD2_REQUEST_TIMEOUT;
	kad.CleanupExpiredRequests();
	KadId id = { 1 };
	const KadContact first(id, 0xc0000201u, 4672);
	const KadContact other(id, 0xc0000201u, 5000);
	return kad.m_bootstrapTimeouts == 2 && kad.m_outstandingRequests.empty() &&
	       kad.m_bootstrapRotation.Select({ first, other }, testNow).contacts.empty();
}

// Twenty cached candidates, no routing contact, nobody answers. Through the
// production request lifecycle every candidate is tried, then retried only after
// its own timeout plus a doubling delay that stops at the cap, for the whole run.
bool test_twenty_silent_candidates_follow_the_backoff_schedule()
{
	testNow = 1000;
	CKademlia kad;
	std::vector<KadContact> cache;
	for (uint32_t i = 0; i < 20; ++i)
	{
		KadId id = { 1, static_cast<unsigned char>(i) };
		cache.emplace_back(id, 0xc0000201u + i * 256u, uint16_t{ 4672 });
	}
	std::map<uint32_t, std::vector<uint64_t>> sends;
	const uint64_t start = 1000, horizon = 3u * 60u * 60u * 1000u, tick = 6000;
	for (uint64_t now = start; now < start + horizon; now += tick)
	{
		testNow = now;
		kad.CleanupExpiredRequests();
		const size_t limit = KadBootstrapBatchLimit(KadBootstrapRotation::MaxColdStartBatch,
		                                            kad.m_outstandingRequests.size(),
		                                            KAD2_MAX_OUTSTANDING_REQUESTS);
		if (limit == 0)
			continue;
		for (const KadContact& c : kad.m_bootstrapRotation.Select(cache, now, limit).contacts)
			if (kad.AddOutstandingRequest(KAD_REQUEST_BOOTSTRAP, Endpoint(c.udpPort, c.ip)) != 0)
				sends[c.ip].push_back(now);
	}
	if (sends.size() != cache.size())
		return false; // an untried candidate was skipped
	for (const auto& entry : sends)
	{
		const auto& times = entry.second;
		if (times.size() < 2)
			return false;
		for (size_t k = 1; k < times.size(); ++k)
		{
			// k-th retry: the timeout, then Delay(k) (60 s doubling, capped at 10 min).
			static const uint64_t delaySeconds[] = { 60, 120, 240, 480, 600 };
			const uint64_t floorMs = KAD2_REQUEST_TIMEOUT + 1000u * delaySeconds[std::min<size_t>(k, 5) - 1];
			if (times[k] - times[k - 1] < floorMs)
				return false; // retried before its backoff elapsed
			if (k >= 5 && times[k] - times[k - 1] > 2u * KadBootstrapRotation::BackoffCapMs)
				return false; // a capped peer must not be abandoned
		}
		// The cap bounds the per-peer rate: about one request per 10.5 minutes.
		if (times.size() > horizon / (KadBootstrapRotation::BackoffCapMs + KadBootstrapRotation::RequestTimeoutMs) + 8)
			return false;
	}
	return kad.m_bootstrapResponses == 0 && kad.m_bootstrapTimeouts > cache.size();
}
} // namespace

void register_kad_bootstrap_response_tests(TestSuite& suite)
{
	suite.add_test("kad_response_expected_port", test_expected_port);
	suite.add_test("kad_response_changed_port_consumes_original", test_changed_port);
	suite.add_test("kad_response_unsolicited", test_unsolicited);
	suite.add_test("kad_response_independent_ports_duplicates", test_independent_ports_and_duplicates);
	suite.add_test("kad_response_completed_port_replay", test_completed_port_cannot_consume_other_request);
	suite.add_test("kad_response_eviction_64bit_age", test_capacity_age_crosses_32bit_boundary);
	suite.add_test("kad_response_partial_first_contact", test_partial_first_contact_keeps_responder);
	suite.add_test("kad_response_other_pending_timeout", test_other_pending_still_times_out);
	suite.add_test("kad_response_late", test_late_reply);
	suite.add_test("kad_response_expired", test_expired_reply);
	suite.add_test("kad_response_capacity_cancels", test_capacity_eviction_is_cancellation);
	suite.add_test("kad_response_evicted_reply_preserves_independent", test_evicted_reply_cannot_consume_independent_request);
	suite.add_test("kad_response_refused_registration_counted", test_refused_registration_is_counted);
	suite.add_test("kad_response_cancel_vs_timeout", test_explicit_cancel_and_real_timeout);
	suite.add_test("kad_response_idle_over_half_cycle", test_long_idle_half_cycle);
	suite.add_test("kad_response_idle_over_full_cycle", test_long_idle_full_cycle);
	suite.add_test("kad_response_pending_full_cycle", test_pending_full_cycle);
	suite.add_test("kad_response_cross_32bit_boundary", test_crosses_32bit_clock_boundary);
	suite.add_test("kad_response_short_header_preserves_request", test_truncated_header_preserves_request);
	suite.add_test("kad_response_partial_framed_contacts", test_partial_contacts_keep_framed_prefix);
	suite.add_test("kad_response_receive_cap", test_receive_cap_and_trailing_bytes);
	suite.add_test("kad_response_unsolicited_never_counts", test_unsolicited_never_counts_as_answer);
	suite.add_test("kad_response_partial_not_valid", test_partial_replies_are_not_valid_responses);
	suite.add_test("kad_response_partial_consumes_like_complete", test_partial_reply_consumes_like_a_complete_one);
	suite.add_test("kad_response_cold_start_coverage", test_cold_start_covers_the_cache_within_the_budget);
	suite.add_test("kad_response_cold_start_rate_budget_bound", test_cold_start_rate_is_set_by_the_budget_not_the_tick);
	suite.add_test("kad_response_outcomes_counted_apart", test_outcomes_are_counted_apart);
	suite.add_test("kad_response_subnet_bounded_by_routing_diversity", test_reply_cannot_fill_table_from_one_subnet);
	suite.add_test("kad_response_spoof_keeps_timeout", test_spoofed_replies_do_not_hide_a_timeout);
	suite.add_test("kad_response_twenty_silent_candidates_backoff", test_twenty_silent_candidates_follow_the_backoff_schedule);
}
