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
#include <stdexcept>

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
	uint32_t m_bootstrapMalformed = 0, m_bootstrapClamped = 0, m_bootstrapRejected = 0;
	uint32_t m_bootstrapResponses = 0, m_bootstrapAccepted = 0, m_bootstrapTimeouts = 0;
	std::vector<KadContact> admitted;
	bool UpdateContact(const KadContact& c, KadContactSource, bool verified)
	{
		if (verified)
			throw std::runtime_error("bootstrap must not mark contacts verified");
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

bool Respond(CKademlia& kad, const SOCKADDR_IN& from, CEDPacket packet = Reply())
{
	const uint32_t before = kad.m_bootstrapResponses;
	kad.OnBootstrapResponse(&from, &packet);
	return kad.m_bootstrapResponses == before + 1;
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
	       kad.m_bootstrapClamped == 1 && kad.m_outstandingRequests.empty();
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
	    kad.m_bootstrapClamped != 1 || !kad.m_outstandingRequests.empty())
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
	       kad.m_bootstrapClamped == 1;
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
	suite.add_test("kad_response_cancel_vs_timeout", test_explicit_cancel_and_real_timeout);
	suite.add_test("kad_response_idle_over_half_cycle", test_long_idle_half_cycle);
	suite.add_test("kad_response_idle_over_full_cycle", test_long_idle_full_cycle);
	suite.add_test("kad_response_pending_full_cycle", test_pending_full_cycle);
	suite.add_test("kad_response_cross_32bit_boundary", test_crosses_32bit_clock_boundary);
	suite.add_test("kad_response_short_header_preserves_request", test_truncated_header_preserves_request);
	suite.add_test("kad_response_partial_framed_contacts", test_partial_contacts_keep_framed_prefix);
	suite.add_test("kad_response_receive_cap", test_receive_cap_and_trailing_bytes);
}
