//
// test_kad_buddy_smoke.cpp
//
// Deterministic tests for the Kad2 buddy / callback helpers (#516).
// Pure helpers only - no CKademlia, no live network, no Sleep().
// Wire oracle: eMule Community KademliaUDPListener.cpp / Search.cpp /
// ClientList.cpp / PacketTracking.cpp / updownclient.h (see KadBuddy.h).
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//

#include "test_framework.h"
#include "../Envy/KadBuddy.h"

#include <cstring>

static const DWORD kPeerA = 0x08080808u; // 8.8.8.8
static const DWORD kPeerB = 0x09090909u; // 9.9.9.9
static const WORD kTcp = 4662;
static const WORD kUdp = 4672;

static const BYTE kKadId[16] = {
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10
};

// ---- Framing: FINDBUDDY_REQ (0x51) ----

static bool test_buddy_req_parse_golden()
{
	// <BuddyID 16 = 0x11..><ClientHash 16 = kKadId><TCPPort 4662 LE>
	BYTE buf[34];
	memset(buf, 0x11, 16);
	memcpy(buf + 16, kKadId, 16);
	buf[32] = 0x36; // 4662 = 0x1236
	buf[33] = 0x12;
	KadFindBuddyReq req;
	if (KadParseFindBuddyReq(buf, 34, req) != KadBuddyParseStatus::Ok)
		return false;
	if (memcmp(req.buddyId, buf, 16) != 0 || memcmp(req.clientHash, kKadId, 16) != 0)
		return false;
	return req.tcpPort == kTcp;
}

static bool test_buddy_req_truncated()
{
	BYTE buf[33] = {};
	KadFindBuddyReq req;
	return KadParseFindBuddyReq(buf, 33, req) == KadBuddyParseStatus::WrongSize && KadParseFindBuddyReq(nullptr, 34, req) == KadBuddyParseStatus::WrongSize;
}

static bool test_buddy_req_trailing_tolerated()
{
	BYTE buf[40] = {};
	KadFindBuddyReq req;
	return KadParseFindBuddyReq(buf, 40, req) == KadBuddyParseStatus::Ok;
}

static bool test_buddy_req_build_roundtrip()
{
	BYTE xored[16];
	KadKadIdToBuddyId(kKadId, xored);
	// XOR of the XOR form must restore the original Kad ID.
	if (!KadBuddyIdMatchesKadId(xored, kKadId))
		return false;
	BYTE buf[34];
	KadBuildFindBuddyReq(buf, xored, kKadId, kTcp);
	// The requester's own ID validates the echo: BuddyID XOR ones == KadID.
	return KadBuddyIdMatchesKadId(buf, kKadId) && buf[32] == 0x36 && buf[33] == 0x12;
}

// ---- Framing: FINDBUDDY_RES (0x5A) ----

static bool test_buddy_res_min_34_no_options()
{
	BYTE buf[34];
	BYTE xored[16];
	KadKadIdToBuddyId(kKadId, xored);
	memcpy(buf, xored, 16);
	memcpy(buf + 16, kKadId, 16);
	buf[32] = 0x36;
	buf[33] = 0x12;
	KadFindBuddyRes res;
	if (KadParseFindBuddyRes(buf, 34, res) != KadBuddyParseStatus::Ok)
		return false;
	return !res.hasConnectOptions && res.tcpPort == kTcp && KadBuddyIdMatchesKadId(res.buddyId, kKadId);
}

static bool test_buddy_res_with_options()
{
	BYTE buf[35];
	memset(buf, 0, sizeof(buf));
	memcpy(buf + 16, kKadId, 16);
	buf[32] = 0x01;
	buf[33] = 0x02;
	buf[34] = 0x09; // ConnectOptions byte (0.49a+)
	KadFindBuddyRes res;
	if (KadParseFindBuddyRes(buf, 35, res) != KadBuddyParseStatus::Ok)
		return false;
	return res.hasConnectOptions && res.connectOptions == 0x09 && res.tcpPort == 0x0201;
}

static bool test_buddy_res_truncated()
{
	BYTE buf[33] = {};
	KadFindBuddyRes res;
	return KadParseFindBuddyRes(buf, 33, res) == KadBuddyParseStatus::WrongSize;
}

static bool test_buddy_res_build_golden()
{
	BYTE xored[16];
	KadKadIdToBuddyId(kKadId, xored);
	BYTE out[35];
	memset(out, 0xEE, sizeof(out));
	KadBuildFindBuddyRes(out, xored, kKadId, kTcp, 0);
	if (memcmp(out, xored, 16) != 0)
		return false;
	if (memcmp(out + 16, kKadId, 16) != 0)
		return false;
	return out[32] == 0x36 && out[33] == 0x12 && out[34] == 0;
}

// ---- Framing: CALLBACK_REQ (0x52) + relay ----

static bool test_callback_req_roundtrip()
{
	BYTE fileHash[16];
	memcpy(fileHash, kKadId, 16);
	BYTE xored[16];
	KadKadIdToBuddyId(kKadId, xored);
	BYTE buf[34];
	KadBuildCallbackReq(buf, xored, fileHash, kTcp);
	KadCallbackReq req;
	if (KadParseCallbackReq(buf, 34, req) != KadBuddyParseStatus::Ok)
		return false;
	return memcmp(req.kadCheck, xored, 16) == 0 && memcmp(req.fileHash, fileHash, 16) == 0 && req.tcpPort == kTcp;
}

static bool test_callback_req_truncated()
{
	BYTE buf[33] = {};
	KadCallbackReq req;
	return KadParseCallbackReq(buf, 33, req) == KadBuddyParseStatus::WrongSize;
}

static bool test_callback_relay_matches_op_callback_layout()
{
	// The relay body must parse with the existing phase-1 OP_CALLBACK helpers
	// and its KadCheck must match the target's Kad ID.
	BYTE fileHash[16];
	memcpy(fileHash, kKadId, 16);
	BYTE xored[16];
	KadKadIdToBuddyId(kKadId, xored);
	BYTE relay[38];
	KadBuildCallbackRelay(relay, xored, fileHash, kPeerA, kTcp);

	Ed2kC2cCallbackFields fields = {};
	if (!Ed2kC2cCallbackParse(relay, sizeof(relay), &fields))
		return false;
	if (!Ed2kCallbackKadIdMatches(fields.kadCheck, kKadId))
		return false;
	// Relay IP is the UDP source in sockaddr (LE) form: 8.8.8.8 -> 08 08 08 08.
	return fields.nIp == 0x08080808u && fields.nTcpPort == kTcp && memcmp(fields.fileHash, fileHash, 16) == 0;
}

static bool test_callback_relay_sender_ip_is_source_not_payload()
{
	// eMule writes the datagram source address; the payload carries no IP.
	BYTE fileHash[16] = {};
	BYTE xored[16] = {};
	BYTE relay[38];
	KadBuildCallbackRelay(relay, xored, fileHash, 0x0A0B0C0Du, 1234);
	Ed2kC2cCallbackFields fields = {};
	return Ed2kC2cCallbackParse(relay, sizeof(relay), &fields) && fields.nIp == 0x0A0B0C0Du && fields.nTcpPort == 1234;
}

// ---- Ping/pong cadence ----

static bool test_ping_due_semantics()
{
	if (!KadBuddyPingDue(0, 1000))
		return false; // never exchanged: ping due immediately
	if (KadBuddyPingDue(1000, 2000))
		return false; // 1 s after last exchange
	if (!KadBuddyPingDue(1000, 1000 + KAD_BUDDY_PING_INTERVAL_MS))
		return false; // exactly the 10-minute cadence
	return !KadBuddyPingDue(1000, 1000 + KAD_BUDDY_PING_INTERVAL_MS - 1);
}

static bool test_inbound_ping_gap()
{
	if (!KadBuddyInboundPingAllowed(0, 1000))
		return false;
	if (KadBuddyInboundPingAllowed(1000, 1000 + KAD_BUDDY_PING_INBOUND_GAP_MS - 1))
		return false;
	return KadBuddyInboundPingAllowed(1000, 1000 + KAD_BUDDY_PING_INBOUND_GAP_MS);
}

// ---- Session: open-node side ----

static KadFindBuddyReq make_req()
{
	KadFindBuddyReq req = {};
	memset(req.buddyId, 0x33, 16);
	memcpy(req.clientHash, kKadId, 16);
	req.tcpPort = kTcp;
	return req;
}

static bool test_accept_fires_guards()
{
	KadBuddySession s;
	s.Reset();
	const KadFindBuddyReq req = make_req();
	// TCP firewalled: refuse (eMule GetFirewalled()).
	if (s.AcceptFindBuddyRequest(kPeerA, kUdp, req, true, false, 0) != KadBuddyAcceptStatus::Firewalled)
		return false;
	// UDP firewalled or unverified: refuse (eMule IsFirewalledUDP/IsVerified).
	if (s.AcceptFindBuddyRequest(kPeerA, kUdp, req, false, true, 0) != KadBuddyAcceptStatus::Firewalled)
		return false;
	// Self or zero IP: refuse.
	if (s.AcceptFindBuddyRequest(kPeerA, kUdp, req, false, false, kPeerA) != KadBuddyAcceptStatus::InvalidSource)
		return false;
	if (s.AcceptFindBuddyRequest(0, kUdp, req, false, false, 0) != KadBuddyAcceptStatus::InvalidSource)
		return false;
	return s.AcceptFindBuddyRequest(kPeerA, kUdp, req, false, false, 0) == KadBuddyAcceptStatus::Accept;
}

static bool test_accept_replaces_pending_bonds_connected()
{
	KadBuddySession s;
	s.Reset();
	const KadFindBuddyReq req = make_req();
	if (s.AcceptFindBuddyRequest(kPeerA, kUdp, req, false, false, 0) != KadBuddyAcceptStatus::Accept)
		return false;
	// Same requester again: AlreadyIncoming (eMule FindClientByIP guard).
	if (s.AcceptFindBuddyRequest(kPeerA, kUdp, req, false, false, 0) != KadBuddyAcceptStatus::AlreadyIncoming)
		return false;
	// A different requester replaces the pending candidate (bounded analog
	// of eMule's KS_INCOMING_BUDDY list where first-connect wins).
	if (s.AcceptFindBuddyRequest(kPeerB, kUdp, req, false, false, 0) != KadBuddyAcceptStatus::Accept)
		return false;
	// After the bond connects, the slot is closed.
	s.OnBuddyConnected(kPeerB, 130);
	if (!s.HasConnectedBuddy() || s.Buddy().ipHost != kPeerB)
		return false;
	return s.AcceptFindBuddyRequest(kPeerA, kUdp, req, false, false, 0) == KadBuddyAcceptStatus::HaveBuddy;
}

static bool test_incoming_bond_records_requester()
{
	KadBuddySession s;
	s.Reset();
	const KadFindBuddyReq req = make_req();
	s.AcceptFindBuddyRequest(kPeerA, 1234, req, false, false, 0);
	if (s.Buddy().ipHost != kPeerA || s.Buddy().udpPort != 1234 || s.Buddy().tcpPort != kTcp)
		return false;
	if (memcmp(s.Buddy().clientHash, kKadId, 16) != 0)
		return false;
	s.OnBuddyConnected(kPeerA, 200);
	return s.HasConnectedBuddy() && s.Buddy().connected && s.Buddy().connectedAt == 200;
}

static bool test_bond_ignores_wrong_ip()
{
	KadBuddySession s;
	s.Reset();
	const KadFindBuddyReq req = make_req();
	s.AcceptFindBuddyRequest(kPeerA, kUdp, req, false, false, 0);
	s.OnBuddyConnected(kPeerB, 200);
	return !s.HasConnectedBuddy();
}

// ---- Session: firewalled-node side ----

static bool test_wants_buddy_search_gates()
{
	KadBuddySession s;
	s.Reset();
	// Needs both TCP and UDP firewalled (eMule IsFirewalled && IsFirewalledUDP).
	if (s.WantsBuddySearch(1000, false, true) || s.WantsBuddySearch(1000, true, false))
		return false;
	if (!s.WantsBuddySearch(1000, true, true))
		return false;
	s.NoteBuddySearchRound(1000);
	// Retry gate: 20 minutes.
	if (s.WantsBuddySearch(1000 + KAD_BUDDY_SEARCH_RETRY_MS - 1, true, true))
		return false;
	if (!s.WantsBuddySearch(1000 + KAD_BUDDY_SEARCH_RETRY_MS, true, true))
		return false;
	// A connected buddy stops the search.
	s.BeginFindBuddyRequest(kPeerA, 1000);
	KadFindBuddyRes res = {};
	memcpy(res.buddyId, kKadId, 16); // patched below to a valid echo
	BYTE xored[16];
	KadKadIdToBuddyId(kKadId, xored);
	memcpy(res.buddyId, xored, 16);
	memcpy(res.clientHash, kKadId, 16);
	res.tcpPort = kTcp;
	if (s.OnFindBuddyResponse(kPeerA, res, kKadId, 1100) != KadBuddyCandidateStatus::Accepted)
		return false;
	s.OnBuddyConnected(kPeerA, 1200);
	return !s.WantsBuddySearch(1200 + KAD_BUDDY_SEARCH_RETRY_MS + 1, true, true);
}

static bool test_out_track_dedupe_and_ttl()
{
	KadBuddySession s;
	s.Reset();
	if (!s.BeginFindBuddyRequest(kPeerA, 1000))
		return false;
	if (s.BeginFindBuddyRequest(kPeerA, 1100))
		return false; // still tracked
	if (!s.HasOutstandingFindBuddyRequest(kPeerA, 1000 + KAD_BUDDY_OUT_TRACK_TTL_MS - 1))
		return false;
	// eMule PacketTracking: tracked answers are accepted within 180 s only.
	if (!s.BeginFindBuddyRequest(kPeerA, 1000 + KAD_BUDDY_OUT_TRACK_TTL_MS))
		return false; // expired entry frees the IP
	return s.HasOutstandingFindBuddyRequest(kPeerA, 1000 + KAD_BUDDY_OUT_TRACK_TTL_MS);
}

static bool test_res_unrequested_and_stale()
{
	KadBuddySession s;
	s.Reset();
	KadFindBuddyRes res = {};
	BYTE xored[16];
	KadKadIdToBuddyId(kKadId, xored);
	memcpy(res.buddyId, xored, 16);
	res.tcpPort = kTcp;
	// No outbound FINDBUDDY_REQ to this IP.
	if (s.OnFindBuddyResponse(kPeerA, res, kKadId, 100) != KadBuddyCandidateStatus::Unrequested)
		return false;
	s.BeginFindBuddyRequest(kPeerA, 100);
	// Answer after the 180 s window: stale (eMule IsOnOutTrackList).
	if (s.OnFindBuddyResponse(kPeerA, res, kKadId, 100 + KAD_BUDDY_OUT_TRACK_TTL_MS + 1) != KadBuddyCandidateStatus::Stale)
		return false;
	return s.OnFindBuddyResponse(kPeerA, res, kKadId, 110) == KadBuddyCandidateStatus::Accepted;
}

static bool test_res_consumes_track_on_first_response()
{
	// eMule consumes the tracked FINDBUDDY_REQ with the first response
	// (IsOnOutTrackList removes on match, before the echo check), so a
	// duplicate or spoofed answer cannot be accepted again in the window.
	KadBuddySession s;
	s.Reset();
	s.BeginFindBuddyRequest(kPeerA, 100);
	KadFindBuddyRes res = {};
	BYTE xored[16];
	KadKadIdToBuddyId(kKadId, xored);
	memcpy(res.buddyId, xored, 16);
	res.tcpPort = kTcp;
	if (s.OnFindBuddyResponse(kPeerA, res, kKadId, 110) != KadBuddyCandidateStatus::Accepted)
		return false;
	if (s.HasOutstandingFindBuddyRequest(kPeerA, 120))
		return false;
	return s.OnFindBuddyResponse(kPeerA, res, kKadId, 130) == KadBuddyCandidateStatus::Unrequested;
}

static bool test_res_echo_mismatch_consumes_track()
{
	// eMule consumes the tracked request even when the echo fails (the
	// IsOnOutTrackList removal happens before validation), so the same IP
	// cannot hammer the check with invalid answers.
	KadBuddySession s;
	s.Reset();
	s.BeginFindBuddyRequest(kPeerA, 100);
	KadFindBuddyRes res = {};
	memcpy(res.buddyId, kKadId, 16); // NOT XORed - must not validate
	res.tcpPort = kTcp;
	if (s.OnFindBuddyResponse(kPeerA, res, kKadId, 110) != KadBuddyCandidateStatus::EchoMismatch)
		return false;
	return s.OnFindBuddyResponse(kPeerA, res, kKadId, 120) == KadBuddyCandidateStatus::Unrequested;
}

static bool test_res_echo_mismatch()
{
	KadBuddySession s;
	s.Reset();
	s.BeginFindBuddyRequest(kPeerA, 100);
	KadFindBuddyRes res = {};
	memcpy(res.buddyId, kKadId, 16); // NOT XORed - must not validate
	res.tcpPort = kTcp;
	return s.OnFindBuddyResponse(kPeerA, res, kKadId, 110) == KadBuddyCandidateStatus::EchoMismatch && !s.HasBuddyRecord();
}

static bool test_res_candidate_fields()
{
	KadBuddySession s;
	s.Reset();
	s.BeginFindBuddyRequest(kPeerA, 100);
	KadFindBuddyRes res = {};
	BYTE xored[16];
	KadKadIdToBuddyId(kKadId, xored);
	memcpy(res.buddyId, xored, 16);
	memcpy(res.clientHash, kKadId, 16);
	res.tcpPort = 4040;
	res.connectOptions = 0x0F;
	res.hasConnectOptions = true;
	if (s.OnFindBuddyResponse(kPeerA, res, kKadId, 110) != KadBuddyCandidateStatus::Accepted)
		return false;
	if (s.Buddy().ipHost != kPeerA || s.Buddy().tcpPort != 4040)
		return false;
	return memcmp(s.Buddy().clientHash, kKadId, 16) == 0 && s.Buddy().connectOptions == 0x0F && s.Buddy().hasConnectOptions;
}

static bool test_res_have_buddy_wins()
{
	KadBuddySession s;
	s.Reset();
	// Bond first (incoming role).
	const KadFindBuddyReq req = make_req();
	s.AcceptFindBuddyRequest(kPeerA, kUdp, req, false, false, 0);
	s.OnBuddyConnected(kPeerA, 110);
	// A FINDBUDDY_RES from anywhere cannot replace a live bond.
	s.BeginFindBuddyRequest(kPeerB, 120);
	KadFindBuddyRes res = {};
	BYTE xored[16];
	KadKadIdToBuddyId(kKadId, xored);
	memcpy(res.buddyId, xored, 16);
	res.tcpPort = kTcp;
	return s.OnFindBuddyResponse(kPeerB, res, kKadId, 130) == KadBuddyCandidateStatus::HaveBuddy && s.Buddy().ipHost == kPeerA;
}

// ---- Session: callback relay ----

static bool test_relay_requires_bond()
{
	KadBuddySession s;
	s.Reset();
	KadCallbackReq req = {};
	req.tcpPort = kTcp;
	BYTE relay[38] = {};
	return s.OnCallbackRequest(kPeerA, req, relay) == KadBuddyRelayStatus::NoBuddy && s.OnCallbackRequest(0, req, relay) == KadBuddyRelayStatus::InvalidSource;
}

static bool test_relay_through_connected_buddy()
{
	KadBuddySession s;
	s.Reset();
	// We answered a FINDBUDDY_REQ; the firewalled requester connected in.
	const KadFindBuddyReq freq = make_req();
	s.AcceptFindBuddyRequest(kPeerA, kUdp, freq, false, false, 0);
	s.OnBuddyConnected(kPeerA, 110);

	BYTE fileHash[16];
	memcpy(fileHash, kKadId, 16);
	BYTE xored[16];
	KadKadIdToBuddyId(kKadId, xored);
	KadCallbackReq req;
	memcpy(req.kadCheck, xored, 16);
	memcpy(req.fileHash, fileHash, 16);
	req.tcpPort = 5000;

	BYTE relay[38] = {};
	if (s.OnCallbackRequest(kPeerB, req, relay) != KadBuddyRelayStatus::Relay)
		return false;
	// Relay body: check + file hash unchanged; endpoint = UDP source.
	Ed2kC2cCallbackFields fields = {};
	if (!Ed2kC2cCallbackParse(relay, sizeof(relay), &fields))
		return false;
	return fields.nIp == kPeerB && fields.nTcpPort == 5000 && memcmp(fields.fileHash, fileHash, 16) == 0 && Ed2kCallbackKadIdMatches(fields.kadCheck, kKadId);
}

// ---- Session: bounded track history ----

static bool test_track_bounded()
{
	KadBuddySession s;
	s.Reset();
	for (size_t i = 0; i < KAD_BUDDY_TRACK_MAX + 6; ++i)
	{
		const DWORD ip = 0x0B000000u + static_cast<DWORD>(i);
		if (!s.BeginFindBuddyRequest(ip, 1000 + static_cast<DWORD>(i)))
			return false;
	}
	return s.TrackCount() == KAD_BUDDY_TRACK_MAX;
}

static bool test_reset_clears_everything()
{
	KadBuddySession s;
	s.Reset();
	const KadFindBuddyReq req = make_req();
	s.AcceptFindBuddyRequest(kPeerA, kUdp, req, false, false, 0);
	s.OnBuddyConnected(kPeerA, 110);
	s.BeginFindBuddyRequest(kPeerB, 120);
	s.Reset();
	return !s.HasConnectedBuddy() && !s.HasBuddyRecord() && s.TrackCount() == 0;
}

static bool test_buddy_status_values_distinct()
{
	return KadBuddyAcceptStatus::Accept != KadBuddyAcceptStatus::Firewalled && KadBuddyCandidateStatus::Accepted != KadBuddyCandidateStatus::Unrequested && KadBuddyCandidateStatus::Unrequested != KadBuddyCandidateStatus::Stale && KadBuddyCandidateStatus::Stale != KadBuddyCandidateStatus::EchoMismatch && KadBuddyRelayStatus::Relay != KadBuddyRelayStatus::NoBuddy && KadBuddyRelayStatus::NoBuddy != KadBuddyRelayStatus::InvalidSource;
}

void register_kad_buddy_smoke_tests(TestSuite& suite)
{
	suite.add_test("kad_buddy_req_parse_golden", test_buddy_req_parse_golden);
	suite.add_test("kad_buddy_req_truncated", test_buddy_req_truncated);
	suite.add_test("kad_buddy_req_trailing", test_buddy_req_trailing_tolerated);
	suite.add_test("kad_buddy_req_build_roundtrip", test_buddy_req_build_roundtrip);
	suite.add_test("kad_buddy_res_min_34", test_buddy_res_min_34_no_options);
	suite.add_test("kad_buddy_res_with_options", test_buddy_res_with_options);
	suite.add_test("kad_buddy_res_truncated", test_buddy_res_truncated);
	suite.add_test("kad_buddy_res_build_golden", test_buddy_res_build_golden);
	suite.add_test("kad_buddy_callback_roundtrip", test_callback_req_roundtrip);
	suite.add_test("kad_buddy_callback_truncated", test_callback_req_truncated);
	suite.add_test("kad_buddy_relay_layout", test_callback_relay_matches_op_callback_layout);
	suite.add_test("kad_buddy_relay_sender_ip", test_callback_relay_sender_ip_is_source_not_payload);
	suite.add_test("kad_buddy_ping_due", test_ping_due_semantics);
	suite.add_test("kad_buddy_ping_inbound_gap", test_inbound_ping_gap);
	suite.add_test("kad_buddy_accept_guards", test_accept_fires_guards);
	suite.add_test("kad_buddy_accept_slot", test_accept_replaces_pending_bonds_connected);
	suite.add_test("kad_buddy_incoming_record", test_incoming_bond_records_requester);
	suite.add_test("kad_buddy_bond_wrong_ip", test_bond_ignores_wrong_ip);
	suite.add_test("kad_buddy_search_gates", test_wants_buddy_search_gates);
	suite.add_test("kad_buddy_out_track_ttl", test_out_track_dedupe_and_ttl);
	suite.add_test("kad_buddy_res_unrequested_stale", test_res_unrequested_and_stale);
	suite.add_test("kad_buddy_res_consumes_track", test_res_consumes_track_on_first_response);
	suite.add_test("kad_buddy_res_echo_consumes_track", test_res_echo_mismatch_consumes_track);
	suite.add_test("kad_buddy_res_echo_mismatch", test_res_echo_mismatch);
	suite.add_test("kad_buddy_res_candidate_fields", test_res_candidate_fields);
	suite.add_test("kad_buddy_res_have_buddy_wins", test_res_have_buddy_wins);
	suite.add_test("kad_buddy_relay_requires_bond", test_relay_requires_bond);
	suite.add_test("kad_buddy_relay_connected", test_relay_through_connected_buddy);
	suite.add_test("kad_buddy_track_bounded", test_track_bounded);
	suite.add_test("kad_buddy_reset", test_reset_clears_everything);
	suite.add_test("kad_buddy_status_distinct", test_buddy_status_values_distinct);
}