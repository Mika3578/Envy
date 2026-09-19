//
// test_kad_firewall_check_smoke.cpp
//
// Deterministic tests for Kad2 TCP firewall-detection baseline (#86).
// Pure helpers only — no CKademlia, no live network, no Sleep().
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//

#include "test_framework.h"
#include "../Envy/KadFirewallCheck.h"

#include <cstring>

static const DWORD kPeerA = 0x08080808u; // 8.8.8.8
static const DWORD kPeerB = 0x09090909u; // 9.9.9.9
static const DWORD kPeerC = 0x04040404u; // 4.4.4.4
static const DWORD kObs1 = 0x01020304u;  // 1.2.3.4
static const DWORD kObs2 = 0x05060708u;  // 5.6.7.8
static const WORD kUdp = 4672;
static const WORD kTcp = 4662;

static bool bytes_eq_u16(const BYTE* p, WORD v)
{
	BYTE tmp[2];
	KadWriteU16LE(tmp, v);
	return p[0] == tmp[0] && p[1] == tmp[1];
}

static bool test_req_valid_exact_2()
{
	BYTE buf[2];
	KadWriteU16LE(buf, kTcp);
	KadFirewalledReq req;
	return KadParseFirewalledReq(buf, 2, req) == KadFwParseStatus::Ok && req.tcpPort == kTcp;
}

static bool test_req_empty()
{
	KadFirewalledReq req;
	return KadParseFirewalledReq(nullptr, 0, req) == KadFwParseStatus::WrongSize;
}

static bool test_req_one_byte()
{
	BYTE buf[1] = { 0x36 };
	KadFirewalledReq req;
	return KadParseFirewalledReq(buf, 1, req) == KadFwParseStatus::WrongSize;
}

static bool test_req_three_bytes()
{
	BYTE buf[3] = { 0x36, 0x12, 0x00 };
	KadFirewalledReq req;
	return KadParseFirewalledReq(buf, 3, req) == KadFwParseStatus::WrongSize;
}

static bool test_req_port_zero()
{
	BYTE buf[2] = { 0x00, 0x00 };
	KadFirewalledReq req;
	return KadParseFirewalledReq(buf, 2, req) == KadFwParseStatus::PortZero;
}

static bool test_req_port_one()
{
	BYTE buf[2] = { 0x01, 0x00 };
	KadFirewalledReq req;
	return KadParseFirewalledReq(buf, 2, req) == KadFwParseStatus::Ok && req.tcpPort == 1;
}

static bool test_req_port_65535()
{
	BYTE buf[2] = { 0xFF, 0xFF };
	KadFirewalledReq req;
	return KadParseFirewalledReq(buf, 2, req) == KadFwParseStatus::Ok && req.tcpPort == 65535;
}

static bool test_req_endian_golden_4662()
{
	// 4662 = 0x1236 → LE 36 12
	const BYTE golden[] = { 0x36, 0x12 };
	KadFirewalledReq req;
	if (KadParseFirewalledReq(golden, 2, req) != KadFwParseStatus::Ok)
		return false;
	if (req.tcpPort != 4662)
		return false;
	BYTE out[2];
	KadWriteU16LE(out, 4662);
	return bytes_eq_u16(out, 4662) && out[0] == 0x36 && out[1] == 0x12;
}

static bool test_res_valid_exact_4()
{
	BYTE buf[4];
	KadWriteU32LE(buf, kObs1);
	KadFirewalledRes res;
	return KadParseFirewalledRes(buf, 4, res) == KadFwParseStatus::Ok && res.observedIpHost == kObs1;
}

static bool test_res_short()
{
	BYTE buf[3] = { 0x04, 0x03, 0x02 };
	KadFirewalledRes res;
	return KadParseFirewalledRes(buf, 0, res) == KadFwParseStatus::WrongSize && KadParseFirewalledRes(buf, 1, res) == KadFwParseStatus::WrongSize && KadParseFirewalledRes(buf, 2, res) == KadFwParseStatus::WrongSize && KadParseFirewalledRes(buf, 3, res) == KadFwParseStatus::WrongSize;
}

static bool test_res_extra_byte()
{
	BYTE buf[5] = { 0x04, 0x03, 0x02, 0x01, 0x00 };
	KadFirewalledRes res;
	return KadParseFirewalledRes(buf, 5, res) == KadFwParseStatus::WrongSize;
}

static bool test_res_endian_golden_1_2_3_4()
{
	const BYTE golden[] = { 0x04, 0x03, 0x02, 0x01 };
	KadFirewalledRes res;
	return KadParseFirewalledRes(golden, 4, res) == KadFwParseStatus::Ok && res.observedIpHost == 0x01020304u;
}

static bool test_res_invalid_zero()
{
	BYTE buf[4] = { 0, 0, 0, 0 };
	KadFirewalledRes res;
	return KadParseFirewalledRes(buf, 4, res) == KadFwParseStatus::InvalidIp;
}

static bool test_res_invalid_broadcast()
{
	BYTE buf[4] = { 0xFF, 0xFF, 0xFF, 0xFF };
	KadFirewalledRes res;
	return KadParseFirewalledRes(buf, 4, res) == KadFwParseStatus::InvalidIp;
}

static bool test_res_invalid_rfc1918()
{
	BYTE buf[4];
	KadWriteU32LE(buf, 0xC0A80101u); // 192.168.1.1
	KadFirewalledRes res;
	return KadParseFirewalledRes(buf, 4, res) == KadFwParseStatus::InvalidIp;
}

static bool test_res_invalid_multicast()
{
	BYTE buf[4];
	KadWriteU32LE(buf, 0xE0000001u); // 224.0.0.1
	KadFirewalledRes res;
	return KadParseFirewalledRes(buf, 4, res) == KadFwParseStatus::InvalidIp;
}

static bool test_ack_empty_ok()
{
	return KadParseFirewalledAck(0) == KadFwParseStatus::Ok && KadParseFirewalledAck(1) == KadFwParseStatus::WrongSize;
}

static bool test_fw2_min_19()
{
	BYTE buf[19]{};
	KadWriteU16LE(buf, 12345);
	buf[18] = 0x01;
	KadFirewalled2Req req;
	return KadParseFirewalled2Req(buf, 19, req) == KadFwParseStatus::Ok && req.tcpPort == 12345 && req.connectOptions == 0x01 && KadParseFirewalled2Req(buf, 18, req) == KadFwParseStatus::WrongSize;
}

static bool test_initial_unknown()
{
	KadFirewallCheck fw;
	fw.OnKadStart(1000, kTcp);
	return fw.TcpState() == KadTcpFirewallState::Unknown && fw.UdpState() == KadUdpFirewallState::Unknown && fw.PublicIpHost() == 0 && fw.OutstandingCount() == 0;
}

static KadFwPeerCandidate make_peer(DWORD ip, WORD udp, bool verified = true)
{
	KadFwPeerCandidate p;
	p.ipHost = ip;
	p.udpPort = udp;
	p.tcpPort = kTcp;
	p.version = 8;
	p.verified = verified;
	p.lastSeen = 10;
	return p;
}

static bool test_test_starts_and_context()
{
	KadFirewallCheck fw;
	fw.OnKadStart(1000, kTcp);
	if (!fw.BeginOutboundCheck(make_peer(kPeerA, kUdp), 1000))
		return false;
	return fw.TcpState() == KadTcpFirewallState::Testing && fw.OutstandingCount() == 1 && fw.HasOutboundCheck(kPeerA, kUdp);
}

static BYTE* write_res(BYTE* buf, DWORD ip)
{
	KadWriteU32LE(buf, ip);
	return buf;
}

static bool test_valid_matching_res()
{
	KadFirewallCheck fw;
	fw.OnKadStart(1, kTcp);
	fw.BeginOutboundCheck(make_peer(kPeerA, kUdp), 10);
	BYTE buf[4];
	write_res(buf, kObs1);
	return fw.OnFirewalledRes(kPeerA, kUdp, buf, 4, 20) == KadFwResStatus::Accepted;
}

static bool test_unsolicited_res_ignored()
{
	KadFirewallCheck fw;
	fw.OnKadStart(1, kTcp);
	BYTE buf[4];
	write_res(buf, kObs1);
	return fw.OnFirewalledRes(kPeerA, kUdp, buf, 4, 20) == KadFwResStatus::Unsolicited && fw.TcpState() == KadTcpFirewallState::Unknown && fw.PublicIpHost() == 0;
}

static bool test_stale_res_ignored()
{
	KadFirewallCheck fw;
	fw.OnKadStart(1, kTcp);
	fw.BeginOutboundCheck(make_peer(kPeerA, kUdp), 10);
	fw.OnTimer(10 + KAD_FW_CHECK_TTL_MS);
	BYTE buf[4];
	write_res(buf, kObs1);
	return fw.OnFirewalledRes(kPeerA, kUdp, buf, 4, 10 + KAD_FW_CHECK_TTL_MS + 1) == KadFwResStatus::Unsolicited;
}

static bool test_duplicate_res_ignored()
{
	KadFirewallCheck fw;
	fw.OnKadStart(1, kTcp);
	fw.BeginOutboundCheck(make_peer(kPeerA, kUdp), 10);
	BYTE buf[4];
	write_res(buf, kObs1);
	if (fw.OnFirewalledRes(kPeerA, kUdp, buf, 4, 20) != KadFwResStatus::Accepted)
		return false;
	return fw.OnFirewalledRes(kPeerA, kUdp, buf, 4, 30) == KadFwResStatus::Duplicate;
}

static bool test_wrong_peer_res_ignored()
{
	KadFirewallCheck fw;
	fw.OnKadStart(1, kTcp);
	fw.BeginOutboundCheck(make_peer(kPeerA, kUdp), 10);
	BYTE buf[4];
	write_res(buf, kObs1);
	return fw.OnFirewalledRes(kPeerB, kUdp, buf, 4, 20) == KadFwResStatus::Unsolicited && fw.PublicIpHost() == 0;
}

static bool test_timeout_goes_firewalled()
{
	KadFirewallCheck fw;
	fw.OnKadStart(1, kTcp);
	fw.BeginOutboundCheck(make_peer(kPeerA, kUdp), 10);
	fw.OnTimer(10 + KAD_FW_CHECK_TTL_MS);
	return fw.TcpState() == KadTcpFirewallState::Firewalled && fw.OutstandingCount() == 0 && fw.TcpState() != KadTcpFirewallState::Open;
}

static bool test_reset_unknown()
{
	KadFirewallCheck fw;
	fw.OnKadStart(1, kTcp);
	fw.BeginOutboundCheck(make_peer(kPeerA, kUdp), 10);
	BYTE buf[4];
	write_res(buf, kObs1);
	fw.OnFirewalledRes(kPeerA, kUdp, buf, 4, 20);
	fw.OnFirewalledAck(kPeerA, kUdp, 0, 21);
	fw.OnKadStop();
	return fw.TcpState() == KadTcpFirewallState::Unknown && fw.OutstandingCount() == 0 && fw.PublicIpHost() == 0 && fw.AckCount() == 0;
}

static bool test_two_acks_open()
{
	KadFirewallCheck fw;
	fw.OnKadStart(1, kTcp);
	fw.BeginOutboundCheck(make_peer(kPeerA, kUdp), 10);
	fw.BeginOutboundCheck(make_peer(kPeerB, kUdp), 11);
	if (fw.OnFirewalledAck(kPeerA, kUdp, 0, 20) != KadFwAckStatus::Accepted)
		return false;
	if (fw.TcpState() == KadTcpFirewallState::Open)
		return false;
	if (fw.OnFirewalledAck(kPeerB, kUdp, 0, 21) != KadFwAckStatus::Accepted)
		return false;
	return fw.TcpState() == KadTcpFirewallState::Open && fw.UdpState() == KadUdpFirewallState::Unknown;
}

static bool test_unsolicited_ack_ignored()
{
	KadFirewallCheck fw;
	fw.OnKadStart(1, kTcp);
	return fw.OnFirewalledAck(kPeerA, kUdp, 0, 20) == KadFwAckStatus::Unsolicited && fw.TcpState() == KadTcpFirewallState::Unknown;
}

static bool test_duplicate_ack_ignored()
{
	KadFirewallCheck fw;
	fw.OnKadStart(1, kTcp);
	fw.BeginOutboundCheck(make_peer(kPeerA, kUdp), 10);
	if (fw.OnFirewalledAck(kPeerA, kUdp, 0, 20) != KadFwAckStatus::Accepted)
		return false;
	return fw.OnFirewalledAck(kPeerA, kUdp, 0, 21) == KadFwAckStatus::Duplicate && fw.AckCount() == 1;
}

static bool test_tcp_ack_0xa8()
{
	KadFirewallCheck fw;
	fw.OnKadStart(1, kTcp);
	fw.BeginOutboundCheck(make_peer(kPeerA, kUdp), 10);
	fw.BeginOutboundCheck(make_peer(kPeerB, kUdp), 11);
	if (fw.OnTcpFirewallCheckAck(kPeerA, 20) != KadFwAckStatus::Accepted)
		return false;
	if (fw.OnTcpFirewallCheckAck(kPeerB, 21) != KadFwAckStatus::Accepted)
		return false;
	return fw.TcpState() == KadTcpFirewallState::Open;
}

static bool test_bounded_simultaneous()
{
	KadFirewallCheck fw;
	fw.OnKadStart(1, kTcp);
	DWORD ip = 0x08080000u;
	size_t accepted = 0;
	for (int i = 0; i < 8; ++i)
	{
		if (fw.BeginOutboundCheck(make_peer(ip + static_cast<DWORD>(i), static_cast<WORD>(kUdp + i)), 10))
			++accepted;
	}
	return accepted == KAD_FW_MAX_OUTSTANDING_CHECKS && fw.OutstandingCount() == KAD_FW_MAX_OUTSTANDING_CHECKS;
}

static bool test_one_observation_not_authoritative()
{
	KadFirewallCheck fw;
	fw.OnKadStart(1, kTcp);
	fw.BeginOutboundCheck(make_peer(kPeerA, kUdp), 10);
	BYTE buf[4];
	write_res(buf, kObs1);
	fw.OnFirewalledRes(kPeerA, kUdp, buf, 4, 20);
	return fw.PublicIpHost() == 0 && fw.ObservationCount() == 1;
}

static bool test_two_independent_agree()
{
	KadFirewallCheck fw;
	fw.OnKadStart(1, kTcp);
	fw.BeginOutboundCheck(make_peer(kPeerA, kUdp), 10);
	fw.BeginOutboundCheck(make_peer(kPeerB, kUdp), 11);
	BYTE buf[4];
	write_res(buf, kObs1);
	fw.OnFirewalledRes(kPeerA, kUdp, buf, 4, 20);
	fw.OnFirewalledRes(kPeerB, kUdp, buf, 4, 21);
	return fw.PublicIpHost() == kObs1;
}

static bool test_conflicting_peers()
{
	KadFirewallCheck fw;
	fw.OnKadStart(1, kTcp);
	fw.BeginOutboundCheck(make_peer(kPeerA, kUdp), 10);
	fw.BeginOutboundCheck(make_peer(kPeerB, kUdp), 11);
	BYTE a[4], b[4];
	write_res(a, kObs1);
	write_res(b, kObs2);
	fw.OnFirewalledRes(kPeerA, kUdp, a, 4, 20);
	fw.OnFirewalledRes(kPeerB, kUdp, b, 4, 21);
	return fw.PublicIpHost() == 0;
}

static bool test_duplicate_peer_not_double_counted()
{
	KadFirewallCheck fw;
	fw.OnKadStart(1, kTcp);
	fw.BeginOutboundCheck(make_peer(kPeerA, kUdp), 10);
	BYTE buf[4];
	write_res(buf, kObs1);
	fw.OnFirewalledRes(kPeerA, kUdp, buf, 4, 20);
	fw.OnFirewalledRes(kPeerA, kUdp, buf, 4, 21);
	return fw.PublicIpHost() == 0 && fw.ObservationCount() == 1;
}

static bool test_invalid_observation_rejected()
{
	KadFirewallCheck fw;
	fw.OnKadStart(1, kTcp);
	fw.BeginOutboundCheck(make_peer(kPeerA, kUdp), 10);
	BYTE buf[4] = { 0, 0, 0, 0 };
	return fw.OnFirewalledRes(kPeerA, kUdp, buf, 4, 20) == KadFwResStatus::InvalidObservedIp && fw.PublicIpHost() == 0;
}

static bool test_public_ip_reset_on_network_change()
{
	KadFirewallCheck fw;
	fw.OnKadStart(1, kTcp);
	fw.BeginOutboundCheck(make_peer(kPeerA, kUdp), 10);
	fw.BeginOutboundCheck(make_peer(kPeerB, kUdp), 11);
	BYTE buf[4];
	write_res(buf, kObs1);
	fw.OnFirewalledRes(kPeerA, kUdp, buf, 4, 20);
	fw.OnFirewalledRes(kPeerB, kUdp, buf, 4, 21);
	if (fw.PublicIpHost() != kObs1)
		return false;
	fw.OnNetworkOrPortChange(50, 4663);
	return fw.PublicIpHost() == 0 && fw.TcpState() == KadTcpFirewallState::Unknown;
}

static bool test_inbound_valid_probe_is_sender()
{
	KadFirewallCheck fw;
	fw.OnKadStart(1, kTcp);
	BYTE req[2];
	KadWriteU16LE(req, 1234);
	const KadFwInboundReqResult r = fw.OnInboundFirewalledReq(kPeerA, kUdp, req, 2, 10, false);
	return r.status == KadFwInboundStatus::Accept && r.sendResponse && r.recordTcpProbe && r.tcpPort == 1234 && r.observedIpHost == kPeerA && fw.InboundProbeCount() == 1;
}

static bool test_inbound_cannot_target_third_party()
{
	KadFirewallCheck fw;
	fw.OnKadStart(1, kTcp);
	BYTE req[2];
	KadWriteU16LE(req, 22);
	const KadFwInboundReqResult r = fw.OnInboundFirewalledReq(kPeerA, kUdp, req, 2, 10, false);
	// Packet carries only a port; observed/probe IP is always the UDP source.
	return r.observedIpHost == kPeerA && r.observedIpHost != kPeerC && r.tcpPort == 22;
}

static bool test_inbound_repeat_rate_limited()
{
	KadFirewallCheck fw;
	fw.OnKadStart(1, kTcp);
	BYTE req[2];
	KadWriteU16LE(req, kTcp);
	if (fw.OnInboundFirewalledReq(kPeerA, kUdp, req, 2, 10, false).status != KadFwInboundStatus::Accept)
		return false;
	KadWriteU16LE(req, 80);
	const KadFwInboundStatus st = fw.OnInboundFirewalledReq(kPeerA, kUdp, req, 2, 11, false).status;
	return (st == KadFwInboundStatus::RateLimited || st == KadFwInboundStatus::DuplicatePortScan) && fw.InboundProbeCount() == 1;
}

static bool test_inbound_flood_capped()
{
	KadFirewallCheck fw;
	fw.OnKadStart(1, kTcp);
	BYTE req[2];
	KadWriteU16LE(req, kTcp);
	size_t accepted = 0;
	size_t denied = 0;
	for (int i = 0; i < 12; ++i)
	{
		const DWORD ip = 0x08081000u + static_cast<DWORD>(i);
		const KadFwInboundReqResult r = fw.OnInboundFirewalledReq(ip, kUdp, req, 2, 10, false);
		if (r.status == KadFwInboundStatus::Accept)
			++accepted;
		else
			++denied;
	}
	return accepted == KAD_FW_MAX_INBOUND_PROBES && denied > 0 && fw.InboundProbeCount() <= KAD_FW_MAX_INBOUND_PROBES && fw.RateEntryCount() <= KAD_FW_MAX_RATE_ENTRIES;
}

static bool test_inbound_invalid_source()
{
	KadFirewallCheck fw;
	fw.OnKadStart(1, kTcp);
	BYTE req[2];
	KadWriteU16LE(req, kTcp);
	return fw.OnInboundFirewalledReq(0, kUdp, req, 2, 10, false).status == KadFwInboundStatus::InvalidSource && fw.OnInboundFirewalledReq(0x7F000001u, kUdp, req, 2, 10, false).status == KadFwInboundStatus::InvalidSource && fw.OnInboundFirewalledReq(0xE0000001u, kUdp, req, 2, 10, false).status == KadFwInboundStatus::InvalidSource && fw.InboundProbeCount() == 0;
}

static bool test_inbound_malformed_no_state()
{
	KadFirewallCheck fw;
	fw.OnKadStart(1, kTcp);
	BYTE req[1] = { 0x01 };
	const KadFwInboundReqResult r = fw.OnInboundFirewalledReq(kPeerA, kUdp, req, 1, 10, false);
	return r.status == KadFwInboundStatus::WrongSize && !r.sendResponse && fw.InboundProbeCount() == 0 && fw.RateEntryCount() == 0;
}

static bool test_select_skips_unverified()
{
	KadFwPeerCandidate in[2];
	in[0] = make_peer(kPeerA, kUdp, false);
	in[1] = make_peer(kPeerB, kUdp, true);
	KadFwPeerCandidate out[4];
	const size_t n = KadSelectFirewallCheckPeers(in, 2, out, 4);
	return n == 1 && out[0].ipHost == kPeerB;
}

static bool test_select_dedupes_ip()
{
	KadFwPeerCandidate in[2];
	in[0] = make_peer(kPeerA, kUdp, true);
	in[1] = make_peer(kPeerA, 1234, true);
	in[1].lastSeen = 99;
	KadFwPeerCandidate out[4];
	const size_t n = KadSelectFirewallCheckPeers(in, 2, out, 4);
	return n == 1 && out[0].ipHost == kPeerA;
}

static bool test_select_skips_loopback()
{
	KadFwPeerCandidate in[1];
	in[0] = make_peer(0x7F000001u, kUdp, true);
	KadFwPeerCandidate out[4];
	return KadSelectFirewallCheckPeers(in, 1, out, 4) == 0;
}

static bool test_no_open_without_ack()
{
	KadFirewallCheck fw;
	fw.OnKadStart(1, kTcp);
	fw.BeginOutboundCheck(make_peer(kPeerA, kUdp), 10);
	fw.BeginOutboundCheck(make_peer(kPeerB, kUdp), 11);
	BYTE buf[4];
	write_res(buf, kObs1);
	fw.OnFirewalledRes(kPeerA, kUdp, buf, 4, 20);
	fw.OnFirewalledRes(kPeerB, kUdp, buf, 4, 21);
	return fw.TcpState() != KadTcpFirewallState::Open && fw.PublicIpHost() == kObs1;
}

static bool test_opcode_stays_req_not_fw2()
{
	return KadFirewalledReqOpcodeForVersion(0) == KAD_OP_FIREWALLED_REQ && KadFirewalledReqOpcodeForVersion(8) == KAD_OP_FIREWALLED_REQ;
}

static bool test_tick_wrap_safe()
{
	return KadTickElapsed(20, 5, 10) && !KadTickElapsed(14, 5, 10) && KadTickElapsed(13, 0xFFFFFFFEu, 10) // wrapped: 15 ms elapsed
	       && !KadTickElapsed(0xFFFFFFFFu, 0xFFFFFFFEu, 10);                                              // 1 ms elapsed
}

void register_kad_firewall_check_smoke_tests(TestSuite& suite)
{
	suite.add_test("kad_fw_req_valid_exact_2", test_req_valid_exact_2);
	suite.add_test("kad_fw_req_empty", test_req_empty);
	suite.add_test("kad_fw_req_one_byte", test_req_one_byte);
	suite.add_test("kad_fw_req_three_bytes", test_req_three_bytes);
	suite.add_test("kad_fw_req_port_zero", test_req_port_zero);
	suite.add_test("kad_fw_req_port_one", test_req_port_one);
	suite.add_test("kad_fw_req_port_65535", test_req_port_65535);
	suite.add_test("kad_fw_req_endian_4662", test_req_endian_golden_4662);
	suite.add_test("kad_fw_res_valid_exact_4", test_res_valid_exact_4);
	suite.add_test("kad_fw_res_short", test_res_short);
	suite.add_test("kad_fw_res_extra", test_res_extra_byte);
	suite.add_test("kad_fw_res_endian_1_2_3_4", test_res_endian_golden_1_2_3_4);
	suite.add_test("kad_fw_res_invalid_zero", test_res_invalid_zero);
	suite.add_test("kad_fw_res_invalid_broadcast", test_res_invalid_broadcast);
	suite.add_test("kad_fw_res_invalid_rfc1918", test_res_invalid_rfc1918);
	suite.add_test("kad_fw_res_invalid_multicast", test_res_invalid_multicast);
	suite.add_test("kad_fw_ack_empty", test_ack_empty_ok);
	suite.add_test("kad_fw2_min_19", test_fw2_min_19);
	suite.add_test("kad_fw_initial_unknown", test_initial_unknown);
	suite.add_test("kad_fw_test_starts_context", test_test_starts_and_context);
	suite.add_test("kad_fw_valid_matching_res", test_valid_matching_res);
	suite.add_test("kad_fw_unsolicited_res", test_unsolicited_res_ignored);
	suite.add_test("kad_fw_stale_res", test_stale_res_ignored);
	suite.add_test("kad_fw_duplicate_res", test_duplicate_res_ignored);
	suite.add_test("kad_fw_wrong_peer_res", test_wrong_peer_res_ignored);
	suite.add_test("kad_fw_timeout_firewalled", test_timeout_goes_firewalled);
	suite.add_test("kad_fw_reset", test_reset_unknown);
	suite.add_test("kad_fw_two_acks_open", test_two_acks_open);
	suite.add_test("kad_fw_unsolicited_ack", test_unsolicited_ack_ignored);
	suite.add_test("kad_fw_duplicate_ack", test_duplicate_ack_ignored);
	suite.add_test("kad_fw_tcp_ack_0xa8", test_tcp_ack_0xa8);
	suite.add_test("kad_fw_bounded_simultaneous", test_bounded_simultaneous);
	suite.add_test("kad_fw_one_observation_insufficient", test_one_observation_not_authoritative);
	suite.add_test("kad_fw_two_peers_agree", test_two_independent_agree);
	suite.add_test("kad_fw_conflicting_peers", test_conflicting_peers);
	suite.add_test("kad_fw_duplicate_peer_vote", test_duplicate_peer_not_double_counted);
	suite.add_test("kad_fw_invalid_observation", test_invalid_observation_rejected);
	suite.add_test("kad_fw_reset_network_change", test_public_ip_reset_on_network_change);
	suite.add_test("kad_fw_inbound_probe_sender", test_inbound_valid_probe_is_sender);
	suite.add_test("kad_fw_inbound_no_third_party", test_inbound_cannot_target_third_party);
	suite.add_test("kad_fw_inbound_repeat", test_inbound_repeat_rate_limited);
	suite.add_test("kad_fw_inbound_flood_capped", test_inbound_flood_capped);
	suite.add_test("kad_fw_inbound_invalid_source", test_inbound_invalid_source);
	suite.add_test("kad_fw_inbound_malformed", test_inbound_malformed_no_state);
	suite.add_test("kad_fw_select_skips_unverified", test_select_skips_unverified);
	suite.add_test("kad_fw_select_dedupes_ip", test_select_dedupes_ip);
	suite.add_test("kad_fw_select_skips_loopback", test_select_skips_loopback);
	suite.add_test("kad_fw_res_not_tcp_open", test_no_open_without_ack);
	suite.add_test("kad_fw_opcode_stays_req", test_opcode_stays_req_not_fw2);
	suite.add_test("kad_fw_tick_wrap_safe", test_tick_wrap_safe);
}
