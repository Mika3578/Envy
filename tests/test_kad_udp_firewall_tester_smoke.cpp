//
// test_kad_udp_firewall_tester_smoke.cpp
//
// Deterministic tests for the Kad2 UDP firewall tester (#515).
// Pure helpers only — no CKademlia, no live network, no Sleep().
// Wire oracle: eMule Community opcodes.h / KademliaUDPListener.cpp /
// UDPFirewallTester.cpp / BaseClient.cpp (see KadUdpFirewallTester.h).
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//

#include "test_framework.h"
#include "../Envy/KadUdpFirewallTester.h"

#include <cstring>

static const DWORD kPeerA = 0x08080808u; // 8.8.8.8
static const DWORD kPeerB = 0x09090909u; // 9.9.9.9
static const DWORD kPeerC = 0x04040404u; // 4.4.4.4
static const WORD kUdp = 4672;

// ---- 0x62 KADEMLIA2_FIREWALLUDP framing ----

static bool test_udpfw_result_exact_3()
{
	// <errorcode 1=0><port 4672 LE>
	const BYTE golden[] = { 0x00, 0x40, 0x12 };
	KadUdpFwResultPacket res;
	return KadParseFirewallUdpResult(golden, 3, res) == KadUdpFwParseStatus::Ok && res.errorCode == 0 && res.incomingPort == kUdp;
}

static bool test_udpfw_result_truncated()
{
	const BYTE buf[2] = { 0x00, 0x40 };
	KadUdpFwResultPacket res;
	return KadParseFirewallUdpResult(buf, 2, res) == KadUdpFwParseStatus::WrongSize && KadParseFirewallUdpResult(nullptr, 3, res) == KadUdpFwParseStatus::WrongSize;
}

static bool test_udpfw_result_trailing_tolerated()
{
	// eMule peeks the fields after a < 3 check; trailing bytes are ignored.
	const BYTE buf[5] = { 0x01, 0x40, 0x12, 0xAA, 0xBB };
	KadUdpFwResultPacket res;
	return KadParseFirewallUdpResult(buf, 5, res) == KadUdpFwParseStatus::Ok && res.errorCode == 1 && res.incomingPort == kUdp;
}

static bool test_udpfw_probe_build_golden()
{
	BYTE out[3] = {};
	KadBuildFirewallUdpProbe(out, KAD_UDPFW_ERROR_OK, 4662); // 4662 = 0x1236 -> 36 12
	return out[0] == 0x00 && out[1] == 0x36 && out[2] == 0x12;
}

static bool test_udpfw_probe_build_biased()
{
	BYTE out[3] = {};
	KadBuildFirewallUdpProbe(out, KAD_UDPFW_ERROR_BIASED, 0xFFFF);
	return out[0] == 0x01 && out[1] == 0xFF && out[2] == 0xFF;
}

// ---- 0xA7 OP_FWCHECKUDPREQ framing ----

static bool test_udpfw_req_exact_8()
{
	// <intern 4672><extern 0><key 0xAABBCCDD> per eMule SendFirewallCheckUDPRequest.
	BYTE buf[8];
	KadBuildUdpFwCheckRequest(buf, kUdp, 0, 0xAABBCCDDu);
	const BYTE golden[] = { 0x40, 0x12, 0x00, 0x00, 0xDD, 0xCC, 0xBB, 0xAA };
	return memcmp(buf, golden, 8) == 0;
}

static bool test_udpfw_req_parse_roundtrip()
{
	BYTE buf[8];
	KadBuildUdpFwCheckRequest(buf, 1234, 5678, 0x01020304u);
	KadUdpFwCheckRequest req;
	return KadParseUdpFwCheckRequest(buf, 8, req) == KadUdpFwParseStatus::Ok && req.internPort == 1234 && req.externPort == 5678 && req.senderKey == 0x01020304u;
}

static bool test_udpfw_req_truncated()
{
	BYTE buf[8] = {};
	KadUdpFwCheckRequest req;
	return KadParseUdpFwCheckRequest(buf, 7, req) == KadUdpFwParseStatus::WrongSize && KadParseUdpFwCheckRequest(nullptr, 8, req) == KadUdpFwParseStatus::WrongSize;
}

static bool test_udpfw_req_trailing_tolerated()
{
	BYTE buf[10] = {};
	KadUdpFwCheckRequest req;
	return KadParseUdpFwCheckRequest(buf, 10, req) == KadUdpFwParseStatus::Ok;
}

// ---- Port rule + probe plan ----

static bool test_udpfw_port_rule()
{
	return KadUdpFwIncomingPortExpected(kUdp, kUdp, 0) && !KadUdpFwIncomingPortExpected(0, kUdp, 0) && !KadUdpFwIncomingPortExpected(1234, kUdp, 0) && KadUdpFwIncomingPortExpected(9999, kUdp, 9999) && !KadUdpFwIncomingPortExpected(0, 0, 0);
}

static bool test_udpfw_plan_intern_only()
{
	const KadUdpFwProbePlan plan = KadPlanFirewallUdpProbes(kUdp, 0, false);
	return plan.count == 1 && plan.errorCode[0] == KAD_UDPFW_ERROR_OK && plan.targetPort[0] == kUdp;
}

static bool test_udpfw_plan_intern_and_extern()
{
	const KadUdpFwProbePlan plan = KadPlanFirewallUdpProbes(kUdp, 4673, false);
	return plan.count == 2 && plan.targetPort[0] == kUdp && plan.targetPort[1] == 4673 && plan.errorCode[0] == KAD_UDPFW_ERROR_OK && plan.errorCode[1] == KAD_UDPFW_ERROR_OK;
}

static bool test_udpfw_plan_same_port_single()
{
	const KadUdpFwProbePlan plan = KadPlanFirewallUdpProbes(kUdp, kUdp, false);
	return plan.count == 1;
}

static bool test_udpfw_plan_biased_marks_both()
{
	const KadUdpFwProbePlan plan = KadPlanFirewallUdpProbes(kUdp, 4673, true);
	return plan.count == 2 && plan.errorCode[0] == KAD_UDPFW_ERROR_BIASED && plan.errorCode[1] == KAD_UDPFW_ERROR_BIASED;
}

static bool test_udpfw_plan_zero_intern_aborts()
{
	const KadUdpFwProbePlan plan = KadPlanFirewallUdpProbes(0, 4673, false);
	return plan.count == 0;
}

// ---- Candidate eligibility (eMule QueryNextClient rules) ----

static bool test_udpfw_candidate_rules()
{
	const BYTE v6 = KAD_UDPFW_MIN_VERSION;
	return KadUdpFwCandidateEligible(v6, kUdp, kPeerA, 0, false, false) && !KadUdpFwCandidateEligible(5, kUdp, kPeerA, 0, false, false) && !KadUdpFwCandidateEligible(0, kUdp, kPeerA, 0, false, false) && !KadUdpFwCandidateEligible(v6, 0, kPeerA, 0, false, false) && !KadUdpFwCandidateEligible(v6, kUdp, 0x7F000001u, 0, false, false) // loopback
	       && !KadUdpFwCandidateEligible(v6, kUdp, 0xFFFFFFFFu, 0, false, false)                                                                                                                                                                                                                                                            // broadcast
	       && !KadUdpFwCandidateEligible(v6, kUdp, kPeerA, kPeerA, false, false)                                                                                                                                                                                                                                                            // self
	       && !KadUdpFwCandidateEligible(v6, kUdp, kPeerA, 0, true, false)                                                                                                                                                                                                                                                                  // in routing zone
	       && !KadUdpFwCandidateEligible(v6, kUdp, kPeerA, 0, false, true);                                                                                                                                                                                                                                                                 // already asked
}

// ---- State machine ----

static KadUdpFirewallTester make_running(DWORD now)
{
	KadUdpFirewallTester t;
	t.OnKadStart(now);
	t.ReCheck(now + 1, false);
	t.BeginProbeRequest(kPeerA, now + 2);
	t.BeginProbeRequest(kPeerB, now + 3);
	return t;
}

static bool test_udpfw_initial_unknown()
{
	KadUdpFirewallTester t;
	t.OnKadStart(1000);
	// A fresh tester owes a round: two probe requests may be registered as
	// soon as the Kad network is joined.
	return t.State() == KadUdpFirewallState::Unknown && !t.IsVerified() && t.IsRunning() && t.UsedCount() == 0 && t.NeedsProbeRequests();
}

static bool test_udpfw_begin_starts_testing()
{
	KadUdpFirewallTester t;
	t.OnKadStart(1000);
	t.ReCheck(1000, false);
	if (!t.BeginProbeRequest(kPeerA, 1010))
		return false;
	if (t.State() != KadUdpFirewallState::Testing)
		return false;
	if (t.RunningCount() != 1 || t.FinishedCount() != 0)
		return false;
	// Second client accepted, third refused (eMule asks exactly two).
	if (!t.BeginProbeRequest(kPeerB, 1020))
		return false;
	return !t.NeedsProbeRequests() && !t.BeginProbeRequest(kPeerC, 1030);
}

static bool test_udpfw_success_is_open_verified()
{
	KadUdpFirewallTester t = make_running(1000);
	if (t.OnProbeResult(kPeerA, true, false, 1100) != KadUdpFwResultStatus::Succeeded)
		return false;
	if (t.State() != KadUdpFirewallState::Open || !t.IsVerified())
		return false;
	if (t.IsRunning() || t.NeedsProbeRequests())
		return false;
	// Late second answer only consumes the slot (eMule: "its all over already").
	return t.OnProbeResult(kPeerB, true, false, 1200) == KadUdpFwResultStatus::NotRunning && t.State() == KadUdpFirewallState::Open;
}

static bool test_udpfw_two_failures_firewalled_verified()
{
	KadUdpFirewallTester t = make_running(1000);
	if (t.OnProbeResult(kPeerA, false, false, 1100) != KadUdpFwResultStatus::Accepted)
		return false;
	if (t.State() != KadUdpFirewallState::Testing || !t.IsRunning())
		return false;
	if (t.OnProbeResult(kPeerB, false, false, 1200) != KadUdpFwResultStatus::Failed)
		return false;
	return t.State() == KadUdpFirewallState::Firewalled && t.IsVerified() && !t.IsRunning();
}

static bool test_udpfw_cancelled_does_not_finish()
{
	KadUdpFirewallTester t;
	t.OnKadStart(1000);
	t.ReCheck(1000, false);
	t.BeginProbeRequest(kPeerA, 1010);
	// Biased helper result (errorcode 1 on expected port): cancelled.
	if (t.OnProbeResult(kPeerA, false, true, 1100) != KadUdpFwResultStatus::Cancelled)
		return false;
	if (t.FinishedCount() != 0 || !t.IsRunning() || !t.NeedsProbeRequests())
		return false;
	// A cancelled slot is not re-asked within the round.
	return t.AlreadyRequested(kPeerA) && t.BeginProbeRequest(kPeerB, 1200);
}

static bool test_udpfw_cancel_on_send_failure_frees_slot()
{
	KadUdpFirewallTester t;
	t.OnKadStart(1000);
	t.ReCheck(1000, false);
	t.BeginProbeRequest(kPeerA, 1010);
	t.CancelProbeRequest(kPeerA);
	if (t.RunningCount() != 0 || t.AlreadyRequested(kPeerA))
		return false;
	// Unknown IP cancel is a no-op; the round stays in flight (Testing).
	t.CancelProbeRequest(kPeerC);
	return t.RunningCount() == 0 && t.State() == KadUdpFirewallState::Testing;
}

static bool test_udpfw_unrequested_result_ignored()
{
	KadUdpFirewallTester t;
	t.OnKadStart(1000);
	return t.OnProbeResult(kPeerA, true, false, 1000) == KadUdpFwResultStatus::Unrequested && t.State() == KadUdpFirewallState::Unknown;
}

static bool test_udpfw_duplicate_result_ignored()
{
	KadUdpFirewallTester t = make_running(1000);
	if (t.OnProbeResult(kPeerA, false, false, 1100) != KadUdpFwResultStatus::Accepted)
		return false;
	return t.OnProbeResult(kPeerA, true, false, 1200) == KadUdpFwResultStatus::Duplicate && t.FinishedCount() == 1;
}

static bool test_udpfw_client_closed_counts_failure()
{
	KadUdpFirewallTester t = make_running(1000);
	if (t.OnProbeClientClosed(kPeerA, 1100) != KadUdpFwResultStatus::Accepted)
		return false;
	// The remaining client answers success: round still opens.
	if (t.OnProbeResult(kPeerB, true, false, 1200) != KadUdpFwResultStatus::Succeeded)
		return false;
	return t.State() == KadUdpFirewallState::Open && t.IsVerified();
}

static bool test_udpfw_timeout_needs_tcp_firewalled()
{
	KadUdpFirewallTester t = make_running(1000); // testStart ~1001
	t.OnTimer(1001 + KAD_UDPFW_TEST_TIMEOUT_MS + 1, false);
	if (t.IsFirewalledUdp(false) || t.IsFirewalledUdp(true))
		return false; // TCP open: no firewalled verdict from the timeout
	t.OnTimer(1001 + KAD_UDPFW_TEST_TIMEOUT_MS + 2, true);
	// The timeout verdict is published as Firewalled (eMule's IsFirewalledUDP
	// reports firewalled from that moment) while verification stays false.
	return t.IsFirewalledUdp(true) && t.IsFirewalledUdp(false) && !t.IsVerified() && t.State() == KadUdpFirewallState::Firewalled;
}

static bool test_udpfw_timeout_cleared_by_verdict()
{
	KadUdpFirewallTester t = make_running(1000);
	t.OnTimer(1001 + KAD_UDPFW_TEST_TIMEOUT_MS + 1, true);
	if (!t.IsFirewalledUdp(true))
		return false;
	if (t.OnProbeResult(kPeerA, true, false, 1001 + KAD_UDPFW_TEST_TIMEOUT_MS + 2) != KadUdpFwResultStatus::Succeeded)
		return false;
	return t.State() == KadUdpFirewallState::Open && t.IsVerified() && t.OnProbeResult(kPeerB, true, false, 1300) == KadUdpFwResultStatus::NotRunning;
}

static bool test_udpfw_last_state_during_retest()
{
	KadUdpFirewallTester t = make_running(1000);
	if (t.OnProbeResult(kPeerA, false, false, 1100) != KadUdpFwResultStatus::Accepted)
		return false;
	if (t.OnProbeResult(kPeerB, false, false, 1200) != KadUdpFwResultStatus::Failed)
		return false;
	// Confirmed firewalled re-tests after the recheck cadence.
	t.OnTimer(1200 + KAD_UDPFW_RECHECK_MS + 1, true);
	if (t.State() != KadUdpFirewallState::Testing || !t.IsVerified())
		return false;
	if (!t.NeedsProbeRequests())
		return false;
	// While the fresh round runs, the last confirmed state is reported.
	return t.IsFirewalledUdp(true) && !t.IsFirewalledUdp(false);
}

static bool test_udpfw_recheck_invalidates_outstanding_probes()
{
	KadUdpFirewallTester t = make_running(1000);
	t.OnProbeResult(kPeerA, false, false, 1100);
	t.OnProbeResult(kPeerB, false, false, 1200);
	t.OnTimer(1200 + KAD_UDPFW_RECHECK_MS + 1, true);
	// A fresh round invalidates the previous round's outstanding probes so
	// their late results or disconnects can neither vote nor finish it.
	if (t.UsedCount() != 0)
		return false;
	if (!t.NeedsProbeRequests() || t.RunningCount() != 0)
		return false;
	if (t.OnProbeResult(kPeerA, true, false, 1300) != KadUdpFwResultStatus::Unrequested)
		return false;
	// The verified flag survives a recheck (eMule keeps m_bIsFWVerifiedUDP);
	// only Reset (kad stop / port change) drops it.
	return t.IsVerified() && t.State() == KadUdpFirewallState::Testing;
}

static bool test_udpfw_round_bumps_on_fresh_rounds()
{
	KadUdpFirewallTester t;
	const DWORD start = t.Round();
	t.ReCheck(1000, false);
	if (t.Round() == start)
		return false;
	const DWORD afterRecheck = t.Round();
	t.OnKadStart(2000); // Reset() path (kad stop/start, port change)
	return t.Round() != afterRecheck && !t.IsVerified() && t.UsedCount() == 0;
}

static bool test_udpfw_used_history_bounded_and_rotates()
{
	KadUdpFirewallTester t;
	t.OnKadStart(1000);
	t.ReCheck(1000, false);
	// Keep the round open by cancelling every result so needs stay true.
	for (size_t i = 0; i < KAD_UDPFW_MAX_USED_CLIENTS + 4; ++i)
	{
		const DWORD ip = 0x0A000000u + static_cast<DWORD>(i);
		if (!t.BeginProbeRequest(ip, 1000 + static_cast<DWORD>(i)))
			return false;
		t.OnProbeResult(ip, false, true, 1000 + static_cast<DWORD>(i)); // cancelled
	}
	return t.UsedCount() == KAD_UDPFW_MAX_USED_CLIENTS && t.IsRunning() && t.NeedsProbeRequests() && t.State() == KadUdpFirewallState::Testing;
}

static bool test_udpfw_stop_resets_everything()
{
	KadUdpFirewallTester t = make_running(1000);
	t.OnProbeResult(kPeerA, false, false, 1100);
	t.OnKadStop();
	return t.State() == KadUdpFirewallState::Unknown && !t.IsVerified() && t.UsedCount() == 0 && t.RunningCount() == 0 && t.FinishedCount() == 0 && t.TestStart() == 0;
}

static bool test_udpfw_tcp_state_independent()
{
	// A UDP verdict never implies anything about the TCP state holder
	// (separate classes here; the shared enum only mirrors value names).
	KadUdpFirewallTester udp;
	udp.OnKadStart(1);
	udp.ReCheck(1, false);
	udp.BeginProbeRequest(kPeerA, 10);
	udp.BeginProbeRequest(kPeerB, 11);
	udp.OnProbeResult(kPeerA, true, false, 20);
	KadFirewallCheck tcp;
	tcp.OnKadStart(1, 4662);
	return udp.State() == KadUdpFirewallState::Open && tcp.TcpState() == KadTcpFirewallState::Unknown && static_cast<BYTE>(KadUdpFirewallState::Open) == static_cast<BYTE>(KadTcpFirewallState::Open) && static_cast<BYTE>(KadUdpFirewallState::Firewalled) == static_cast<BYTE>(KadTcpFirewallState::Firewalled);
}

static bool test_udpfw_result_status_values_distinct()
{
	return KadUdpFwResultStatus::Accepted != KadUdpFwResultStatus::Unrequested && KadUdpFwResultStatus::Unrequested != KadUdpFwResultStatus::Duplicate && KadUdpFwResultStatus::Duplicate != KadUdpFwResultStatus::NotRunning && KadUdpFwResultStatus::NotRunning != KadUdpFwResultStatus::Cancelled && KadUdpFwResultStatus::Cancelled != KadUdpFwResultStatus::Failed && KadUdpFwResultStatus::Failed != KadUdpFwResultStatus::Succeeded;
}

void register_kad_udp_firewall_tester_smoke_tests(TestSuite& suite)
{
	suite.add_test("kad_udpfw_result_exact_3", test_udpfw_result_exact_3);
	suite.add_test("kad_udpfw_result_truncated", test_udpfw_result_truncated);
	suite.add_test("kad_udpfw_result_trailing", test_udpfw_result_trailing_tolerated);
	suite.add_test("kad_udpfw_probe_build", test_udpfw_probe_build_golden);
	suite.add_test("kad_udpfw_probe_build_biased", test_udpfw_probe_build_biased);
	suite.add_test("kad_udpfw_req_build", test_udpfw_req_exact_8);
	suite.add_test("kad_udpfw_req_roundtrip", test_udpfw_req_parse_roundtrip);
	suite.add_test("kad_udpfw_req_truncated", test_udpfw_req_truncated);
	suite.add_test("kad_udpfw_req_trailing", test_udpfw_req_trailing_tolerated);
	suite.add_test("kad_udpfw_port_rule", test_udpfw_port_rule);
	suite.add_test("kad_udpfw_plan_intern_only", test_udpfw_plan_intern_only);
	suite.add_test("kad_udpfw_plan_intern_extern", test_udpfw_plan_intern_and_extern);
	suite.add_test("kad_udpfw_plan_same_port", test_udpfw_plan_same_port_single);
	suite.add_test("kad_udpfw_plan_biased", test_udpfw_plan_biased_marks_both);
	suite.add_test("kad_udpfw_plan_zero_intern", test_udpfw_plan_zero_intern_aborts);
	suite.add_test("kad_udpfw_candidate_rules", test_udpfw_candidate_rules);
	suite.add_test("kad_udpfw_initial_unknown", test_udpfw_initial_unknown);
	suite.add_test("kad_udpfw_begin_testing", test_udpfw_begin_starts_testing);
	suite.add_test("kad_udpfw_success_open", test_udpfw_success_is_open_verified);
	suite.add_test("kad_udpfw_two_failures", test_udpfw_two_failures_firewalled_verified);
	suite.add_test("kad_udpfw_cancelled_no_finish", test_udpfw_cancelled_does_not_finish);
	suite.add_test("kad_udpfw_cancel_frees_slot", test_udpfw_cancel_on_send_failure_frees_slot);
	suite.add_test("kad_udpfw_unrequested", test_udpfw_unrequested_result_ignored);
	suite.add_test("kad_udpfw_duplicate", test_udpfw_duplicate_result_ignored);
	suite.add_test("kad_udpfw_closed_counts_failure", test_udpfw_client_closed_counts_failure);
	suite.add_test("kad_udpfw_timeout_tcp_gate", test_udpfw_timeout_needs_tcp_firewalled);
	suite.add_test("kad_udpfw_timeout_cleared", test_udpfw_timeout_cleared_by_verdict);
	suite.add_test("kad_udpfw_last_state_retest", test_udpfw_last_state_during_retest);
	suite.add_test("kad_udpfw_recheck_invalidates", test_udpfw_recheck_invalidates_outstanding_probes);
	suite.add_test("kad_udpfw_round_bumps", test_udpfw_round_bumps_on_fresh_rounds);
	suite.add_test("kad_udpfw_used_bounded", test_udpfw_used_history_bounded_and_rotates);
	suite.add_test("kad_udpfw_stop_resets", test_udpfw_stop_resets_everything);
	suite.add_test("kad_udpfw_tcp_independent", test_udpfw_tcp_state_independent);
	suite.add_test("kad_udpfw_status_distinct", test_udpfw_result_status_values_distinct);
}