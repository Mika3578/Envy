//
// KadUdpFirewallTester.h
//
// Kad2 UDP firewall tester (#515): the eMule CUDPFirewallTester state machine
// plus the KADEMLIA2_FIREWALLUDP (0x62) / OP_FWCHECKUDPREQ (0xA7) wire helpers.
// Pure helpers shared by CKademlia/CEDClient and EnvyTests. No MFC windows,
// no sockets.
//
// Wire reference (eMule Community, irwir/eMule master @ 88a8c8f):
//   opcodes.h:618  KADEMLIA2_FIREWALLUDP 0x62  <errorcode [1]><UDPPort_Used [2]>
//   opcodes.h:282  OP_FWCHECKUDPREQ 0xA7  <Inter_Port 2><Extern_Port 2><KadUDPKey 4>
//                  (*Support required for Kadversion >= 6)
//   KademliaUDPListener.cpp Process_KADEMLIA2_FIREWALLUDP: packets shorter
//   than 3 bytes are rejected; the incoming port must equal our intern or
//   external Kad UDP port and be non-zero; errorcode 0 is a success, any
//   other value cancels the test.
//   BaseClient.cpp SendFirewallCheckUDPRequest / ProcessFirewallCheckUDPRequest:
//   the 0xA7 request rides an ED2K C2C TCP connection; the answering node
//   sends one FIREWALLUDP probe to the intern port and, when different and
//   non-zero, a second probe to the extern port; errorcode 1 marks a biased
//   result (the helper already knows the requester from transfers or the
//   routing zone). A probe-request client that disconnects after the request
//   was sent counts as a failed test; one that never connected counts as
//   cancelled (BaseClient.cpp Disconnected).
//   UDPFirewallTester.cpp: UDP_FIREWALLTEST_CLIENTSTOASK = 2. One positive
//   result is enough for open; a running test that cannot finish within
//   MIN2MS(6) is reported firewalled (unverified); cancelled results do not
//   advance the finished count.
//
// Envy notes:
//   - UDP verify keys are phase D (#513): probes and requests are sent
//     unencrypted with a zero key. eMule answers unencrypted when the
//     requester key is zero, so framing stays interoperable either way.
//   - eMule acquires fresh-IP test clients from a NODEFWCHECKUDP Kad lookup
//     and creates new TCP connections for them. Envy selects eligible idle
//     clients from its existing client pool (kad >= 6, idle, UDP port known,
//     endpoint absent from the routing zone) and never opens a connection
//     just for the test. The wire and the state machine are unchanged.
//   - The used-client history is capped (eMule keeps it unbounded); entries
//     rotate so the no-repeat-per-IP rule still holds for the recent past.
//   - TCP and UDP firewall states stay distinct. Nothing here flips
//     Network.IsFirewalled(); the Hello Kad capability nibble stays 0.
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//

#pragma once

#include <windows.h>
#include "KadFirewallCheck.h"

// KADEMLIA2_FIREWALLUDP (eMule opcodes.h:618).
constexpr BYTE KAD_OP_FIREWALLUDP = 0x62;
// OP_FWCHECKUDPREQ (0xA7) rides ED2K C2C TCP; the handler and sender use
// ED2K_C2C_FWCHECKUDPREQ from Envy/EDPacket.h.

constexpr size_t KAD_UDPFW_RESULT_MIN_SIZE = 3; // <errorcode 1><incomingPort 2>
constexpr size_t KAD_UDPFW_REQ_MIN_SIZE = 8;    // <internPort 2><externPort 2><senderKey 4>

// UDP_FIREWALLTEST_CLIENTSTOASK: more clients increase false positives,
// fewer increase false negatives (eMule UDPFirewallTester.cpp).
constexpr size_t KAD_UDPFW_CLIENTS_TO_ASK = 2;
// eMule reports firewalled when a running test cannot finish within MIN2MS(6).
constexpr DWORD KAD_UDPFW_TEST_TIMEOUT_MS = 6 * 60 * 1000;
// A confirmed firewalled UDP state re-tests on the TCP baseline recheck
// cadence so a since-opened port does not stay firewalled forever
// (bounded: 2 probe requests per round).
constexpr DWORD KAD_UDPFW_RECHECK_MS = KAD_FW_RECHECK_MS;
// KADEMLIA_VERSION6_49aBETA: the first Kad version that understands the
// UDP firewall check (eMule opcodes.h:27).
constexpr BYTE KAD_UDPFW_MIN_VERSION = 6;
// Result errorcode 0: the probe result is valid. Any other value (eMule
// uses 1 for "result would be biased") cancels the test round.
constexpr BYTE KAD_UDPFW_ERROR_OK = 0;
constexpr BYTE KAD_UDPFW_ERROR_BIASED = 1;
// Inbound 0x62 flood guard per source IP (a finished test yields at most two
// result packets; anything beyond this rate is abusive or spoofed).
constexpr unsigned KAD_UDPFW_RESULT_PER_MINUTE = 4;
// Bounded used-client history (eMule: unbounded CList; Envy discipline caps).
constexpr size_t KAD_UDPFW_MAX_USED_CLIENTS = 8;

enum class KadUdpFwParseStatus : BYTE
{
	Ok = 0,
	WrongSize
};

// Inbound KADEMLIA2_FIREWALLUDP (0x62) body.
struct KadUdpFwResultPacket
{
	BYTE errorCode = 0;
	WORD incomingPort = 0;
};

// OP_FWCHECKUDPREQ (0xA7) body.
struct KadUdpFwCheckRequest
{
	WORD internPort = 0;
	WORD externPort = 0;
	DWORD senderKey = 0;
};

inline KadUdpFwParseStatus KadParseFirewallUdpResult(const BYTE* data, size_t len, KadUdpFwResultPacket& out)
{
	out = KadUdpFwResultPacket{};
	// eMule rejects uLenPacket < 3 and then peeks the two fields, so trailing
	// bytes are tolerated but truncation is not.
	if (data == nullptr || len < KAD_UDPFW_RESULT_MIN_SIZE)
		return KadUdpFwParseStatus::WrongSize;
	out.errorCode = data[0];
	out.incomingPort = KadReadU16LE(data + 1);
	return KadUdpFwParseStatus::Ok;
}

inline void KadBuildFirewallUdpProbe(BYTE* out3, BYTE errorCode, WORD incomingPort)
{
	if (out3 == nullptr)
		return;
	out3[0] = errorCode;
	KadWriteU16LE(out3 + 1, incomingPort);
}

inline KadUdpFwParseStatus KadParseUdpFwCheckRequest(const BYTE* data, size_t len, KadUdpFwCheckRequest& out)
{
	out = KadUdpFwCheckRequest{};
	// eMule reads 2+2+4 via CSafeMemFile without an explicit length check;
	// a shorter body throws inside the reads, so >= 8 is the de-facto frame.
	if (data == nullptr || len < KAD_UDPFW_REQ_MIN_SIZE)
		return KadUdpFwParseStatus::WrongSize;
	out.internPort = KadReadU16LE(data);
	out.externPort = KadReadU16LE(data + 2);
	out.senderKey = KadReadU32LE(data + 4);
	return KadUdpFwParseStatus::Ok;
}

inline void KadBuildUdpFwCheckRequest(BYTE* out8, WORD internPort, WORD externPort, DWORD senderKey)
{
	if (out8 == nullptr)
		return;
	KadWriteU16LE(out8, internPort);
	KadWriteU16LE(out8 + 2, externPort);
	KadWriteU32LE(out8 + 4, senderKey);
}

// Port rule from Process_KADEMLIA2_FIREWALLUDP: the reported incoming port
// must be one of our Kad UDP ports and non-zero, otherwise the result counts
// as cancelled. Envy currently knows only its intern (listen) port; the
// external port is unknown until an extern-port lookup exists.
inline bool KadUdpFwIncomingPortExpected(WORD incomingPort, WORD ourInternUdpPort, WORD ourExternUdpPort)
{
	if (incomingPort == 0)
		return false;
	if (ourInternUdpPort != 0 && incomingPort == ourInternUdpPort)
		return true;
	return ourExternUdpPort != 0 && incomingPort == ourExternUdpPort;
}

// Probe plan for answering an inbound 0xA7 (eMule ProcessFirewallCheckUDPRequest).
// The helper sends one probe to the intern port; a second probe goes to the
// extern port when it is present and different. A biased helper (requester
// already known from transfers/chat/routing zone) marks both probes with
// errorcode 1 so the requester discards the result instead of trusting it.
constexpr size_t KAD_UDPFW_PROBES_MAX = 2;

struct KadUdpFwProbePlan
{
	BYTE count = 0;
	BYTE errorCode[KAD_UDPFW_PROBES_MAX] = {};
	WORD targetPort[KAD_UDPFW_PROBES_MAX] = {};
};

inline KadUdpFwProbePlan KadPlanFirewallUdpProbes(
    WORD internPort, WORD externPort, bool requesterAlreadyKnown)
{
	KadUdpFwProbePlan plan;
	// eMule aborts when the intern port is zero; the probe target would be
	// meaningless and the requester's test would never see an answer.
	if (internPort == 0)
		return plan;
	const BYTE errorCode = requesterAlreadyKnown ? KAD_UDPFW_ERROR_BIASED : KAD_UDPFW_ERROR_OK;
	plan.errorCode[plan.count] = errorCode;
	plan.targetPort[plan.count] = internPort;
	++plan.count;
	if (externPort != 0 && externPort != internPort && plan.count < KAD_UDPFW_PROBES_MAX)
	{
		plan.errorCode[plan.count] = errorCode;
		plan.targetPort[plan.count] = externPort;
		++plan.count;
	}
	return plan;
}

// Candidate eligibility for outbound probe requests (eMule
// CUDPFirewallTester::QueryNextClient): kad version >= 6, a known Kad UDP
// port, a usable IP, never requested before, and an endpoint that is absent
// from the routing zone so the probe IP carries no prior Kad UDP history.
inline bool KadUdpFwCandidateEligible(
    BYTE kadVersion,
    WORD kadUdpPort,
    DWORD ipHost,
    DWORD ourPublicIpHost,
    bool inRoutingZone,
    bool alreadyRequested)
{
	if (kadVersion < KAD_UDPFW_MIN_VERSION)
		return false;
	if (kadUdpPort == 0)
		return false;
	if (!KadIpv4IsUsableFirewallPeer(ipHost))
		return false;
	if (ipHost == ourPublicIpHost)
		return false;
	if (inRoutingZone || alreadyRequested)
		return false;
	return true;
}

enum class KadUdpFwResultStatus : BYTE
{
	Accepted = 0, // consumed; round continues (or was cancelled and re-asks)
	Unrequested,  // IP never requested a check for
	Duplicate,    // this test client already answered once
	NotRunning,   // test round already finished; answer only consumed
	Cancelled,    // valid cancelled result (biased/wrong-port/never connected)
	Failed,       // valid negative result; round closed as firewalled
	Succeeded     // valid positive result; round closed as open
};

// eMule CUDPFirewallTester, adapted to Envy's bounded-state discipline.
// The caller classifies inbound 0x62 packets (port rule + errorcode) and
// passes cancelled/succeeded flags exactly like eMule's listener does.
class KadUdpFirewallTester
{
public:
	KadUdpFirewallTester()
	{
		Reset();
	}

	void Reset()
	{
		m_state = KadUdpFirewallState::Unknown;
		m_verified = false;
		m_timedOut = false;
		m_lastState = false;
		m_testStart = 0;
		m_lastRecheck = 0;
		m_running = 0;
		m_finished = 0;
		ClearUsed();
		++m_round;
	}

	void OnKadStart(DWORD now)
	{
		Reset();
		m_lastRecheck = now;
	}

	void OnKadStop()
	{
		Reset();
	}

	// eMule ReCheckFirewallUDP(bSetUnverified): counters reset, the last
	// confirmed state is captured for IsFirewalledUdp(true), and the verified
	// flag is kept or dropped per argument (eMule keeps m_bIsFWVerifiedUDP
	// across rechecks; only Reset drops it). Envy deviation from eMule's
	// kept used-client list: the list is cleared so probes outstanding from
	// the previous round can neither vote (late results) nor finish (late
	// client disconnects) the fresh round.
	void ReCheck(DWORD now, bool setUnverified)
	{
		m_running = 0;
		m_finished = 0;
		m_testStart = now;
		m_timedOut = false;
		m_lastState = IsFirewalled();
		m_verified = (m_verified && !setUnverified);
		m_lastRecheck = now;
		m_state = KadUdpFirewallState::Testing;
		ClearUsed();
		++m_round;
	}

	// Advisory round id: bumped whenever a fresh round begins (kad start,
	// recheck, port change). Lock-free readers may act one tick late; the
	// tester no-ops for already-requested IPs either way.
	DWORD Round() const
	{
		return m_round;
	}

	bool IsRunning() const
	{
		return m_finished < KAD_UDPFW_CLIENTS_TO_ASK;
	}

	bool IsVerified() const
	{
		return m_verified;
	}

	KadUdpFirewallState State() const
	{
		return m_state;
	}

	bool IsFirewalled() const
	{
		return m_state == KadUdpFirewallState::Firewalled;
	}

	// eMule IsFirewalledUDP(bLastStateIfTesting): while a test runs the caller
	// may ask for the last confirmed state instead of the in-flight guess.
	bool IsFirewalledUdp(bool lastStateIfTesting) const
	{
		if (m_timedOut && IsRunning())
			return true;
		if (lastStateIfTesting && IsRunning())
			return m_lastState;
		return IsFirewalled();
	}

	// eMule GetUDPCheckClientsNeeded(): running + finished below the ask cap.
	bool NeedsProbeRequests() const
	{
		return IsRunning() && (m_running + m_finished) < KAD_UDPFW_CLIENTS_TO_ASK;
	}

	bool AlreadyRequested(DWORD ipHost) const
	{
		for (size_t i = 0; i < KAD_UDPFW_MAX_USED_CLIENTS; ++i)
		{
			if (m_used[i].occupied && m_used[i].ipHost == ipHost)
				return true;
		}
		return false;
	}

	// Register an outbound probe request (eMule DoRequestFirewallCheckUDP
	// succeeded). The caller owns actually sending the 0xA7 request; on send
	// failure it calls CancelProbeRequest.
	bool BeginProbeRequest(DWORD ipHost, DWORD now)
	{
		if (!NeedsProbeRequests())
			return false;
		if (ipHost == 0)
			return false;
		if (AlreadyRequested(ipHost))
			return false;

		KadUdpFwUsedClient* slot = FreeUsedSlot();
		if (slot == nullptr)
		{
			// History is full: rotate out the oldest entry (bounded, still
			// honours no-repeat-per-IP for the recent past).
			slot = OldestUsedSlot();
			if (slot == nullptr)
				return false;
		}
		*slot = KadUdpFwUsedClient{};
		slot->ipHost = ipHost;
		slot->requestedAt = now;
		slot->occupied = true;
		++m_running;
		// The first real request of a round starts the timeout clock.
		if (m_testStart == 0)
			m_testStart = now;
		if (m_state == KadUdpFirewallState::Unknown)
			m_state = KadUdpFirewallState::Testing;
		return true;
	}

	// The probe request could not be sent (client never connected, helper
	// became busy, send failure): release the slot so another client can be
	// asked. eMule counts this as cancelled — no finished result.
	void CancelProbeRequest(DWORD ipHost)
	{
		KadUdpFwUsedClient* slot = FindUsed(ipHost);
		if (slot == nullptr || slot->answered)
			return;
		*slot = KadUdpFwUsedClient{};
		if (m_running > 0)
			--m_running;
	}

	// eMule SetUDPFWCheckResult. The caller supplies the eMule listener's
	// classification: succeeded (errorcode 0 + expected port) or cancelled
	// (any other outcome).
	KadUdpFwResultStatus OnProbeResult(DWORD ipHost, bool succeeded, bool cancelled, DWORD now)
	{
		KadUdpFwUsedClient* slot = FindUsed(ipHost);
		if (slot == nullptr)
			return KadUdpFwResultStatus::Unrequested;
		if (slot->answered)
			return KadUdpFwResultStatus::Duplicate;
		slot->answered = true;
		slot->succeeded = succeeded;

		if (!IsRunning())
			return KadUdpFwResultStatus::NotRunning; // eMule: "its all over already"

		if (m_running > 0)
			--m_running;

		if (cancelled)
			return KadUdpFwResultStatus::Cancelled; // finished count untouched

		++m_finished;
		if (succeeded)
		{
			// One positive result is enough (eMule forces the finished count
			// to the ask cap so no further tests run this round).
			m_state = KadUdpFirewallState::Open;
			m_verified = true;
			m_timedOut = false;
			m_finished = KAD_UDPFW_CLIENTS_TO_ASK;
			m_running = 0;
			m_testStart = 0;
			return KadUdpFwResultStatus::Succeeded;
		}

		if (m_finished >= KAD_UDPFW_CLIENTS_TO_ASK)
		{
			m_state = KadUdpFirewallState::Firewalled;
			m_verified = true;
			m_timedOut = false;
			m_testStart = 0;
			m_lastRecheck = now;
			return KadUdpFwResultStatus::Failed;
		}
		return KadUdpFwResultStatus::Accepted;
	}

	// eMule Disconnected() with KS_FWCHECK_UDP: the probe-request connection
	// dropped after the request was sent — a valid failed test.
	KadUdpFwResultStatus OnProbeClientClosed(DWORD ipHost, DWORD now)
	{
		return OnProbeResult(ipHost, false, false, now);
	}

	// eMule's IsFirewalledUDP timeout: a running test that exceeds MIN2MS(6)
	// while we are TCP-firewalled counts as firewalled (unverified). The
	// verdict is published into the state (eMule's IsFirewalledUDP reports
	// firewalled from that moment); a later real probe result still
	// overrides it. A confirmed firewalled state re-tests on the recheck
	// cadence.
	void OnTimer(DWORD now, bool tcpFirewalled)
	{
		if (m_timedOut && !IsRunning())
			m_timedOut = false;
		if (!m_timedOut && IsRunning() && !IsFirewalled() && tcpFirewalled && m_testStart != 0 && !m_verified && KadTickElapsed(now, m_testStart, KAD_UDPFW_TEST_TIMEOUT_MS))
		{
			m_timedOut = true;
			m_state = KadUdpFirewallState::Firewalled;
		}
		if (!IsRunning() && IsFirewalled() && m_lastRecheck != 0 && KadTickElapsed(now, m_lastRecheck, KAD_UDPFW_RECHECK_MS))
		{
			ReCheck(now, false);
		}
	}

	DWORD TestStart() const { return m_testStart; }
	size_t RunningCount() const { return m_running; }
	size_t FinishedCount() const { return m_finished; }
	size_t UsedCount() const
	{
		size_t n = 0;
		for (size_t i = 0; i < KAD_UDPFW_MAX_USED_CLIENTS; ++i)
		{
			if (m_used[i].occupied)
				++n;
		}
		return n;
	}

private:
	struct KadUdpFwUsedClient
	{
		DWORD ipHost = 0;
		DWORD requestedAt = 0;
		bool answered = false;
		bool succeeded = false;
		bool occupied = false;
	};

	KadUdpFwUsedClient m_used[KAD_UDPFW_MAX_USED_CLIENTS];
	KadUdpFirewallState m_state;
	bool m_verified;
	bool m_timedOut;
	bool m_lastState;
	DWORD m_testStart;
	DWORD m_lastRecheck;
	DWORD m_round = 0; // defined before Reset(); Reset()/ReCheck() bump it
	size_t m_running;
	size_t m_finished;

	void ClearUsed()
	{
		for (size_t i = 0; i < KAD_UDPFW_MAX_USED_CLIENTS; ++i)
			m_used[i] = KadUdpFwUsedClient{};
	}

	KadUdpFwUsedClient* FindUsed(DWORD ipHost)
	{
		for (size_t i = 0; i < KAD_UDPFW_MAX_USED_CLIENTS; ++i)
		{
			if (m_used[i].occupied && m_used[i].ipHost == ipHost)
				return &m_used[i];
		}
		return nullptr;
	}

	KadUdpFwUsedClient* FreeUsedSlot()
	{
		for (size_t i = 0; i < KAD_UDPFW_MAX_USED_CLIENTS; ++i)
		{
			if (!m_used[i].occupied)
				return &m_used[i];
		}
		return nullptr;
	}

	KadUdpFwUsedClient* OldestUsedSlot()
	{
		KadUdpFwUsedClient* oldest = nullptr;
		for (size_t i = 0; i < KAD_UDPFW_MAX_USED_CLIENTS; ++i)
		{
			if (!m_used[i].occupied)
				continue;
			if (oldest == nullptr || m_used[i].requestedAt < oldest->requestedAt)
				oldest = &m_used[i];
		}
		return oldest;
	}
};
