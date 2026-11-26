//
// KadBuddy.h
//
// Kad2 buddy / callback helpers (#516): FINDBUDDY and CALLBACK UDP wire
// framing plus the bounded buddy-bond session state. Pure helpers shared by
// CKademlia/CEDClient and EnvyTests. No MFC windows, no sockets.
//
// Wire reference (eMule Community, irwir/eMule master @ 88a8c8f):
//   opcodes.h:607  KADEMLIA_FINDBUDDY_REQ  0x51  <TCPPORT (sender) [2]>
//   opcodes.h:608  KADEMLIA_CALLBACK_REQ   0x52  <TCPPORT (sender) [2]>
//   opcodes.h:613  KADEMLIA_FINDBUDDY_RES  0x5A  <TCPPORT (sender) [2]>
//   (the opcode comments only name the trailing port; the full layouts are in
//   the handlers below)
//
//   KademliaUDPListener.cpp Process_KADEMLIA_FINDBUDDY_REQ (min 34 bytes):
//     <BuddyID 16><ClientHash 16><TCPPort 2>
//     Guards: refuse when we are TCP-firewalled, UDP-firewalled, or the UDP
//     tester is not verified; refuse when we already have a buddy.
//   Process_KADEMLIA_FINDBUDDY_RES (min 34 bytes): first field must equal the
//     requester's own KadID XOR 0xFF..FF (ClientList.cpp starts the FINDBUDDY
//     lookup with CUInt128(true).Xor(GetKadID()) and the listener echoes the
//     request's first field back); len > 34 adds the responder's
//     ConnectOptions byte (0.49a+; older clients ignore the extra byte).
//   Process_KADEMLIA_CALLBACK_REQ (min 34 bytes): <KadCheck 16><FileHash 16>
//     <TCPPort 2>. Only a node that currently buddies for someone relays it:
//     the 38-byte TCP OP_CALLBACK (0x99) body
//     <KadCheck 16><FileHash 16><sender IP 4><TCPPort 2> goes to the bonded
//     firewalled client, which then connects out to the requester
//     (ListenSocket.cpp OP_CALLBACK validates KadCheck XOR 0xFF..FF against
//     its own KadID - Envy already handles that inbound in CEDClient).
//   Outbound CALLBACK_REQ (BaseClient.cpp TryToConnect, CCS_KADCALLBACK):
//     <BuddyID 16 = target's KadID XOR ones><FileHash 16><our TCPPort 2>,
//     sent by UDP to the target's buddy endpoint.
//   PacketTracking.cpp: FINDBUDDY_REQ/CALLBACK_REQ answers are only accepted
//     within 180 s of the tracked outbound request; inbound flood limits are
//     FINDBUDDY_REQ 2/min and CALLBACK_REQ 1/min per IP.
//   Buddy ping/pong (updownclient.h): OP_BUDDYPING (0x9F) / OP_BUDDYPONG
//     (0xA0) are empty C2C packets; a bonded client pings every 10 min and
//     accepts an inbound ping only after a 3-minute gap, each side stamping
//     the exchange to keep the buddy socket alive.
//
// Envy notes:
//   - The buddy bond is a single bounded slot (eMule keeps one m_pBuddy too).
//     A node either buddies FOR a firewalled client (it answered FINDBUDDY_REQ
//     and the requester connected out) or USES a buddy (it is firewalled and
//     connected out after a FINDBUDDY_RES).
//   - eMule drives FINDBUDDY through a Kad lookup for ownKadID XOR ones and
//     creates fresh client connections; Envy sends FINDBUDDY_REQ to verified
//     routing contacts and reuses the client pool. Wire formats are unchanged.
//   - Source types 3/5/6 stay refused in KadSearchResDelivery until the
//     download-side callback consumer exists; this slice delivers the buddy
//     protocol layer it will ride on.
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//

#pragma once

#include <windows.h>
#include "KadFirewallCheck.h"
#include "Ed2kLowIdCallback.h"

// KADEMLIA_FINDBUDDY_REQ / KADEMLIA_CALLBACK_REQ / KADEMLIA_FINDBUDDY_RES
// (eMule opcodes.h:607/608/613).
constexpr BYTE KAD_OP_FINDBUDDY_REQ = 0x51;
constexpr BYTE KAD_OP_CALLBACK_REQ = 0x52;
constexpr BYTE KAD_OP_FINDBUDDY_RES = 0x5A;

constexpr size_t KAD_BUDDY_REQ_MIN_SIZE = 34; // 16 + 16 + 2
constexpr size_t KAD_BUDDY_RES_MIN_SIZE = 34; // + optional ConnectOptions
constexpr size_t KAD_BUDDY_RES_WITH_OPTIONS = 35;
constexpr size_t KAD_CALLBACK_RELAY_SIZE = 38; // OP_CALLBACK body (Ed2kC2cCallbackExactBytes)

// eMule PacketTracking.cpp: outbound request tracking window.
constexpr DWORD KAD_BUDDY_OUT_TRACK_TTL_MS = 180000;
// Bounded out-track history (eMule list is unbounded; Envy discipline caps).
constexpr size_t KAD_BUDDY_TRACK_MAX = 16;
// eMule InTrackListIsAllowedPacket flood limits.
constexpr unsigned KAD_BUDDY_FINDBUDDY_PER_MINUTE = 2;
constexpr unsigned KAD_BUDDY_CALLBACK_PER_MINUTE = 1;
// eMule buddy ping/pong cadence (updownclient.h).
constexpr DWORD KAD_BUDDY_PING_INTERVAL_MS = 10 * 60 * 1000;
constexpr DWORD KAD_BUDDY_PING_INBOUND_GAP_MS = 3 * 60 * 1000;
// eMule ClientList.cpp: buddy search re-armed at most every MIN2S(20).
constexpr DWORD KAD_BUDDY_SEARCH_RETRY_MS = 20 * 60 * 1000;
// FINDBUDDY_REQ recipients per round (bounded subset of eMule's
// SEARCHFINDBUDDY_TOTAL = 10 answers; eMule sends to every answering contact).
constexpr size_t KAD_BUDDY_REQ_CONTACTS_PER_ROUND = 4;
// Envy retains a queued OP_CALLBACK relay briefly so a buddy that is still
// connecting (it dialed out seconds after our FINDBUDDY_RES) can still
// receive it; eMule relays immediately and drops when the buddy socket is
// absent. The requester's own callback wait times out regardless.
constexpr DWORD KAD_BUDDY_RELAY_RETAIN_MS = 30000;

enum class KadBuddyParseStatus : BYTE
{
	Ok = 0,
	WrongSize
};

struct KadFindBuddyReq
{
	BYTE buddyId[KAD_ID_SIZE]{};    // requester's KadID XOR 0xFF..FF
	BYTE clientHash[KAD_ID_SIZE]{}; // requester's user hash
	WORD tcpPort = 0;
};

struct KadFindBuddyRes
{
	BYTE buddyId[KAD_ID_SIZE]{};    // echo of the request's BuddyID
	BYTE clientHash[KAD_ID_SIZE]{}; // responder's user hash
	WORD tcpPort = 0;
	BYTE connectOptions = 0;
	bool hasConnectOptions = false;
};

struct KadCallbackReq
{
	BYTE kadCheck[KAD_ID_SIZE]{}; // target's buddy ID (KadID XOR 0xFF..FF)
	BYTE fileHash[KAD_ID_SIZE]{};
	WORD tcpPort = 0;
};

inline KadBuddyParseStatus KadParseFindBuddyReq(const BYTE* data, size_t len, KadFindBuddyReq& out)
{
	out = KadFindBuddyReq{};
	if (data == nullptr || len < KAD_BUDDY_REQ_MIN_SIZE)
		return KadBuddyParseStatus::WrongSize;
	memcpy(out.buddyId, data, KAD_ID_SIZE);
	memcpy(out.clientHash, data + KAD_ID_SIZE, KAD_ID_SIZE);
	out.tcpPort = KadReadU16LE(data + 2 * KAD_ID_SIZE);
	// eMule performs no port-zero rejection here; a broken contact simply
	// never completes a TCP connect.
	return KadBuddyParseStatus::Ok;
}

inline void KadBuildFindBuddyReq(BYTE* out34, const BYTE* ownKadIdXored16, const BYTE* clientHash16, WORD tcpPort)
{
	if (out34 == nullptr || ownKadIdXored16 == nullptr || clientHash16 == nullptr)
		return;
	memcpy(out34, ownKadIdXored16, KAD_ID_SIZE);
	memcpy(out34 + KAD_ID_SIZE, clientHash16, KAD_ID_SIZE);
	KadWriteU16LE(out34 + 2 * KAD_ID_SIZE, tcpPort);
}

inline KadBuddyParseStatus KadParseFindBuddyRes(const BYTE* data, size_t len, KadFindBuddyRes& out)
{
	out = KadFindBuddyRes{};
	if (data == nullptr || len < KAD_BUDDY_RES_MIN_SIZE)
		return KadBuddyParseStatus::WrongSize;
	memcpy(out.buddyId, data, KAD_ID_SIZE);
	memcpy(out.clientHash, data + KAD_ID_SIZE, KAD_ID_SIZE);
	out.tcpPort = KadReadU16LE(data + 2 * KAD_ID_SIZE);
	if (len > KAD_BUDDY_RES_MIN_SIZE)
	{
		out.connectOptions = data[KAD_BUDDY_RES_MIN_SIZE];
		out.hasConnectOptions = true;
	}
	return KadBuddyParseStatus::Ok;
}

inline void KadBuildFindBuddyRes(BYTE* out35, const BYTE* buddyId16, const BYTE* clientHash16,
                                 WORD tcpPort, BYTE connectOptions)
{
	if (out35 == nullptr || buddyId16 == nullptr || clientHash16 == nullptr)
		return;
	memcpy(out35, buddyId16, KAD_ID_SIZE);
	memcpy(out35 + KAD_ID_SIZE, clientHash16, KAD_ID_SIZE);
	KadWriteU16LE(out35 + 2 * KAD_ID_SIZE, tcpPort);
	out35[KAD_BUDDY_RES_MIN_SIZE] = connectOptions;
}

inline KadBuddyParseStatus KadParseCallbackReq(const BYTE* data, size_t len, KadCallbackReq& out)
{
	out = KadCallbackReq{};
	if (data == nullptr || len < KAD_BUDDY_REQ_MIN_SIZE)
		return KadBuddyParseStatus::WrongSize;
	memcpy(out.kadCheck, data, KAD_ID_SIZE);
	memcpy(out.fileHash, data + KAD_ID_SIZE, KAD_ID_SIZE);
	out.tcpPort = KadReadU16LE(data + 2 * KAD_ID_SIZE);
	return KadBuddyParseStatus::Ok;
}

// Outbound CALLBACK_REQ body (BaseClient.cpp CCS_KADCALLBACK): the target's
// buddy ID, the file we need the callback for, and our TCP port.
inline void KadBuildCallbackReq(BYTE* out34, const BYTE* buddyId16, const BYTE* fileHash16, WORD tcpPort)
{
	if (out34 == nullptr || buddyId16 == nullptr || fileHash16 == nullptr)
		return;
	memcpy(out34, buddyId16, KAD_ID_SIZE);
	memcpy(out34 + KAD_ID_SIZE, fileHash16, KAD_ID_SIZE);
	KadWriteU16LE(out34 + 2 * KAD_ID_SIZE, tcpPort);
}

// TCP OP_CALLBACK (0x99) relay body carried to the bonded firewalled client.
// The receiving side validates via Ed2kC2cCallbackParse (38 bytes).
inline void KadBuildCallbackRelay(BYTE* out38, const BYTE* kadCheck16, const BYTE* fileHash16,
                                  DWORD senderIpHost, WORD senderTcpPort)
{
	if (out38 == nullptr || kadCheck16 == nullptr || fileHash16 == nullptr)
		return;
	memcpy(out38, kadCheck16, KAD_ID_SIZE);
	memcpy(out38 + KAD_ID_SIZE, fileHash16, KAD_ID_SIZE);
	KadWriteU32LE(out38 + 2 * KAD_ID_SIZE, senderIpHost);
	KadWriteU16LE(out38 + 2 * KAD_ID_SIZE + 4, senderTcpPort);
}

// BuddyID check shared by FINDBUDDY_RES echo validation and OP_CALLBACK
// validation: value XOR 0xFF..FF must equal the expected Kad ID.
inline bool KadBuddyIdMatchesKadId(const BYTE* pValue16, const BYTE* pOwnKadId16)
{
	if (pValue16 == nullptr || pOwnKadId16 == nullptr)
		return false;
	BYTE tmp[KAD_ID_SIZE];
	memcpy(tmp, pValue16, KAD_ID_SIZE);
	for (int i = 0; i < KAD_ID_SIZE; ++i)
		tmp[i] = static_cast<BYTE>(tmp[i] ^ 0xFF);
	return memcmp(tmp, pOwnKadId16, KAD_ID_SIZE) == 0;
}

// XOR our Kad ID into the buddy-ID form used on the wire.
inline void KadKadIdToBuddyId(const BYTE* pOwnKadId16, BYTE* pOut16)
{
	if (pOwnKadId16 == nullptr || pOut16 == nullptr)
		return;
	for (int i = 0; i < KAD_ID_SIZE; ++i)
		pOut16[i] = static_cast<BYTE>(pOwnKadId16[i] ^ 0xFF);
}

// Buddy ping/pong cadence (eMule updownclient.h): a bonded client pings when
// the previous exchange is older than 10 minutes; an inbound ping is answered
// only after a 3-minute gap so a hostile buddy cannot be ping-flooded.
inline bool KadBuddyPingDue(DWORD lastPingPongAt, DWORD now)
{
	return lastPingPongAt == 0 || KadTickElapsed(now, lastPingPongAt, KAD_BUDDY_PING_INTERVAL_MS);
}

inline bool KadBuddyInboundPingAllowed(DWORD lastPingPongAt, DWORD now)
{
	return lastPingPongAt == 0 || KadTickElapsed(now, lastPingPongAt, KAD_BUDDY_PING_INBOUND_GAP_MS);
}

enum class KadBuddyAcceptStatus : BYTE
{
	Accept = 0,
	Firewalled, // TCP firewalled or UDP firewalled/unverified
	HaveBuddy,  // the single buddy slot is taken
	InvalidSource,
	AlreadyIncoming // same requester already recorded
};

enum class KadBuddyCandidateStatus : BYTE
{
	Accepted = 0,
	Unrequested,  // no outstanding FINDBUDDY_REQ to this IP
	Stale,        // out-track entry older than 180 s
	EchoMismatch, // BuddyID echo does not match our KadID
	HaveBuddy
};

enum class KadBuddyRelayStatus : BYTE
{
	Relay = 0,
	NoBuddy, // no connected bonded firewalled client
	InvalidSource
};

struct KadBuddyRecord
{
	DWORD ipHost = 0;
	WORD tcpPort = 0;
	WORD udpPort = 0;
	BYTE clientHash[KAD_ID_SIZE]{};
	BYTE buddyId[KAD_ID_SIZE]{};
	BYTE connectOptions = 0;
	bool hasConnectOptions = false;
	bool connected = false;
	DWORD connectedAt = 0;
};

// Bounded buddy-bond session (single slot, eMule m_pBuddy semantics).
class KadBuddySession
{
public:
	KadBuddySession()
	{
		Reset();
	}

	void Reset()
	{
		m_buddy = KadBuddyRecord{};
		m_buddyConnected = false;
		m_searchArmedAt = 0;
		ClearTrack();
	}

	// ---- Open-node side: answer FINDBUDDY_REQ ----

	// eMule Process_KADEMLIA_FINDBUDDY_REQ guards. Firewall facts come from
	// the caller (m_firewall / m_udpFirewall); this records the incoming
	// buddy candidate and owns the single-slot + duplicate decisions.
	KadBuddyAcceptStatus AcceptFindBuddyRequest(
	    DWORD ipHost, WORD sourceUdpPort, const KadFindBuddyReq& req,
	    bool tcpFirewalled, bool udpFirewalledOrUnverified, DWORD ourPublicIpHost)
	{
		if (tcpFirewalled || udpFirewalledOrUnverified)
			return KadBuddyAcceptStatus::Firewalled;
		if (ipHost == 0 || ipHost == ourPublicIpHost)
			return KadBuddyAcceptStatus::InvalidSource;
		if (m_buddyConnected)
			return KadBuddyAcceptStatus::HaveBuddy;
		if (m_buddy.ipHost == ipHost)
			return KadBuddyAcceptStatus::AlreadyIncoming;

		// A pending (not yet connected) incoming candidate is replaced by a
		// newer request - the bounded analog of eMule keeping several
		// KS_INCOMING_BUDDY clients where the first to connect wins.
		m_buddy = KadBuddyRecord{};
		m_buddy.ipHost = ipHost;
		m_buddy.udpPort = sourceUdpPort;
		m_buddy.tcpPort = req.tcpPort;
		memcpy(m_buddy.clientHash, req.clientHash, KAD_ID_SIZE);
		memcpy(m_buddy.buddyId, req.buddyId, KAD_ID_SIZE);
		return KadBuddyAcceptStatus::Accept;
	}

	// ---- Firewalled-node side: seek and bind a buddy ----

	// Arm the buddy search (eMule ClientList.cpp GetFindBuddy / SetFindBuddy:
	// re-armed at most every 20 minutes while firewalled without a buddy).
	bool WantsBuddySearch(DWORD now, bool tcpFirewalled, bool udpFirewalled) const
	{
		if (!tcpFirewalled || !udpFirewalled)
			return false;
		if (m_buddyConnected)
			return false;
		return m_searchArmedAt == 0 || KadTickElapsed(now, m_searchArmedAt, KAD_BUDDY_SEARCH_RETRY_MS);
	}

	void NoteBuddySearchRound(DWORD now)
	{
		m_searchArmedAt = now;
	}

	// eMule PacketTracking::AddTrackedOutPacket (FINDBUDDY_REQ is tracked;
	// only answers within 180 s are accepted).
	bool BeginFindBuddyRequest(DWORD ipHost, DWORD now)
	{
		if (ipHost == 0 || HasOutstandingFindBuddyRequest(ipHost, now))
			return false;
		ExpireTrack(now);
		KadBuddyTrack* slot = FreeTrackSlot();
		if (slot == nullptr)
		{
			slot = OldestTrackSlot();
			if (slot == nullptr)
				return false;
		}
		*slot = KadBuddyTrack{};
		slot->ipHost = ipHost;
		slot->sentAt = now;
		slot->occupied = true;
		return true;
	}

	bool HasOutstandingFindBuddyRequest(DWORD ipHost, DWORD now) const
	{
		return FindFreshTrack(ipHost, now) != nullptr;
	}

	// eMule Process_KADEMLIA_FINDBUDDY_RES: the tracked FINDBUDDY_REQ is
	// consumed by the FIRST response from that IP (IsOnOutTrackList removes
	// on match, before the echo check), so a duplicate or forged response
	// cannot be accepted again within the 180 s window.
	KadBuddyCandidateStatus OnFindBuddyResponse(
	    DWORD ipHost, const KadFindBuddyRes& res, const BYTE* pOwnKadId16, DWORD now)
	{
		if (pOwnKadId16 == nullptr)
			return KadBuddyCandidateStatus::EchoMismatch;
		KadBuddyTrack* slot = FindFreshTrack(ipHost, now);
		if (slot == nullptr)
			return TrackContains(ipHost) ? KadBuddyCandidateStatus::Stale
			                             : KadBuddyCandidateStatus::Unrequested;
		// eMule consumes the tracked request before validating the echo.
		*slot = KadBuddyTrack{};
		if (!KadBuddyIdMatchesKadId(res.buddyId, pOwnKadId16))
			return KadBuddyCandidateStatus::EchoMismatch;
		if (m_buddyConnected)
			return KadBuddyCandidateStatus::HaveBuddy;

		m_buddy = KadBuddyRecord{};
		m_buddy.ipHost = ipHost;
		m_buddy.tcpPort = res.tcpPort;
		memcpy(m_buddy.clientHash, res.clientHash, KAD_ID_SIZE);
		memcpy(m_buddy.buddyId, res.buddyId, KAD_ID_SIZE);
		m_buddy.connectOptions = res.connectOptions;
		m_buddy.hasConnectOptions = res.hasConnectOptions;
		// Our own buddy: we connect out (eMule RequestBuddy -> client connect).
		return KadBuddyCandidateStatus::Accepted;
	}

	// The buddy TCP connection (outgoing or incoming) came up.
	void OnBuddyConnected(DWORD ipHost, DWORD now)
	{
		if (m_buddy.ipHost != ipHost)
			return;
		m_buddyConnected = true;
		m_buddy.connected = true;
		m_buddy.connectedAt = now;
	}

	void OnBuddyDisconnected()
	{
		m_buddy = KadBuddyRecord{};
		m_buddyConnected = false;
	}

	bool HasBuddyRecord() const
	{
		return m_buddy.ipHost != 0;
	}

	bool HasConnectedBuddy() const
	{
		return m_buddyConnected;
	}

	const KadBuddyRecord& Buddy() const
	{
		return m_buddy;
	}

	// ---- CALLBACK relay (we buddy FOR a firewalled client) ----

	// eMule Process_KADEMLIA_CALLBACK_REQ: only a node with a connected
	// bonded firewalled client relays. The relay body carries the UDP source
	// address of the requester, never an IP from the payload. Flood limiting
	// is the caller's inbound limiter (eMule: CALLBACK_REQ 1/min per IP).
	KadBuddyRelayStatus OnCallbackRequest(
	    DWORD senderIpHost, const KadCallbackReq& req, BYTE* outRelay38)
	{
		if (senderIpHost == 0)
			return KadBuddyRelayStatus::InvalidSource;
		if (!m_buddyConnected)
			return KadBuddyRelayStatus::NoBuddy;
		if (outRelay38 != nullptr)
			KadBuildCallbackRelay(outRelay38, req.kadCheck, req.fileHash, senderIpHost, req.tcpPort);
		return KadBuddyRelayStatus::Relay;
	}

	// ---- Ping/pong ----
	// eMule keeps the ping/pong cadence on the client object
	// (m_dwLastBuddyPingPongTime); KadBuddyPingDue / KadBuddyInboundPingAllowed
	// above are the pure forms the bonded CEDClient uses.

	size_t TrackCount() const
	{
		size_t n = 0;
		for (size_t i = 0; i < KAD_BUDDY_TRACK_MAX; ++i)
		{
			if (m_track[i].occupied)
				++n;
		}
		return n;
	}

private:
	struct KadBuddyTrack
	{
		DWORD ipHost = 0;
		DWORD sentAt = 0;
		bool occupied = false;
	};

	KadBuddyTrack m_track[KAD_BUDDY_TRACK_MAX];
	KadBuddyRecord m_buddy;
	bool m_buddyConnected;
	DWORD m_searchArmedAt;

	void ClearTrack()
	{
		for (size_t i = 0; i < KAD_BUDDY_TRACK_MAX; ++i)
			m_track[i] = KadBuddyTrack{};
	}

	bool TrackContains(DWORD ipHost) const
	{
		for (size_t i = 0; i < KAD_BUDDY_TRACK_MAX; ++i)
		{
			if (m_track[i].occupied && m_track[i].ipHost == ipHost)
				return true;
		}
		return false;
	}

	void ExpireTrack(DWORD now)
	{
		for (size_t i = 0; i < KAD_BUDDY_TRACK_MAX; ++i)
		{
			if (m_track[i].occupied && KadTickElapsed(now, m_track[i].sentAt, KAD_BUDDY_OUT_TRACK_TTL_MS))
				m_track[i] = KadBuddyTrack{};
		}
	}

	KadBuddyTrack* FindFreshTrack(DWORD ipHost, DWORD now)
	{
		for (size_t i = 0; i < KAD_BUDDY_TRACK_MAX; ++i)
		{
			if (m_track[i].occupied && m_track[i].ipHost == ipHost && !KadTickElapsed(now, m_track[i].sentAt, KAD_BUDDY_OUT_TRACK_TTL_MS))
				return &m_track[i];
		}
		return nullptr;
	}

	const KadBuddyTrack* FindFreshTrack(DWORD ipHost, DWORD now) const
	{
		for (size_t i = 0; i < KAD_BUDDY_TRACK_MAX; ++i)
		{
			if (m_track[i].occupied && m_track[i].ipHost == ipHost && !KadTickElapsed(now, m_track[i].sentAt, KAD_BUDDY_OUT_TRACK_TTL_MS))
				return &m_track[i];
		}
		return nullptr;
	}

	KadBuddyTrack* FreeTrackSlot()
	{
		for (size_t i = 0; i < KAD_BUDDY_TRACK_MAX; ++i)
		{
			if (!m_track[i].occupied)
				return &m_track[i];
		}
		return nullptr;
	}

	KadBuddyTrack* OldestTrackSlot()
	{
		KadBuddyTrack* oldest = nullptr;
		for (size_t i = 0; i < KAD_BUDDY_TRACK_MAX; ++i)
		{
			if (!m_track[i].occupied)
				continue;
			if (oldest == nullptr || m_track[i].sentAt < oldest->sentAt)
				oldest = &m_track[i];
		}
		return oldest;
	}
};