//
// KadFirewallCheck.h
//
// Kad2 TCP firewall-detection baseline (#86 phase 1).
// Pure helpers shared by CKademlia and EnvyTests. No MFC windows, no sockets.
//
// Wire reference (eMule Community / aMule KademliaUDPListener):
//   KADEMLIA_FIREWALLED_REQ  (0x50): exact 2 bytes, little-endian TCP port
//   KADEMLIA_FIREWALLED_RES  (0x58): exact 4 bytes, little-endian IPv4
//                                    (observer's view of the requester)
//   KADEMLIA_FIREWALLED_ACK_RES (0x59): exact 0 bytes; Kad < 7 UDP ACK
//   KADEMLIA_FIREWALLED2_REQ (0x53): min 19 bytes for Kad version > 6
//                                    <TCPPort 2><UserHash 16><ConnectOptions 1>
//
// FIREWALLED_RES is public-IP observation, not TCP reachability.
// TCP Open requires two independent ACKs (UDP 0x59 or TCP 0xA8).
// UDP firewall state is intentionally not derived from this path.
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//

#pragma once

#include <windows.h>
#include <cstdint>
#include <cstring>

#ifndef KAD_ID_SIZE
#define KAD_ID_SIZE 16
#endif

// Opcodes (same values as Envy/EDPacket.h Kad1 FIREWALLED_*).
constexpr BYTE KAD_OP_FIREWALLED_REQ = 0x50;
constexpr BYTE KAD_OP_FIREWALLED2_REQ = 0x53;
constexpr BYTE KAD_OP_FIREWALLED_RES = 0x58;
constexpr BYTE KAD_OP_FIREWALLED_ACK_RES = 0x59;

constexpr size_t KAD_FW_REQ_SIZE = 2;
constexpr size_t KAD_FW_RES_SIZE = 4;
constexpr size_t KAD_FW_ACK_SIZE = 0;
constexpr size_t KAD_FW2_REQ_MIN_SIZE = 19;

// eMule opcodes.h KADEMLIAFIREWALLCHECKS — concurrent outbound checks.
constexpr size_t KAD_FW_MAX_OUTSTANDING_CHECKS = 4;
constexpr size_t KAD_FW_MAX_INBOUND_PROBES = 4;
constexpr size_t KAD_FW_MAX_RATE_ENTRIES = 64;
constexpr size_t KAD_FW_MAX_IP_OBSERVATIONS = 8;
constexpr size_t KAD_FW_MAX_CANDIDATES = 16;

constexpr DWORD KAD_FW_CHECK_TTL_MS = 180000; // eMule listFirewallCheckRequests
constexpr DWORD KAD_FW_INBOUND_COOLDOWN_MS = 60000;
constexpr DWORD KAD_FW_RECHECK_MS = 10 * 60 * 1000;
constexpr DWORD KAD_FW_ACKS_FOR_OPEN = 2;
constexpr DWORD KAD_FW_IP_AGREE_FOR_PUBLIC = 2;
constexpr BYTE KAD_FW_FIREWALLED2_MIN_VERSION = 7;

enum class KadTcpFirewallState : BYTE
{
	Unknown = 0,
	Testing = 1,
	Open = 2,
	Firewalled = 3
};

// Distinct from TCP. This slice never promotes UDP to Open/Firewalled.
enum class KadUdpFirewallState : BYTE
{
	Unknown = 0
};

enum class KadFwParseStatus : BYTE
{
	Ok = 0,
	WrongSize,
	PortZero,
	InvalidIp
};

enum class KadFwResStatus : BYTE
{
	Accepted = 0,
	Unsolicited,
	WrongEndpoint,
	Stale,
	Duplicate,
	InvalidPayload,
	InvalidObservedIp
};

enum class KadFwAckStatus : BYTE
{
	Accepted = 0,
	Unsolicited,
	WrongEndpoint,
	Stale,
	Duplicate,
	InvalidPayload
};

enum class KadFwInboundStatus : BYTE
{
	Accept = 0,
	WrongSize,
	PortZero,
	InvalidSource,
	RateLimited,
	ProbeCap,
	DuplicatePortScan
};

struct KadFirewalledReq
{
	WORD tcpPort = 0;
};

struct KadFirewalled2Req
{
	WORD tcpPort = 0;
	BYTE userHash[KAD_ID_SIZE]{};
	BYTE connectOptions = 0;
};

struct KadFirewalledRes
{
	DWORD observedIpHost = 0; // eMule WriteUInt32 host-order IPv4
};

struct KadFwPeerCandidate
{
	DWORD ipHost = 0;
	WORD udpPort = 0;
	WORD tcpPort = 0;
	BYTE version = 0;
	bool verified = false;
	DWORD lastSeen = 0;
};

struct KadFwCheckContext
{
	DWORD ipHost = 0;
	WORD udpPort = 0;
	WORD tcpPort = 0;
	BYTE version = 0;
	DWORD sentAt = 0;
	bool occupied = false;
	bool resConsumed = false;
	bool ackConsumed = false;
};

struct KadFwInboundProbe
{
	DWORD ipHost = 0;
	WORD tcpPort = 0;
	DWORD recordedAt = 0;
	bool occupied = false;
};

struct KadFwInboundReqResult
{
	KadFwInboundStatus status = KadFwInboundStatus::WrongSize;
	WORD tcpPort = 0;
	DWORD observedIpHost = 0;
	bool sendResponse = false;
	bool recordTcpProbe = false; // intent only — not proof of TCP reachability
};

struct KadFwIpObservation
{
	DWORD peerIpHost = 0;
	DWORD observedIpHost = 0;
	bool occupied = false;
};

inline bool KadTickElapsed(DWORD now, DWORD start, DWORD timeoutMs)
{
	return (now - start) >= timeoutMs;
}

inline WORD KadReadU16LE(const BYTE* p)
{
	return static_cast<WORD>(p[0] | (static_cast<WORD>(p[1]) << 8));
}

inline DWORD KadReadU32LE(const BYTE* p)
{
	return static_cast<DWORD>(p[0]) | (static_cast<DWORD>(p[1]) << 8) | (static_cast<DWORD>(p[2]) << 16) | (static_cast<DWORD>(p[3]) << 24);
}

inline void KadWriteU16LE(BYTE* p, WORD v)
{
	p[0] = static_cast<BYTE>(v & 0xFFu);
	p[1] = static_cast<BYTE>((v >> 8) & 0xFFu);
}

inline void KadWriteU32LE(BYTE* p, DWORD v)
{
	p[0] = static_cast<BYTE>(v & 0xFFu);
	p[1] = static_cast<BYTE>((v >> 8) & 0xFFu);
	p[2] = static_cast<BYTE>((v >> 16) & 0xFFu);
	p[3] = static_cast<BYTE>((v >> 24) & 0xFFu);
}

inline BYTE KadIpv4HostOctet(DWORD ipHost, int n)
{
	return static_cast<BYTE>((ipHost >> (8 * (3 - n))) & 0xFFu);
}

inline bool KadIpv4IsUnspecified(DWORD ipHost)
{
	return ipHost == 0;
}

inline bool KadIpv4IsBroadcast(DWORD ipHost)
{
	return ipHost == 0xFFFFFFFFu;
}

inline bool KadIpv4IsLoopback(DWORD ipHost)
{
	return KadIpv4HostOctet(ipHost, 0) == 127;
}

inline bool KadIpv4IsMulticastOrReserved(DWORD ipHost)
{
	return KadIpv4HostOctet(ipHost, 0) >= 224;
}

inline bool KadIpv4IsRfc1918OrLinkLocal(DWORD ipHost)
{
	const BYTE b1 = KadIpv4HostOctet(ipHost, 0);
	const BYTE b2 = KadIpv4HostOctet(ipHost, 1);
	if (b1 == 10)
		return true;
	if (b1 == 172 && b2 >= 16 && b2 <= 31)
		return true;
	if (b1 == 192 && b2 == 168)
		return true;
	if (b1 == 169 && b2 == 254)
		return true;
	return false;
}

// Peers we may send FIREWALLED_REQ to (LAN allowed; loopback/multicast not).
inline bool KadIpv4IsUsableFirewallPeer(DWORD ipHost)
{
	if (KadIpv4IsUnspecified(ipHost) || KadIpv4IsBroadcast(ipHost))
		return false;
	if (KadIpv4IsLoopback(ipHost) || KadIpv4IsMulticastOrReserved(ipHost))
		return false;
	return true;
}

// Authoritative public-IP observations: reject reserved/private.
inline bool KadIpv4IsUsablePublicObservation(DWORD ipHost)
{
	if (!KadIpv4IsUsableFirewallPeer(ipHost))
		return false;
	if (KadIpv4IsRfc1918OrLinkLocal(ipHost))
		return false;
	return true;
}

inline KadFwParseStatus KadParseFirewalledReq(const BYTE* data, size_t len, KadFirewalledReq& out)
{
	out = KadFirewalledReq{};
	if (data == nullptr || len != KAD_FW_REQ_SIZE)
		return KadFwParseStatus::WrongSize;
	out.tcpPort = KadReadU16LE(data);
	if (out.tcpPort == 0)
		return KadFwParseStatus::PortZero;
	return KadFwParseStatus::Ok;
}

inline KadFwParseStatus KadParseFirewalled2Req(const BYTE* data, size_t len, KadFirewalled2Req& out)
{
	out = KadFirewalled2Req{};
	if (data == nullptr || len < KAD_FW2_REQ_MIN_SIZE)
		return KadFwParseStatus::WrongSize;
	out.tcpPort = KadReadU16LE(data);
	memcpy(out.userHash, data + 2, KAD_ID_SIZE);
	out.connectOptions = data[2 + KAD_ID_SIZE];
	if (out.tcpPort == 0)
		return KadFwParseStatus::PortZero;
	return KadFwParseStatus::Ok;
}

inline KadFwParseStatus KadParseFirewalledRes(const BYTE* data, size_t len, KadFirewalledRes& out)
{
	out = KadFirewalledRes{};
	if (data == nullptr || len != KAD_FW_RES_SIZE)
		return KadFwParseStatus::WrongSize;
	out.observedIpHost = KadReadU32LE(data);
	if (!KadIpv4IsUsablePublicObservation(out.observedIpHost))
		return KadFwParseStatus::InvalidIp;
	return KadFwParseStatus::Ok;
}

inline KadFwParseStatus KadParseFirewalledAck(size_t len)
{
	if (len != KAD_FW_ACK_SIZE)
		return KadFwParseStatus::WrongSize;
	return KadFwParseStatus::Ok;
}

inline BYTE KadFirewalledReqOpcodeForVersion(BYTE kadVersion)
{
	// Outbound: send 0x50 to all versions (v7+ still accept it). Do not emit
	// FIREWALLED2_REQ here — connect-options/crypt are out of this slice.
	(void)kadVersion;
	return KAD_OP_FIREWALLED_REQ;
}

// Distinct verified contacts, newest first. Never uses unverified nodes.dat.
inline size_t KadSelectFirewallCheckPeers(
    const KadFwPeerCandidate* in,
    size_t inCount,
    KadFwPeerCandidate* out,
    size_t outMax)
{
	if (in == nullptr || out == nullptr || outMax == 0)
		return 0;

	size_t nOut = 0;
	for (size_t pass = 0; pass < inCount && nOut < outMax; ++pass)
	{
		size_t best = inCount;
		for (size_t i = 0; i < inCount; ++i)
		{
			if (!in[i].verified || in[i].udpPort == 0)
				continue;
			if (!KadIpv4IsUsableFirewallPeer(in[i].ipHost))
				continue;
			bool dup = false;
			for (size_t j = 0; j < nOut; ++j)
			{
				if (out[j].ipHost == in[i].ipHost)
				{
					dup = true;
					break;
				}
			}
			if (dup)
				continue;
			if (best == inCount || in[i].lastSeen > in[best].lastSeen)
				best = i;
		}
		if (best == inCount)
			break;
		out[nOut++] = in[best];
	}
	return nOut;
}

class KadFirewallCheck
{
public:
	KadFirewallCheck()
	{
		Reset(0);
	}

	void Reset(DWORD now)
	{
		m_tcpState = KadTcpFirewallState::Unknown;
		m_udpState = KadUdpFirewallState::Unknown;
		m_publicIpHost = 0;
		m_publicIpLast = 0;
		m_ackCount = 0;
		m_lastRoundFinishedAt = now;
		m_ourTcpPort = 0;
		m_loggedOpen = false;
		ClearChecks();
		ClearProbes();
		ClearRate();
		ClearObservations();
	}

	void OnKadStart(DWORD now, WORD ourTcpPort)
	{
		Reset(now);
		m_ourTcpPort = ourTcpPort;
	}

	void OnKadStop()
	{
		Reset(0);
	}

	void OnNetworkOrPortChange(DWORD now, WORD ourTcpPort)
	{
		Reset(now);
		m_ourTcpPort = ourTcpPort;
	}

	KadTcpFirewallState TcpState() const { return m_tcpState; }
	KadUdpFirewallState UdpState() const { return m_udpState; }
	DWORD PublicIpHost() const { return m_publicIpHost; }
	DWORD AckCount() const { return m_ackCount; }
	size_t OutstandingCount() const { return CountChecks(); }
	size_t InboundProbeCount() const { return CountProbes(); }
	size_t RateEntryCount() const { return CountRate(); }
	size_t ObservationCount() const { return CountObservations(); }
	WORD OurTcpPort() const { return m_ourTcpPort; }

	void SetOurTcpPort(WORD port) { m_ourTcpPort = port; }

	KadFwInboundReqResult OnInboundFirewalledReq(
	    DWORD sourceIpHost,
	    WORD sourceUdpPort,
	    const BYTE* payload,
	    size_t len,
	    DWORD now,
	    bool firewalled2)
	{
		(void)sourceUdpPort;
		KadFwInboundReqResult r;

		if (!KadIpv4IsUsableFirewallPeer(sourceIpHost))
		{
			r.status = KadFwInboundStatus::InvalidSource;
			return r;
		}

		WORD tcpPort = 0;
		if (firewalled2)
		{
			KadFirewalled2Req req;
			const KadFwParseStatus st = KadParseFirewalled2Req(payload, len, req);
			if (st == KadFwParseStatus::WrongSize)
			{
				r.status = KadFwInboundStatus::WrongSize;
				return r;
			}
			if (st == KadFwParseStatus::PortZero)
			{
				r.status = KadFwInboundStatus::PortZero;
				return r;
			}
			tcpPort = req.tcpPort;
		}
		else
		{
			KadFirewalledReq req;
			const KadFwParseStatus st = KadParseFirewalledReq(payload, len, req);
			if (st == KadFwParseStatus::WrongSize)
			{
				r.status = KadFwInboundStatus::WrongSize;
				return r;
			}
			if (st == KadFwParseStatus::PortZero)
			{
				r.status = KadFwInboundStatus::PortZero;
				return r;
			}
			tcpPort = req.tcpPort;
		}

		ExpireInbound(now);

		if (IsRateLimited(sourceIpHost, now))
		{
			r.status = KadFwInboundStatus::RateLimited;
			return r;
		}

		if (HasRecentProbeFrom(sourceIpHost, now))
		{
			r.status = KadFwInboundStatus::DuplicatePortScan;
			return r;
		}

		if (CountProbes() >= KAD_FW_MAX_INBOUND_PROBES)
		{
			r.status = KadFwInboundStatus::ProbeCap;
			return r;
		}

		NoteRate(sourceIpHost, now);
		RecordProbe(sourceIpHost, tcpPort, now);

		r.status = KadFwInboundStatus::Accept;
		r.tcpPort = tcpPort;
		r.observedIpHost = sourceIpHost;
		r.sendResponse = true;
		r.recordTcpProbe = true;
		return r;
	}

	bool BeginOutboundCheck(const KadFwPeerCandidate& peer, DWORD now)
	{
		if (m_ourTcpPort == 0)
			return false;
		if (!peer.verified || peer.udpPort == 0)
			return false;
		if (!KadIpv4IsUsableFirewallPeer(peer.ipHost))
			return false;
		if (FindCheck(peer.ipHost, peer.udpPort) != nullptr)
			return false;
		ExpireChecks(now);
		if (CountChecks() >= KAD_FW_MAX_OUTSTANDING_CHECKS)
			return false;

		KadFwCheckContext* slot = FreeCheckSlot();
		if (slot == nullptr)
			return false;

		*slot = KadFwCheckContext{};
		slot->ipHost = peer.ipHost;
		slot->udpPort = peer.udpPort;
		slot->tcpPort = peer.tcpPort;
		slot->version = peer.version;
		slot->sentAt = now;
		slot->occupied = true;

		if (m_tcpState == KadTcpFirewallState::Firewalled)
		{
			m_ackCount = 0;
			m_loggedOpen = false;
		}
		if (m_tcpState == KadTcpFirewallState::Unknown || m_tcpState == KadTcpFirewallState::Firewalled)
		{
			m_tcpState = KadTcpFirewallState::Testing;
		}
		return true;
	}

	bool HasOutboundCheck(DWORD ipHost, WORD udpPort) const
	{
		return FindCheck(ipHost, udpPort) != nullptr;
	}

	KadFwResStatus OnFirewalledRes(
	    DWORD fromIpHost,
	    WORD fromUdpPort,
	    const BYTE* payload,
	    size_t len,
	    DWORD now)
	{
		KadFirewalledRes parsed;
		const KadFwParseStatus pst = KadParseFirewalledRes(payload, len, parsed);
		if (pst == KadFwParseStatus::WrongSize)
			return KadFwResStatus::InvalidPayload;
		if (pst == KadFwParseStatus::InvalidIp)
			return KadFwResStatus::InvalidObservedIp;

		KadFwCheckContext* ctx = FindCheck(fromIpHost, fromUdpPort);
		if (ctx == nullptr)
			return KadFwResStatus::Unsolicited;
		if (KadTickElapsed(now, ctx->sentAt, KAD_FW_CHECK_TTL_MS))
			return KadFwResStatus::Stale;
		if (ctx->resConsumed)
			return KadFwResStatus::Duplicate;

		ctx->resConsumed = true;
		NoteIpObservation(fromIpHost, parsed.observedIpHost);
		return KadFwResStatus::Accepted;
	}

	KadFwAckStatus OnFirewalledAck(
	    DWORD fromIpHost,
	    WORD fromUdpPort,
	    size_t len,
	    DWORD now)
	{
		if (KadParseFirewalledAck(len) != KadFwParseStatus::Ok)
			return KadFwAckStatus::InvalidPayload;

		KadFwCheckContext* ctx = FindCheck(fromIpHost, fromUdpPort);
		if (ctx == nullptr)
			return KadFwAckStatus::Unsolicited;
		if (KadTickElapsed(now, ctx->sentAt, KAD_FW_CHECK_TTL_MS))
			return KadFwAckStatus::Stale;
		if (ctx->ackConsumed)
			return KadFwAckStatus::Duplicate;

		ctx->ackConsumed = true;
		++m_ackCount;
		if (m_ackCount >= KAD_FW_ACKS_FOR_OPEN)
			m_tcpState = KadTcpFirewallState::Open;
		return KadFwAckStatus::Accepted;
	}

	// TCP OP_KAD_FWTCPCHECK_ACK (0xA8) from an ED2K C2C connection.
	// Matched by peer IPv4 only (TCP port is ours; UDP port may differ).
	KadFwAckStatus OnTcpFirewallCheckAck(DWORD fromIpHost, DWORD now)
	{
		KadFwCheckContext* ctx = FindCheckByIp(fromIpHost);
		if (ctx == nullptr)
			return KadFwAckStatus::Unsolicited;
		if (KadTickElapsed(now, ctx->sentAt, KAD_FW_CHECK_TTL_MS))
			return KadFwAckStatus::Stale;
		if (ctx->ackConsumed)
			return KadFwAckStatus::Duplicate;

		ctx->ackConsumed = true;
		++m_ackCount;
		if (m_ackCount >= KAD_FW_ACKS_FOR_OPEN)
			m_tcpState = KadTcpFirewallState::Open;
		return KadFwAckStatus::Accepted;
	}

	// Expire contexts. Returns true when TCP state changed this tick.
	bool OnTimer(DWORD now)
	{
		const KadTcpFirewallState before = m_tcpState;
		ExpireInbound(now);
		ExpireChecks(now);

		if (m_tcpState == KadTcpFirewallState::Testing && CountChecks() == 0 && m_ackCount < KAD_FW_ACKS_FOR_OPEN)
		{
			m_tcpState = KadTcpFirewallState::Firewalled;
			m_lastRoundFinishedAt = now;
		}
		return m_tcpState != before;
	}

	bool WantsNewOutboundCheck(DWORD now) const
	{
		if (m_ourTcpPort == 0)
			return false;
		if (m_tcpState == KadTcpFirewallState::Open)
			return false;
		if (CountChecks() >= KAD_FW_MAX_OUTSTANDING_CHECKS)
			return false;
		if (m_tcpState == KadTcpFirewallState::Firewalled && !KadTickElapsed(now, m_lastRoundFinishedAt, KAD_FW_RECHECK_MS))
			return false;
		if (m_tcpState == KadTcpFirewallState::Firewalled)
			return true;
		if (m_tcpState == KadTcpFirewallState::Unknown || m_tcpState == KadTcpFirewallState::Testing)
			return true;
		return false;
	}

	bool ShouldLogOpenTransition()
	{
		if (m_tcpState == KadTcpFirewallState::Open && !m_loggedOpen)
		{
			m_loggedOpen = true;
			return true;
		}
		return false;
	}

private:
	KadTcpFirewallState m_tcpState;
	KadUdpFirewallState m_udpState;
	DWORD m_publicIpHost;
	DWORD m_publicIpLast;
	DWORD m_ackCount;
	DWORD m_lastRoundFinishedAt;
	WORD m_ourTcpPort;
	bool m_loggedOpen;
	KadFwCheckContext m_checks[KAD_FW_MAX_OUTSTANDING_CHECKS];
	KadFwInboundProbe m_probes[KAD_FW_MAX_INBOUND_PROBES];
	KadFwIpObservation m_obs[KAD_FW_MAX_IP_OBSERVATIONS];
	DWORD m_rateIp[KAD_FW_MAX_RATE_ENTRIES];
	DWORD m_rateAt[KAD_FW_MAX_RATE_ENTRIES];
	bool m_rateOcc[KAD_FW_MAX_RATE_ENTRIES];

	void ClearChecks()
	{
		for (size_t i = 0; i < KAD_FW_MAX_OUTSTANDING_CHECKS; ++i)
			m_checks[i] = KadFwCheckContext{};
	}

	void ClearProbes()
	{
		for (size_t i = 0; i < KAD_FW_MAX_INBOUND_PROBES; ++i)
			m_probes[i] = KadFwInboundProbe{};
	}

	void ClearObservations()
	{
		for (size_t i = 0; i < KAD_FW_MAX_IP_OBSERVATIONS; ++i)
			m_obs[i] = KadFwIpObservation{};
		m_publicIpHost = 0;
		m_publicIpLast = 0;
	}

	void ClearRate()
	{
		for (size_t i = 0; i < KAD_FW_MAX_RATE_ENTRIES; ++i)
		{
			m_rateIp[i] = 0;
			m_rateAt[i] = 0;
			m_rateOcc[i] = false;
		}
	}

	size_t CountChecks() const
	{
		size_t n = 0;
		for (size_t i = 0; i < KAD_FW_MAX_OUTSTANDING_CHECKS; ++i)
		{
			if (m_checks[i].occupied)
				++n;
		}
		return n;
	}

	size_t CountProbes() const
	{
		size_t n = 0;
		for (size_t i = 0; i < KAD_FW_MAX_INBOUND_PROBES; ++i)
		{
			if (m_probes[i].occupied)
				++n;
		}
		return n;
	}

	size_t CountObservations() const
	{
		size_t n = 0;
		for (size_t i = 0; i < KAD_FW_MAX_IP_OBSERVATIONS; ++i)
		{
			if (m_obs[i].occupied)
				++n;
		}
		return n;
	}

	size_t CountRate() const
	{
		size_t n = 0;
		for (size_t i = 0; i < KAD_FW_MAX_RATE_ENTRIES; ++i)
		{
			if (m_rateOcc[i])
				++n;
		}
		return n;
	}

	KadFwCheckContext* FindCheck(DWORD ipHost, WORD udpPort)
	{
		for (size_t i = 0; i < KAD_FW_MAX_OUTSTANDING_CHECKS; ++i)
		{
			if (m_checks[i].occupied && m_checks[i].ipHost == ipHost && m_checks[i].udpPort == udpPort)
				return &m_checks[i];
		}
		return nullptr;
	}

	const KadFwCheckContext* FindCheck(DWORD ipHost, WORD udpPort) const
	{
		for (size_t i = 0; i < KAD_FW_MAX_OUTSTANDING_CHECKS; ++i)
		{
			if (m_checks[i].occupied && m_checks[i].ipHost == ipHost && m_checks[i].udpPort == udpPort)
				return &m_checks[i];
		}
		return nullptr;
	}

	KadFwCheckContext* FindCheckByIp(DWORD ipHost)
	{
		for (size_t i = 0; i < KAD_FW_MAX_OUTSTANDING_CHECKS; ++i)
		{
			if (m_checks[i].occupied && m_checks[i].ipHost == ipHost)
				return &m_checks[i];
		}
		return nullptr;
	}

	KadFwCheckContext* FreeCheckSlot()
	{
		for (size_t i = 0; i < KAD_FW_MAX_OUTSTANDING_CHECKS; ++i)
		{
			if (!m_checks[i].occupied)
				return &m_checks[i];
		}
		return nullptr;
	}

	void ExpireChecks(DWORD now)
	{
		for (size_t i = 0; i < KAD_FW_MAX_OUTSTANDING_CHECKS; ++i)
		{
			if (!m_checks[i].occupied)
				continue;
			if (KadTickElapsed(now, m_checks[i].sentAt, KAD_FW_CHECK_TTL_MS))
				m_checks[i] = KadFwCheckContext{};
		}
	}

	void ExpireInbound(DWORD now)
	{
		for (size_t i = 0; i < KAD_FW_MAX_INBOUND_PROBES; ++i)
		{
			if (!m_probes[i].occupied)
				continue;
			if (KadTickElapsed(now, m_probes[i].recordedAt, KAD_FW_INBOUND_COOLDOWN_MS))
				m_probes[i] = KadFwInboundProbe{};
		}
		for (size_t i = 0; i < KAD_FW_MAX_RATE_ENTRIES; ++i)
		{
			if (!m_rateOcc[i])
				continue;
			if (KadTickElapsed(now, m_rateAt[i], KAD_FW_INBOUND_COOLDOWN_MS * 2))
			{
				m_rateOcc[i] = false;
				m_rateIp[i] = 0;
				m_rateAt[i] = 0;
			}
		}
	}

	bool HasRecentProbeFrom(DWORD ipHost, DWORD now) const
	{
		for (size_t i = 0; i < KAD_FW_MAX_INBOUND_PROBES; ++i)
		{
			if (m_probes[i].occupied && m_probes[i].ipHost == ipHost && !KadTickElapsed(now, m_probes[i].recordedAt, KAD_FW_INBOUND_COOLDOWN_MS))
				return true;
		}
		return false;
	}

	void RecordProbe(DWORD ipHost, WORD tcpPort, DWORD now)
	{
		for (size_t i = 0; i < KAD_FW_MAX_INBOUND_PROBES; ++i)
		{
			if (!m_probes[i].occupied)
			{
				m_probes[i].ipHost = ipHost;
				m_probes[i].tcpPort = tcpPort;
				m_probes[i].recordedAt = now;
				m_probes[i].occupied = true;
				return;
			}
		}
	}

	bool IsRateLimited(DWORD ipHost, DWORD now) const
	{
		for (size_t i = 0; i < KAD_FW_MAX_RATE_ENTRIES; ++i)
		{
			if (m_rateOcc[i] && m_rateIp[i] == ipHost && !KadTickElapsed(now, m_rateAt[i], KAD_FW_INBOUND_COOLDOWN_MS))
				return true;
		}
		return false;
	}

	void NoteRate(DWORD ipHost, DWORD now)
	{
		for (size_t i = 0; i < KAD_FW_MAX_RATE_ENTRIES; ++i)
		{
			if (m_rateOcc[i] && m_rateIp[i] == ipHost)
			{
				m_rateAt[i] = now;
				return;
			}
		}
		for (size_t i = 0; i < KAD_FW_MAX_RATE_ENTRIES; ++i)
		{
			if (!m_rateOcc[i])
			{
				m_rateOcc[i] = true;
				m_rateIp[i] = ipHost;
				m_rateAt[i] = now;
				return;
			}
		}
		m_rateOcc[0] = true;
		m_rateIp[0] = ipHost;
		m_rateAt[0] = now;
	}

	void NoteIpObservation(DWORD peerIpHost, DWORD observedIpHost)
	{
		for (size_t i = 0; i < KAD_FW_MAX_IP_OBSERVATIONS; ++i)
		{
			if (m_obs[i].occupied && m_obs[i].peerIpHost == peerIpHost)
				return; // one vote per peer
		}

		for (size_t i = 0; i < KAD_FW_MAX_IP_OBSERVATIONS; ++i)
		{
			if (!m_obs[i].occupied)
			{
				m_obs[i].occupied = true;
				m_obs[i].peerIpHost = peerIpHost;
				m_obs[i].observedIpHost = observedIpHost;
				break;
			}
		}

		// eMule SetIPAddress: two consecutive matching values become current.
		// Plus independent-peer consensus before publishing.
		if (m_publicIpLast == observedIpHost && m_publicIpLast != 0)
			m_publicIpHost = observedIpHost;
		else
			m_publicIpLast = observedIpHost;

		DWORD agree = 0;
		for (size_t i = 0; i < KAD_FW_MAX_IP_OBSERVATIONS; ++i)
		{
			if (m_obs[i].occupied && m_obs[i].observedIpHost == observedIpHost)
				++agree;
		}
		if (agree >= KAD_FW_IP_AGREE_FOR_PUBLIC)
			m_publicIpHost = observedIpHost;
	}
};
