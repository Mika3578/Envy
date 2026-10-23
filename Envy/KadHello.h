//
// KadHello.h
//
// Kad2 HELLO wire layout and inbound request flood limiter, free of MFC and
// networking so the byte layout and the limits can be tested natively.
//
// HELLO_REQ and HELLO_RES carry the same body in eMule and aMule
// (SendMyDetails / AddContact_KADEMLIA2):
//   <SenderKadID 16><TCPPort 2><Version 1><TagCount 1><Tag>*
// where each tag is <Type 1><NameLength 2><Name><Value>. TAG_SOURCEUPORT (0xFC,
// UINT16) carries the sender's internal UDP port when it differs from the
// source port. There is no fixed UDP port field.
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
// SPDX-License-Identifier: AGPL-3.0-or-later
//

#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <map>

struct KadHello
{
	uint8_t id[16] = {};
	uint16_t tcpPort = 0;
	uint8_t version = 0;
	uint16_t udpPort = 0; // 0 when no TAG_SOURCEUPORT was sent
};

constexpr size_t KadHelloFixedBytes = 16 + 2 + 1 + 1;
constexpr uint8_t KadHelloTagSourceUdpPort = 0xFC;

// Kad2 requests that are exactly the two header bytes (protocol, opcode) and draw a reply.
// Both are rate limited on receipt; no other opcode and no other ED2K UDP protocol may use a
// two-byte datagram, so a forged source cannot turn one into a reflected reply.
constexpr uint8_t KadProtocolByte = 0xE4;   // ED2K_PROTOCOL_KAD
constexpr uint8_t KadOpBootstrapReq = 0x01; // KADEMLIA2_BOOTSTRAP_REQ
constexpr uint8_t KadOpPing = 0x60;         // KADEMLIA2_PING

inline bool KadIsBodylessRequest(const uint8_t* p, size_t n)
{
	return p != nullptr && n == 2 && p[0] == KadProtocolByte && (p[1] == KadOpBootstrapReq || p[1] == KadOpPing);
}

// Writes a HELLO body without tags. Returns the byte count, or 0 if cap is too small.
inline size_t KadWriteHello(uint8_t* out, size_t cap, const uint8_t* id, uint16_t tcpPort, uint8_t version)
{
	if (out == nullptr || id == nullptr || cap < KadHelloFixedBytes)
		return 0;
	memcpy(out, id, 16);
	out[16] = static_cast<uint8_t>(tcpPort & 0xff);
	out[17] = static_cast<uint8_t>(tcpPort >> 8);
	out[18] = version;
	out[19] = 0;
	return KadHelloFixedBytes;
}

// Parses a HELLO body. Fails on a short or truncated body. Tags other than the
// UDP port are skipped; a tag of unknown type ends the walk but keeps what was read,
// since a newer peer's tag must not cost it its contact entry.
inline bool KadParseHello(const uint8_t* p, size_t n, KadHello& out)
{
	if (p == nullptr || n < KadHelloFixedBytes)
		return false;
	KadHello hello;
	memcpy(hello.id, p, 16);
	hello.tcpPort = static_cast<uint16_t>(p[16] | (p[17] << 8));
	hello.version = p[18];
	size_t pos = KadHelloFixedBytes;
	for (unsigned tags = p[19]; tags > 0; --tags)
	{
		if (n - pos < 3)
			return false;
		const uint8_t type = p[pos];
		const size_t nameLen = static_cast<size_t>(p[pos + 1] | (p[pos + 2] << 8));
		pos += 3;
		if (n - pos < nameLen)
			return false;
		const uint8_t* name = p + pos;
		pos += nameLen;

		size_t valueLen = 0;
		bool known = true;
		switch (type)
		{
		case 0x01: valueLen = 16; break; // HASH16
		case 0x03:
		case 0x04: valueLen = 4; break; // UINT32, FLOAT32
		case 0x05:
		case 0x09: valueLen = 1; break; // BOOL, UINT8
		case 0x08: valueLen = 2; break; // UINT16
		case 0x0b: valueLen = 8; break; // UINT64
		case 0x02:                      // STRING
			if (n - pos < 2)
				return false;
			valueLen = 2 + static_cast<size_t>(p[pos] | (p[pos + 1] << 8));
			break;
		default:
			if (type >= 0x11 && type <= 0x20) // short string, length in the type
				valueLen = static_cast<size_t>(type - 0x10);
			else
				known = false;
			break;
		}
		if (!known)
			break;
		if (n - pos < valueLen)
			return false;
		if (type == 0x08 && nameLen == 1 && name[0] == KadHelloTagSourceUdpPort)
		{
			const uint16_t port = static_cast<uint16_t>(p[pos] | (p[pos + 1] << 8));
			if (port != 0)
				hello.udpPort = port;
		}
		pos += valueLen;
	}
	out = hello;
	return true;
}

// Per-source-IP and opcode token bucket for inbound requests that trigger a larger reply,
// the scheme eMule and aMule use (CPacketTracking::InTrackListIsAllowedPacket):
// a bucket of one minute of tokens, each packet costing 60 s / perMinute, so a
// peer may burst to perMinute packets and then sustain perMinute per minute.
class KadInboundLimiter
{
public:
	static constexpr size_t MaxTrackedIps = 4096;
	static constexpr int64_t BucketMs = 60000;

	bool Allow(uint32_t ip, uint8_t opcode, unsigned perMinute, uint64_t now)
	{
		const uint64_t key = (static_cast<uint64_t>(ip) << 8) | opcode;
		return AllowKey(key, perMinute, now);
	}

	bool AllowKey(uint64_t key, unsigned perMinute, uint64_t now)
	{
		if (perMinute == 0)
			return false;
		const int64_t cost = BucketMs / static_cast<int64_t>(perMinute);
		auto it = m_state.find(key);
		if (it == m_state.end())
		{
			if (m_state.size() >= MaxTrackedIps)
			{
				Prune(now);
				if (m_state.size() >= MaxTrackedIps)
					return false; // fail closed rather than grow without bound
			}
			m_state.emplace(key, State{ BucketMs - cost, now });
			return true;
		}
		State& s = it->second;
		// A clock that went backwards refills nothing and does not move the stamp back, so a
		// regression can neither wrap the unsigned difference nor grant a free refill.
		const uint64_t elapsed = now > s.latest ? now - s.latest : 0;
		s.tokens = elapsed >= static_cast<uint64_t>(BucketMs) ? BucketMs
		                                                      : (s.tokens + static_cast<int64_t>(elapsed) > BucketMs ? BucketMs : s.tokens + static_cast<int64_t>(elapsed));
		if (now > s.latest)
			s.latest = now;
		if (s.tokens < cost)
			return false; // a refused packet does not deepen the debt
		s.tokens -= cost;
		return true;
	}

	size_t Tracked() const { return m_state.size(); }

	void Prune(uint64_t now)
	{
		for (auto it = m_state.begin(); it != m_state.end();)
		{
			if (now > it->second.latest && now - it->second.latest >= static_cast<uint64_t>(BucketMs))
				it = m_state.erase(it);
			else
				++it;
		}
	}

private:
	struct State
	{
		int64_t tokens;
		uint64_t latest;
	};
	std::map<uint64_t, State> m_state;
};
