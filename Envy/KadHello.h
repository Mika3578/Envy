//
// KadHello.h
//
// Kad2 HELLO wire layout and inbound request flood limiter, free of MFC and
// networking so the byte layout and the limits can be tested natively.
//
// HELLO_REQ and HELLO_RES carry the same body in eMule and aMule
// (SendMyDetails / AddContact_KADEMLIA2):
//   <SenderKadID 16><TCPPort 2><Version 1><TagCount 1><Tag>*
// where each tag is <Type 1><NameLength 2><Name><Value>. TAG_SOURCEUPORT (0xFC)
// carries the sender's internal UDP port and TAG_KADMISCOPTIONS (0xF2) its firewall
// state. There is no fixed UDP port field.
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
	uint16_t udpPort = 0;    // 0 when no valid TAG_SOURCEUPORT was sent
	uint8_t miscOptions = 0; // TAG_KADMISCOPTIONS, 0 when absent
	size_t consumed = 0;     // bytes read; any trailing bytes are ignored as in the references

	bool UdpFirewalled() const { return (miscOptions & 0x01) != 0; }
	bool TcpFirewalled() const { return (miscOptions & 0x02) != 0; }
	// Bit 2 only means something in a HELLO_RES from a Kad version 8 or newer sender.
	bool RequestsAck() const { return (miscOptions & 0x04) != 0 && version >= 8; }
};

constexpr size_t KadHelloFixedBytes = 16 + 2 + 1 + 1;
constexpr uint8_t KadHelloTagSourceUdpPort = 0xFC;
constexpr uint8_t KadHelloTagMiscOptions = 0xF2;

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

namespace KadHelloDetail
{
// Reads an unsigned integer tag value; false for a non-integer type.
inline bool IntValue(uint8_t type, const uint8_t* v, uint64_t& out)
{
	size_t width = 0;
	switch (type)
	{
	case 0x09: width = 1; break; // UINT8
	case 0x08: width = 2; break; // UINT16
	case 0x03: width = 4; break; // UINT32
	case 0x0b: width = 8; break; // UINT64
	default: return false;
	}
	out = 0;
	for (size_t i = 0; i < width; ++i)
		out |= static_cast<uint64_t>(v[i]) << (8 * i);
	return true;
}
} // namespace KadHelloDetail

// Parses a HELLO body in the eMule/aMule layout. The union of the two readers is accepted:
// HASH16, STRING, UINT8/16/32/64, FLOAT32, BOOL, BLOB (32-bit length), BSOB (8-bit length),
// STR1..STR16 and the compact form (type | 0x80, one-byte name). A tag of any other type
// (including BOOLARRAY, whose size the references compute differently), a length that runs past
// the body, version 0, or two valid but different values for the same tag fail the whole
// parse, as the references abort on a tag they cannot delimit. Bytes after the last declared tag
// are ignored; hello.consumed tells how many were read.
inline bool KadParseHello(const uint8_t* p, size_t n, KadHello& out)
{
	if (p == nullptr || n < KadHelloFixedBytes)
		return false;
	KadHello hello;
	memcpy(hello.id, p, 16);
	hello.tcpPort = static_cast<uint16_t>(p[16] | (p[17] << 8));
	hello.version = p[18];
	if (hello.version == 0)
		return false;
	size_t pos = KadHelloFixedBytes;
	bool haveUdp = false, haveMisc = false;
	for (unsigned tags = p[19]; tags > 0; --tags)
	{
		if (n - pos < 1)
			return false;
		uint8_t type = p[pos++];
		uint8_t shortName = 0;
		size_t nameLen = 1;
		if ((type & 0x80) != 0)
		{
			type &= 0x7f;
			if (n - pos < 1)
				return false;
			shortName = p[pos++];
		}
		else
		{
			if (n - pos < 2)
				return false;
			nameLen = static_cast<size_t>(p[pos] | (p[pos + 1] << 8));
			pos += 2;
			if (n - pos < nameLen)
				return false;
			if (nameLen == 1)
				shortName = p[pos];
			pos += nameLen;
		}
		const bool oneByteName = nameLen == 1;

		size_t valueLen = 0;
		switch (type)
		{
		case 0x01: valueLen = 16; break; // HASH16
		case 0x03:
		case 0x04: valueLen = 4; break; // UINT32, FLOAT32
		case 0x05:
		case 0x09: valueLen = 1; break; // BOOL, UINT8
		case 0x08: valueLen = 2; break; // UINT16
		case 0x0b: valueLen = 8; break; // UINT64
		case 0x02:                      // STRING: <len 2><bytes>
			if (n - pos < 2)
				return false;
			valueLen = 2 + static_cast<size_t>(p[pos] | (p[pos + 1] << 8));
			break;
		case 0x07: // BLOB: <len 4><bytes>
		{
			if (n - pos < 4)
				return false;
			const uint64_t len = static_cast<uint64_t>(p[pos]) | (static_cast<uint64_t>(p[pos + 1]) << 8) |
			                     (static_cast<uint64_t>(p[pos + 2]) << 16) | (static_cast<uint64_t>(p[pos + 3]) << 24);
			if (len > n - pos - 4)
				return false;
			valueLen = 4 + static_cast<size_t>(len);
			break;
		}
		case 0x0a: // BSOB: <len 1><bytes>
			if (n - pos < 1)
				return false;
			valueLen = 1 + static_cast<size_t>(p[pos]);
			break;
		default:
			if (type >= 0x11 && type <= 0x20) // STR1..STR16, length in the type
				valueLen = static_cast<size_t>(type - 0x10);
			else
				return false;
			break;
		}
		if (n - pos < valueLen)
			return false;

		uint64_t value = 0;
		if (oneByteName && KadHelloDetail::IntValue(type, p + pos, value))
		{
			if (shortName == KadHelloTagSourceUdpPort)
			{
				// Zero is ignored as in the references; a value that does not fit 16 bits is not a port.
				if (value > 0 && value <= 0xffff)
				{
					if (haveUdp && hello.udpPort != value)
						return false;
					hello.udpPort = static_cast<uint16_t>(value);
					haveUdp = true;
				}
			}
			else if (shortName == KadHelloTagMiscOptions)
			{
				if (value > 0 && value <= 0xff)
				{
					if (haveMisc && hello.miscOptions != value)
						return false;
					hello.miscOptions = static_cast<uint8_t>(value);
					haveMisc = true;
				}
			}
		}
		pos += valueLen;
	}
	hello.consumed = pos;
	out = hello;
	return true;
}

// Runs a send whose reply may arrive before it returns: the request is registered first and
// withdrawn again if the send did not go out. Returns whether the send succeeded.
template<class Register, class Cancel, class Send>
inline bool KadSendRegistered(Register&& doRegister, Cancel&& doCancel, Send&& doSend)
{
	const auto handle = doRegister();
	if (doSend())
		return true;
	doCancel(handle);
	return false;
}

// UDP port to store for a contact: the advertised internal port when the HELLO carried one,
// otherwise the port the datagram came from. The contact's IP is always the datagram source,
// so an advertised port can only redirect traffic to another port of the same host.
inline uint16_t KadHelloContactUdpPort(const KadHello& hello, uint16_t observedPort)
{
	return hello.udpPort != 0 ? hello.udpPort : observedPort;
}

// The references never add (or update) a contact that reports itself UDP firewalled.
inline bool KadHelloMayEnterRoutingTable(const KadHello& hello)
{
	return !hello.UdpFirewalled();
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
