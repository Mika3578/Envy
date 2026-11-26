//
// KadOpcodes.h
//
// Kad2 UDP opcodes (protocol byte 0xE4) and how Envy dispatches them.
// Values follow eMule Community opcodes.h and aMule
// src/include/protocol/kad2/Client2Client/UDP.h. No MFC dependency.
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

#pragma once

#include <cstdint>

// <TagList> is <Count 1>[<Tag>]* in Kad2.
#define KADEMLIA2_BOOTSTRAP_REQ 0x01     // <NodeID 16><TagList>
#define KADEMLIA2_BOOTSTRAP_RES 0x09     // <NodeID 16><TagList>[<NodeID 16><IP 4><UDPPort 2><TCPPort 2><TagList>]*
#define KADEMLIA2_HELLO_REQ 0x11         // <NodeID 16><TCPPort 2><Version 1><TagList>
#define KADEMLIA2_HELLO_RES 0x19         // <NodeID 16><TCPPort 2><Version 1><TagList>
#define KADEMLIA2_REQ 0x21               // <Type 1><TargetID 16><ReceiverID 16>
#define KADEMLIA2_HELLO_RES_ACK 0x22     // <NodeID 16><TagList>; not implemented
#define KADEMLIA_FIND_NODE 0x0B          // eMule FIND_NODE search type
#define KADEMLIA2_RES 0x29               // <TargetID 16><Count 1>[<contacts>...]
#define KADEMLIA2_SEARCH_KEY_REQ 0x33    // <FileHash 16><StartPos 8><TagList>
#define KADEMLIA2_SEARCH_SOURCE_REQ 0x34 // <FileHash 16><StartPosition 2 LE><FileSize 8 LE>
#define KADEMLIA2_SEARCH_NOTES_REQ 0x35  // <FileHash 16><StartPos 8><TagList>
#define KADEMLIA2_SEARCH_RES 0x3B        // eMule/aMule: <SenderID 16><TargetID 16><Count 2>[<AnswerID 16><TagList>]*
// PUBLISH is not implemented. Envy neither sends these opcodes nor parses
// their payloads; inbound packets are dropped (KadUdpOpcodeDispositionOf).
#define KADEMLIA2_PUBLISH_KEY_REQ 0x43    // <KeywordHash 16><Count 2>[<FileHash 16><TagList>]*
#define KADEMLIA2_PUBLISH_SOURCE_REQ 0x44 // <FileHash 16><SourceID 16><TagList>
#define KADEMLIA2_PUBLISH_NOTES_REQ 0x45  // <FileHash 16><SourceID 16><TagList>
#define KADEMLIA2_PUBLISH_RES 0x4B        // <TargetHash 16><Load 1>
#define KADEMLIA2_PUBLISH_RES_ACK 0x4C    // (null)
#define KADEMLIA2_FIREWALLED_REQ 0x50     // <TCPPort 2>  (Kad1 opcode, still used by Kad2)
#define KADEMLIA_FIREWALLED2_REQ 0x53     // <TCPPort 2><UserHash 16><ConnectOptions 1> Kad version > 6
#define KADEMLIA2_FIREWALLED_RES 0x58     // <IPv4 4> observed address of the requester
#define KADEMLIA2_FIREWALLED_ACK_RES 0x59 // empty; Kad < 7 UDP ACK (Kad >= 7 uses ED2K_C2C_KAD_FWTCPCHECK_ACK)
#define KADEMLIA2_PING 0x60               // <TagList>
#define KADEMLIA2_PONG 0x61               // <TagList>

// KADEMLIA2_REQ type value (not an opcode)
#define KADEMLIA_FIND_VALUE 0x02 // Search for values/files in DHT

enum class KadUdpOpcodeDisposition
{
	Dispatched,  // CKademlia::OnPacket has a handler for it
	Unsupported, // Standard Kad2 opcode Envy deliberately drops unparsed
	Unknown      // Anything else: standard opcodes without a handler, Kad1, retired values
};

// Must list exactly the opcodes CKademlia::OnPacket switches on, plus the
// standard opcodes it rejects before any handler or state change. Retired
// values (Kad1 0x42/0x4A, unused 0x41/0x49) stay Unknown so packets sent
// with them are never treated as PUBLISH.
constexpr KadUdpOpcodeDisposition KadUdpOpcodeDispositionOf(std::uint8_t nOpcode) noexcept
{
	switch (nOpcode)
	{
	case KADEMLIA2_BOOTSTRAP_REQ:
	case KADEMLIA2_BOOTSTRAP_RES:
	case KADEMLIA2_PING:
	case KADEMLIA2_PONG:
	case KADEMLIA2_REQ:
	case KADEMLIA2_RES:
	case KADEMLIA2_HELLO_REQ:
	case KADEMLIA2_HELLO_RES:
	case KADEMLIA2_SEARCH_KEY_REQ:
	case KADEMLIA2_SEARCH_SOURCE_REQ:
	case KADEMLIA2_SEARCH_RES:
	case KADEMLIA2_FIREWALLED_REQ:
	case KADEMLIA_FIREWALLED2_REQ:
	case KADEMLIA2_FIREWALLED_RES:
	case KADEMLIA2_FIREWALLED_ACK_RES:
		return KadUdpOpcodeDisposition::Dispatched;
	case KADEMLIA2_HELLO_RES_ACK:
	case KADEMLIA2_SEARCH_NOTES_REQ:
	case KADEMLIA2_PUBLISH_KEY_REQ:
	case KADEMLIA2_PUBLISH_SOURCE_REQ:
	case KADEMLIA2_PUBLISH_NOTES_REQ:
	case KADEMLIA2_PUBLISH_RES:
	case KADEMLIA2_PUBLISH_RES_ACK:
		return KadUdpOpcodeDisposition::Unsupported;
	default:
		return KadUdpOpcodeDisposition::Unknown;
	}
}
