//
// test_kad_opcodes.cpp
//
// Kad2 UDP opcode wire values and the dispatch classification of every opcode byte.
// Expected values are literals copied from eMule Community opcodes.h and aMule
// src/include/protocol/kad2/Client2Client/UDP.h, never derived from the constants
// under test. Retired, Kad1 and previously misassigned values must stay unknown.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

#include "test_framework.h"
#include "../Envy/KadOpcodes.h"
#include <algorithm>
#include <cstdint>
#include <set>
#include <vector>

namespace
{
struct WireValue
{
	const char* name;
	unsigned actual;
	unsigned expected;
};

const WireValue kWire[] = {
	{ "BOOTSTRAP_REQ", KADEMLIA2_BOOTSTRAP_REQ, 0x01 },
	{ "BOOTSTRAP_RES", KADEMLIA2_BOOTSTRAP_RES, 0x09 },
	{ "HELLO_REQ", KADEMLIA2_HELLO_REQ, 0x11 },
	{ "HELLO_RES", KADEMLIA2_HELLO_RES, 0x19 },
	{ "REQ", KADEMLIA2_REQ, 0x21 },
	{ "HELLO_RES_ACK", KADEMLIA2_HELLO_RES_ACK, 0x22 },
	{ "RES", KADEMLIA2_RES, 0x29 },
	{ "SEARCH_KEY_REQ", KADEMLIA2_SEARCH_KEY_REQ, 0x33 },
	{ "SEARCH_SOURCE_REQ", KADEMLIA2_SEARCH_SOURCE_REQ, 0x34 },
	{ "SEARCH_NOTES_REQ", KADEMLIA2_SEARCH_NOTES_REQ, 0x35 },
	{ "SEARCH_RES", KADEMLIA2_SEARCH_RES, 0x3B },
	{ "PUBLISH_KEY_REQ", KADEMLIA2_PUBLISH_KEY_REQ, 0x43 },
	{ "PUBLISH_SOURCE_REQ", KADEMLIA2_PUBLISH_SOURCE_REQ, 0x44 },
	{ "PUBLISH_NOTES_REQ", KADEMLIA2_PUBLISH_NOTES_REQ, 0x45 },
	{ "PUBLISH_RES", KADEMLIA2_PUBLISH_RES, 0x4B },
	{ "PUBLISH_RES_ACK", KADEMLIA2_PUBLISH_RES_ACK, 0x4C },
	{ "FIREWALLED_REQ", KADEMLIA2_FIREWALLED_REQ, 0x50 },
	{ "FIREWALLED2_REQ", KADEMLIA_FIREWALLED2_REQ, 0x53 },
	{ "FIREWALLED_RES", KADEMLIA2_FIREWALLED_RES, 0x58 },
	{ "FIREWALLED_ACK_RES", KADEMLIA2_FIREWALLED_ACK_RES, 0x59 },
	{ "PING", KADEMLIA2_PING, 0x60 },
	{ "PONG", KADEMLIA2_PONG, 0x61 },
};

// Opcodes CKademlia::OnPacket hands to a handler.
const std::set<unsigned> kDispatched = { 0x01, 0x09, 0x11, 0x19, 0x21, 0x29, 0x33, 0x34,
	                                     0x3B, 0x50, 0x53, 0x58, 0x59, 0x60, 0x61 };
// Standard opcodes dropped before any handler: PUBLISH is not implemented and
// Envy holds no UDP keys to answer or verify a HELLO_RES_ACK.
const std::set<unsigned> kUnsupported = { 0x22, 0x35, 0x43, 0x44, 0x45, 0x4B, 0x4C };

KadUdpOpcodeDisposition Of(unsigned opcode)
{
	return KadUdpOpcodeDispositionOf(static_cast<std::uint8_t>(opcode));
}

bool test_kad_opcode_wire_values()
{
	for (const WireValue& v : kWire)
	{
		if (v.actual != v.expected)
		{
			std::cerr << "KADEMLIA2_" << v.name << " = 0x" << std::hex << v.actual << ", expected 0x"
			          << v.expected << std::dec << "\n";
			return false;
		}
	}
	// Request type values carried inside KADEMLIA2_REQ, not opcodes.
	return KADEMLIA_FIND_VALUE == 0x02 && KADEMLIA_FIND_NODE == 0x0B;
}

bool test_kad_opcode_values_do_not_collide()
{
	std::set<unsigned> seen;
	for (const WireValue& v : kWire)
	{
		if (!seen.insert(v.actual).second)
		{
			std::cerr << "Kad2 opcode collision on KADEMLIA2_" << v.name << "\n";
			return false;
		}
	}
	return seen.size() == sizeof(kWire) / sizeof(kWire[0]);
}

bool test_kad_opcode_dispatch_covers_every_byte()
{
	for (unsigned opcode = 0; opcode <= 0xFF; ++opcode)
	{
		KadUdpOpcodeDisposition expected = KadUdpOpcodeDisposition::Unknown;
		if (kDispatched.count(opcode))
			expected = KadUdpOpcodeDisposition::Dispatched;
		else if (kUnsupported.count(opcode))
			expected = KadUdpOpcodeDisposition::Unsupported;
		if (Of(opcode) != expected)
		{
			std::cerr << "Kad2 opcode 0x" << std::hex << opcode << std::dec << " misclassified\n";
			return false;
		}
	}
	return true;
}

// Values Envy used to send or accept for PUBLISH/ACK, the invented ACK aliases
// and the Kad1/retired opcodes from the references must never reach a handler.
bool test_kad_opcode_retired_and_old_values_stay_unknown()
{
	const unsigned retired[] = {
		0x41, 0x42, 0x49, 0x4A, // old Envy PUBLISH values; 0x41/0x49 retired, 0x42/0x4A Kad1
		0x12, 0x1A, 0x2A, 0x3C, // old Envy ACK aliases without a reference opcode
		0x00, 0x08, 0x10, 0x18, 0x20, 0x28, 0x30, 0x31, 0x32, 0x38, 0x39, 0x3A, 0x40,
		0x48, 0x51, 0x52, 0x5A, // Kad1 / retired reference opcodes
		0x62,                     // standard opcode without a handler in Envy
	};
	return std::all_of(std::begin(retired), std::end(retired),
	                   [](unsigned opcode)
	                   { return Of(opcode) == KadUdpOpcodeDisposition::Unknown; });
}

// The drop happens on the opcode byte alone, so empty, truncated and oversized
// bodies of an unsupported opcode are all rejected the same way.
bool test_kad_opcode_publish_never_dispatched()
{
	const unsigned publish[] = { KADEMLIA2_PUBLISH_KEY_REQ, KADEMLIA2_PUBLISH_SOURCE_REQ,
		                         KADEMLIA2_PUBLISH_NOTES_REQ, KADEMLIA2_PUBLISH_RES,
		                         KADEMLIA2_PUBLISH_RES_ACK, KADEMLIA2_HELLO_RES_ACK };
	return std::all_of(std::begin(publish), std::end(publish),
	                   [](unsigned opcode)
	                   { return Of(opcode) == KadUdpOpcodeDisposition::Unsupported; });
}

static_assert(KadUdpOpcodeDispositionOf(KADEMLIA2_SEARCH_SOURCE_REQ) == KadUdpOpcodeDisposition::Dispatched,
              "SEARCH_SOURCE_REQ must stay dispatched");
static_assert(KadUdpOpcodeDispositionOf(KADEMLIA2_PUBLISH_KEY_REQ) == KadUdpOpcodeDisposition::Unsupported,
              "PUBLISH_KEY_REQ must be dropped unparsed");
} // namespace

void register_kad_opcodes_tests(TestSuite& suite)
{
	suite.add_test("kad_opcode_wire_values", test_kad_opcode_wire_values);
	suite.add_test("kad_opcode_values_do_not_collide", test_kad_opcode_values_do_not_collide);
	suite.add_test("kad_opcode_dispatch_covers_every_byte", test_kad_opcode_dispatch_covers_every_byte);
	suite.add_test("kad_opcode_retired_and_old_values_stay_unknown",
	               test_kad_opcode_retired_and_old_values_stay_unknown);
	suite.add_test("kad_opcode_publish_never_dispatched", test_kad_opcode_publish_never_dispatched);
}
