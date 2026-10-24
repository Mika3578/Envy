//
// test_kad_hello.cpp
//
// Kad2 HELLO wire layout, tag handling, two-byte request gate and inbound request limiter.
// Synthetic data only. The "golden" vectors are derived by hand from the serializers of
// eMule Community v0.72a (CKademliaUDPListener::SendMyDetails) and amule-org/amule master
// (CKademliaUDPListener::SendMyDetails, AddContact2); they are not captures of live peers.
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
// SPDX-License-Identifier: AGPL-3.0-or-later
//

#include "test_framework.h"
#include "../Envy/KadHello.h"
#include <algorithm>
#include <vector>

namespace
{
const uint8_t kId[16] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };

std::vector<uint8_t> Body(uint8_t tagCount, std::vector<uint8_t> tags, uint8_t version = 8)
{
	std::vector<uint8_t> b(kId, kId + 16);
	b.insert(b.end(), { 0x36, 0x12, version, tagCount }); // TCP 0x1236
	b.insert(b.end(), tags.begin(), tags.end());
	return b;
}

// TAG_SOURCEUPORT as eMule writes it: type UINT16, name length 1, name 0xFC, value 4672.
const std::vector<uint8_t> kUdpTag = { 0x08, 0x01, 0x00, 0xFC, 0x40, 0x12 };
// TAG_KADMISCOPTIONS as eMule writes it: type UINT8, name 0xF2.
std::vector<uint8_t> MiscTag(uint8_t v) { return { 0x09, 0x01, 0x00, 0xF2, v }; }

std::vector<uint8_t> Cat(std::vector<uint8_t> a, const std::vector<uint8_t>& b)
{
	a.insert(a.end(), b.begin(), b.end());
	return a;
}

bool Parse(const std::vector<uint8_t>& b, KadHello& h) { return KadParseHello(b.data(), b.size(), h); }

bool test_write_matches_reference_layout()
{
	uint8_t out[32] = {};
	if (KadWriteHello(out, sizeof(out), kId, 0x1236, 8) != 20 || KadWriteHello(out, 19, kId, 1, 8) != 0)
		return false;
	const auto expected = Body(0, {});
	return std::equal(expected.begin(), expected.end(), out);
}

// eMule SendMyDetails, not firewalled, internal port sent: <ID><TCP><Version 0x0A><1><SOURCEUPORT>.
bool test_golden_emule_hello_request()
{
	const auto v = Body(1, kUdpTag, 0x0A);
	if (v.size() != 26)
		return false;
	KadHello h;
	return Parse(v, h) && h.version == 0x0A && h.tcpPort == 0x1236 && h.udpPort == 4672 && h.miscOptions == 0 &&
	       h.consumed == v.size() && memcmp(h.id, kId, 16) == 0;
}

// eMule SendMyDetails with the firewall tag: UDP firewalled (bit 0) and requesting HELLO_RES_ACK (bit 2).
bool test_golden_emule_hello_res_with_misc_options()
{
	const auto v = Body(2, Cat(kUdpTag, MiscTag(0x05)), 0x0A);
	KadHello h;
	if (!Parse(v, h) || h.miscOptions != 0x05 || !h.UdpFirewalled() || h.TcpFirewalled() || !h.RequestsAck() || h.udpPort != 4672)
		return false;
	// The request-ACK bit is meaningless below Kad version 8.
	const auto old = Body(1, MiscTag(0x04), 7);
	return Parse(old, h) && !h.RequestsAck() && !h.UdpFirewalled();
}

bool test_udp_port_value_widths_and_limits()
{
	KadHello h;
	// aMule writes the smallest integer width that holds the value.
	if (!Parse(Body(1, { 0x09, 0x01, 0x00, 0xFC, 80 }), h) || h.udpPort != 80)
		return false;
	if (!Parse(Body(1, { 0x03, 0x01, 0x00, 0xFC, 0x40, 0x12, 0, 0 }), h) || h.udpPort != 4672)
		return false;
	if (!Parse(Body(1, { 0x0b, 0x01, 0x00, 0xFC, 0x40, 0x12, 0, 0, 0, 0, 0, 0 }), h) || h.udpPort != 4672)
		return false;
	// Zero and out-of-range values are ignored, not truncated; the contact keeps the observed port.
	if (!Parse(Body(1, { 0x08, 0x01, 0x00, 0xFC, 0, 0 }), h) || h.udpPort != 0)
		return false;
	if (!Parse(Body(1, { 0x03, 0x01, 0x00, 0xFC, 0x40, 0x12, 1, 0 }), h) || h.udpPort != 0)
		return false;
	// A string under the same name is not a port.
	if (!Parse(Body(1, { 0x11, 0x01, 0x00, 0xFC, 'x' }), h) || h.udpPort != 0)
		return false;
	// A multi-byte name equal to 0xFC in its first byte is another tag.
	if (!Parse(Body(1, { 0x08, 0x02, 0x00, 0xFC, 0x00, 0x40, 0x12 }), h) || h.udpPort != 0)
		return false;
	return KadHelloContactUdpPort(h, 7000) == 7000;
}

bool test_compact_tag_form()
{
	// aMule's CTag reader also accepts type | 0x80 with a one-byte name.
	KadHello h;
	return Parse(Body(1, { 0x88, 0xFC, 0x40, 0x12 }), h) && h.udpPort == 4672 && h.consumed == 20 + 4;
}

bool test_blob_bsob_and_other_values_are_delimited()
{
	KadHello h;
	// BLOB (32-bit length), BSOB (8-bit length), STRING, STR3, HASH16, FLOAT32, BOOL, then the port.
	std::vector<uint8_t> tags;
	tags = Cat(tags, { 0x07, 0x01, 0x00, 0x41, 3, 0, 0, 0, 'a', 'b', 'c' });
	tags = Cat(tags, { 0x0a, 0x01, 0x00, 0x42, 2, 'x', 'y' });
	tags = Cat(tags, { 0x02, 0x01, 0x00, 0x43, 2, 0, 'h', 'i' });
	tags = Cat(tags, { 0x13, 0x01, 0x00, 0x44, 'a', 'b', 'c' });
	tags = Cat(tags, { 0x01, 0x01, 0x00, 0x45, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 });
	tags = Cat(tags, { 0x04, 0x01, 0x00, 0x46, 0, 0, 0x80, 0x3f });
	tags = Cat(tags, { 0x05, 0x01, 0x00, 0x47, 1 });
	tags = Cat(tags, kUdpTag);
	const auto v = Body(8, tags);
	return Parse(v, h) && h.udpPort == 4672 && h.consumed == v.size();
}

bool test_malformed_tags_fail_the_whole_hello()
{
	KadHello h;
	// BLOB length larger than the body, including a 32-bit value that would wrap a size_t sum.
	if (Parse(Body(1, { 0x07, 0x01, 0x00, 0x41, 0xff, 0xff, 0xff, 0xff, 'a' }), h))
		return false;
	if (Parse(Body(1, { 0x07, 0x01, 0x00, 0x41, 5, 0, 0, 0, 'a', 'b' }), h))
		return false;
	// BSOB and STRING lengths running past the end.
	if (Parse(Body(1, { 0x0a, 0x01, 0x00, 0x42, 9, 'x' }), h) || Parse(Body(1, { 0x02, 0x01, 0x00, 0x43, 0xff, 0xff }), h))
		return false;
	// Name length running past the end.
	if (Parse(Body(1, { 0x08, 0xff, 0xff, 0xfc }), h))
		return false;
	// Unknown types and BOOLARRAY cannot be delimited the same way by both references.
	for (uint8_t type : { 0x00, 0x06, 0x0c, 0x10, 0x21, 0x7e })
		if (Parse(Body(2, Cat({ type, 0x01, 0x00, 0x01, 0x00 }, kUdpTag)), h))
			return false;
	// Declared tag count larger than the tags present.
	if (Parse(Body(3, kUdpTag), h))
		return false;
	// Version 0 is invalid, a null buffer is refused.
	return !Parse(Body(0, {}, 0), h) && !KadParseHello(nullptr, 20, h);
}

bool test_truncation_sweep()
{
	KadHello h;
	const auto ok = Body(2, Cat(kUdpTag, MiscTag(1)), 0x0A);
	for (size_t n = 0; n < ok.size(); ++n)
		if (KadParseHello(ok.data(), n, h))
			return false;
	return KadParseHello(ok.data(), ok.size(), h);
}

bool test_old_envy_layout_is_not_accepted_as_valid_tags()
{
	// Previous layout: 16-byte ID, TCP, version, UDP port (2), no tag count. Its
	// low UDP byte lands where eMule reads the tag count and must not parse.
	std::vector<uint8_t> legacy(kId, kId + 16);
	legacy.insert(legacy.end(), { 0x36, 0x12, 8, 0x40, 0x12 });
	KadHello h;
	return !Parse(legacy, h);
}

bool test_duplicate_and_contradictory_tags()
{
	KadHello h;
	// Identical duplicates are harmless; different valid values are ambiguous and refused.
	if (!Parse(Body(2, Cat(kUdpTag, kUdpTag)), h) || h.udpPort != 4672)
		return false;
	if (Parse(Body(2, Cat(kUdpTag, { 0x08, 0x01, 0x00, 0xFC, 0x41, 0x12 })), h))
		return false;
	if (Parse(Body(2, Cat(MiscTag(1), MiscTag(2))), h))
		return false;
	// A zero (ignored) value next to a valid one is not a contradiction.
	return Parse(Body(2, Cat({ 0x08, 0x01, 0x00, 0xFC, 0, 0 }, kUdpTag)), h) && h.udpPort == 4672;
}

bool test_trailing_bytes_and_cursor()
{
	KadHello h;
	const auto base = Body(1, kUdpTag);
	auto trailing = base;
	trailing.insert(trailing.end(), { 0xde, 0xad, 0xbe, 0xef });
	return Parse(trailing, h) && h.consumed == base.size() && h.udpPort == 4672;
}

bool test_routing_admission_policy()
{
	KadHello h;
	if (!Parse(Body(1, MiscTag(0x01)), h) || KadHelloMayEnterRoutingTable(h))
		return false;
	// TCP-firewalled only and the request-ACK bit do not keep a contact out.
	if (!Parse(Body(1, MiscTag(0x06)), h) || !KadHelloMayEnterRoutingTable(h))
		return false;
	// No options tag at all: admitted.
	KadHello plain;
	return Parse(Body(0, {}), plain) && KadHelloMayEnterRoutingTable(plain);
}

bool test_register_before_send_and_cancel_on_failure()
{
	std::vector<int> log;
	int cancelled = -1;
	// Success: registered first, never cancelled.
	bool ok = KadSendRegistered([&]
	                            { log.push_back(1); return 42; }, [&](int h)
	                            { cancelled = h; log.push_back(3); },
	                            [&]
	                            { log.push_back(2); return true; });
	if (!ok || cancelled != -1 || log != std::vector<int>({ 1, 2 }))
		return false;
	// Send failure: the same handle that was registered is withdrawn after the attempt.
	log.clear();
	ok = KadSendRegistered([&]
	                       { log.push_back(1); return 43; }, [&](int h)
	                       { cancelled = h; log.push_back(3); },
	                       [&]
	                       { log.push_back(2); return false; });
	return !ok && cancelled == 43 && log == std::vector<int>({ 1, 2, 3 });
}

bool test_parser_never_overreads_on_random_input()
{
	// Deterministic pseudo-random bodies with a valid header; run under sanitizers in CI-less checks.
	uint32_t state = 0x1234567u;
	auto next = [&]
	{ state = state * 1664525u + 1013904223u; return static_cast<uint8_t>(state >> 24); };
	for (int round = 0; round < 20000; ++round)
	{
		std::vector<uint8_t> b(kId, kId + 16);
		b.insert(b.end(), { 0x36, 0x12, 8, next() });
		const size_t extra = next() % 48;
		for (size_t i = 0; i < extra; ++i)
			b.push_back(next());
		std::vector<uint8_t> exact(b); // exact-size heap copy so sanitizers see any over-read
		KadHello h;
		if (KadParseHello(exact.data(), exact.size(), h) && h.consumed > exact.size())
			return false;
	}
	return true;
}

bool test_limiter_burst_then_refill()
{
	KadInboundLimiter lim;
	const uint32_t ip = 0xc0000201u;
	if (!lim.Allow(ip, 1, 2, 0) || !lim.Allow(ip, 1, 2, 1) || lim.Allow(ip, 1, 2, 2))
		return false;
	// Refused packets do not deepen the debt: half a minute after the burst one passes.
	for (uint64_t t = 3; t < 30000; t += 997)
		if (lim.Allow(ip, 1, 2, t))
			return false;
	if (!lim.Allow(ip, 1, 2, 30002) || lim.Allow(ip, 1, 2, 30003))
		return false;
	// Another IP and another opcode have their own bucket.
	return lim.Allow(ip + 1, 1, 2, 5) && lim.Allow(ip, 2, 2, 5);
}

bool test_limiter_bounded_and_clock_safe()
{
	KadInboundLimiter lim;
	for (uint32_t i = 0; i < KadInboundLimiter::MaxTrackedIps; ++i)
		if (!lim.Allow(0xc6336400u + i, 1, 2, 1000))
			return false;
	// Full of fresh entries: a new source is refused, not tracked.
	if (lim.Allow(0xcb007100u, 1, 2, 1001) || lim.Tracked() != KadInboundLimiter::MaxTrackedIps)
		return false;
	// Once idle entries age out the table accepts new sources again.
	if (!lim.Allow(0xcb007100u, 1, 2, 1000 + KadInboundLimiter::BucketMs))
		return false;
	// 64-bit time far beyond 2^32 ms must not break refill.
	KadInboundLimiter l2;
	const uint64_t base = (uint64_t{ 1 } << 33);
	return l2.Allow(5, 1, 2, base) && l2.Allow(5, 1, 2, base) && !l2.Allow(5, 1, 2, base) &&
	       l2.Allow(5, 1, 2, base + 60000) && !l2.Allow(5, 1, 0, base);
}
bool test_limiter_clock_regression_and_boundaries()
{
	// Equal timestamps: no refill, no wrap.
	KadInboundLimiter a;
	if (!a.Allow(7, 1, 2, 1000) || !a.Allow(7, 1, 2, 1000) || a.Allow(7, 1, 2, 1000))
		return false;
	// A smaller timestamp must not wrap the unsigned difference into a full refill.
	if (a.Allow(7, 1, 2, 999) || a.Allow(7, 1, 2, 0))
		return false;
	// The stamp did not move back: a full bucket after one minute from the original stamp.
	if (!a.Allow(7, 1, 2, 1000 + KadInboundLimiter::BucketMs))
		return false;
	// Pruning keeps an entry stamped in the future and drops one exactly a bucket old.
	KadInboundLimiter b;
	b.Allow(1, 1, 2, 5000);
	b.Allow(2, 1, 2, 100);
	b.Prune(100 + KadInboundLimiter::BucketMs - 1);
	if (b.Tracked() != 2)
		return false;
	b.Prune(100 + KadInboundLimiter::BucketMs);
	if (b.Tracked() != 1)
		return false;
	b.Prune(0);
	return b.Tracked() == 1;
}

bool test_bodyless_request_gate()
{
	const uint8_t bootstrap[] = { 0xE4, 0x01 }, ping[] = { 0xE4, 0x60 };
	if (!KadIsBodylessRequest(bootstrap, 2) || !KadIsBodylessRequest(ping, 2))
		return false;
	// Any other Kad opcode, including ones that reach a larger reply or the ED2K server-result path.
	for (unsigned op = 0; op < 256; ++op)
	{
		const uint8_t d[] = { 0xE4, static_cast<uint8_t>(op) };
		if (KadIsBodylessRequest(d, 2) != (op == 0x01 || op == 0x60))
			return false;
	}
	// Every other protocol byte (eDonkey, eMule, packed Kad, RevConnect, Gnutella...) at two bytes.
	for (unsigned proto = 0; proto < 256; ++proto)
		for (unsigned op : { 0x01u, 0x60u, 0x99u, 0x9Bu })
		{
			const uint8_t d[] = { static_cast<uint8_t>(proto), static_cast<uint8_t>(op) };
			if (proto != 0xE4 && KadIsBodylessRequest(d, 2))
				return false;
		}
	// Only exactly two bytes; null and other lengths are refused.
	const uint8_t longer[] = { 0xE4, 0x01, 0x00 };
	return !KadIsBodylessRequest(bootstrap, 1) && !KadIsBodylessRequest(bootstrap, 0) &&
	       !KadIsBodylessRequest(longer, 3) && !KadIsBodylessRequest(nullptr, 2);
}

bool test_write_failure_leaves_buffer_untouched()
{
	uint8_t out[24];
	memset(out, 0xAB, sizeof(out));
	if (KadWriteHello(out, KadHelloFixedBytes - 1, kId, 1, 8) != 0 || KadWriteHello(out, 0, kId, 1, 8) != 0 ||
	    KadWriteHello(out, sizeof(out), nullptr, 1, 8) != 0 || KadWriteHello(nullptr, sizeof(out), kId, 1, 8) != 0)
		return false;
	for (uint8_t b : out)
		if (b != 0xAB)
			return false;
	return true;
}
} // namespace

void register_kad_hello_tests(TestSuite& suite)
{
	suite.add_test("kad_hello_write_layout", test_write_matches_reference_layout);
	suite.add_test("kad_hello_golden_emule_request", test_golden_emule_hello_request);
	suite.add_test("kad_hello_golden_emule_response_misc", test_golden_emule_hello_res_with_misc_options);
	suite.add_test("kad_hello_udp_port_widths_and_limits", test_udp_port_value_widths_and_limits);
	suite.add_test("kad_hello_compact_tag_form", test_compact_tag_form);
	suite.add_test("kad_hello_blob_bsob_delimited", test_blob_bsob_and_other_values_are_delimited);
	suite.add_test("kad_hello_malformed_tags_fail", test_malformed_tags_fail_the_whole_hello);
	suite.add_test("kad_hello_truncation_sweep", test_truncation_sweep);
	suite.add_test("kad_hello_rejects_old_envy_layout", test_old_envy_layout_is_not_accepted_as_valid_tags);
	suite.add_test("kad_hello_duplicate_contradictory_tags", test_duplicate_and_contradictory_tags);
	suite.add_test("kad_hello_trailing_bytes_cursor", test_trailing_bytes_and_cursor);
	suite.add_test("kad_hello_routing_admission", test_routing_admission_policy);
	suite.add_test("kad_hello_register_before_send", test_register_before_send_and_cancel_on_failure);
	suite.add_test("kad_hello_random_input_bounded", test_parser_never_overreads_on_random_input);
	suite.add_test("kad_inbound_limiter_burst_refill", test_limiter_burst_then_refill);
	suite.add_test("kad_inbound_limiter_bounded", test_limiter_bounded_and_clock_safe);
	suite.add_test("kad_inbound_limiter_clock_regression", test_limiter_clock_regression_and_boundaries);
	suite.add_test("kad_bodyless_request_gate", test_bodyless_request_gate);
	suite.add_test("kad_hello_write_failure_untouched", test_write_failure_leaves_buffer_untouched);
}
