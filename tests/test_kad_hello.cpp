//
// test_kad_hello.cpp
//
// Kad2 HELLO wire layout and inbound request limiter, synthetic data only.
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//

#include "test_framework.h"
#include "../Envy/KadHello.h"
#include <vector>

namespace
{
const uint8_t kId[16] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };

std::vector<uint8_t> Body(uint8_t tagCount, std::vector<uint8_t> tags)
{
	std::vector<uint8_t> b(kId, kId + 16);
	b.insert(b.end(), { 0x36, 0x12, 8, tagCount }); // TCP 0x1236, version 8
	b.insert(b.end(), tags.begin(), tags.end());
	return b;
}

// Layout produced by eMule SendMyDetails with TAG_SOURCEUPORT: 3 bytes of tag
// header (type, name length), name 0xFC, then the UINT16 value.
const std::vector<uint8_t> kUdpTag = { 0x08, 0x01, 0x00, 0xFC, 0x40, 0x12 };

bool test_write_matches_reference_layout()
{
	uint8_t out[32] = {};
	if (KadWriteHello(out, sizeof(out), kId, 0x1236, 8) != 20 || KadWriteHello(out, 19, kId, 1, 8) != 0)
		return false;
	const auto expected = Body(0, {});
	return std::equal(expected.begin(), expected.end(), out);
}

bool test_parse_round_trip_and_udp_tag()
{
	KadHello h;
	const auto plain = Body(0, {});
	if (!KadParseHello(plain.data(), plain.size(), h) || h.tcpPort != 0x1236 || h.version != 8 ||
	    h.udpPort != 0 || memcmp(h.id, kId, 16) != 0)
		return false;
	const auto tagged = Body(1, kUdpTag);
	return KadParseHello(tagged.data(), tagged.size(), h) && h.udpPort == 0x1240;
}

bool test_old_envy_layout_is_not_accepted_as_valid_tags()
{
	// Previous layout: 16-byte ID, TCP, version, UDP port (2), no tag count. Its
	// low UDP byte lands where eMule reads the tag count and must not parse.
	std::vector<uint8_t> legacy(kId, kId + 16);
	legacy.insert(legacy.end(), { 0x36, 0x12, 8, 0x40, 0x12 });
	KadHello h;
	return !KadParseHello(legacy.data(), legacy.size(), h);
}

bool test_truncated_and_malformed()
{
	KadHello h;
	const auto ok = Body(1, kUdpTag);
	for (size_t n = 0; n < ok.size(); ++n)
		if (KadParseHello(ok.data(), n, h))
			return false;
	// Declares more tags than bytes carry.
	const auto lying = Body(3, kUdpTag);
	if (KadParseHello(lying.data(), lying.size(), h))
		return false;
	// Name length running past the end, string length running past the end.
	const auto badName = Body(1, { 0x08, 0xff, 0xff, 0xfc });
	const auto badStr = Body(1, { 0x02, 0x01, 0x00, 0x01, 0xff, 0xff });
	return !KadParseHello(badName.data(), badName.size(), h) && !KadParseHello(badStr.data(), badStr.size(), h) &&
	       !KadParseHello(nullptr, 20, h);
}

bool test_unknown_tag_type_keeps_contact_and_other_tags_are_skipped()
{
	KadHello h;
	// A string tag and a UINT8 tag first, then the UDP port; then an unknown type.
	std::vector<uint8_t> tags = { 0x02, 0x01, 0x00, 0x01, 0x02, 0x00, 'h', 'i', 0x09, 0x01, 0x00, 0xf2, 0x05 };
	tags.insert(tags.end(), kUdpTag.begin(), kUdpTag.end());
	tags.insert(tags.end(), { 0x7e, 0x01, 0x00, 0x01, 0x00 });
	const auto b = Body(4, tags);
	return KadParseHello(b.data(), b.size(), h) && h.udpPort == 0x1240 && h.tcpPort == 0x1236;
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
} // namespace

void register_kad_hello_tests(TestSuite& suite)
{
	suite.add_test("kad_hello_write_layout", test_write_matches_reference_layout);
	suite.add_test("kad_hello_parse_and_udp_tag", test_parse_round_trip_and_udp_tag);
	suite.add_test("kad_hello_rejects_old_envy_layout", test_old_envy_layout_is_not_accepted_as_valid_tags);
	suite.add_test("kad_hello_truncated_malformed", test_truncated_and_malformed);
	suite.add_test("kad_hello_unknown_tags", test_unknown_tag_type_keeps_contact_and_other_tags_are_skipped);
	suite.add_test("kad_inbound_limiter_burst_refill", test_limiter_burst_then_refill);
	suite.add_test("kad_inbound_limiter_bounded", test_limiter_bounded_and_clock_safe);
}
