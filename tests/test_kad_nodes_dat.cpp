//
// test_kad_nodes_dat.cpp
//
// Deterministic nodes.dat parser tests (v0/v1/v2/v3, truncation, overflow).
// No live network, no MFC, no UDP.
//
// Fixture IPs use TEST-NET-3 (203.0.113.0/24) and spread 203.x.y.z /24s so
// same-subnet caps can be tested without live public addresses.
//
// Layout of the golden v1 record (little-endian integers):
//   marker 00 00 00 00 | version 01 00 00 00 | count 01 00 00 00
//   id 01..10 | IP CB 00 71 05 (203.0.113.5) | UDP 40 12 (4672)
//   TCP 36 12 (4662) | Kad version 08
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//

#ifdef ENVY_KAD_NODES_DAT_STANDALONE
#include <functional>
#include <iostream>
#include <string>
#include <vector>
class TestSuite
{
public:
	void add_test(const std::string& name, std::function<bool()> fn)
	{
		m_names.push_back(name);
		m_fns.push_back(fn);
	}
	int run()
	{
		int failed = 0;
		for (size_t i = 0; i < m_fns.size(); ++i)
		{
			const bool ok = m_fns[i]();
			std::cout << (ok ? "PASS " : "FAIL ") << m_names[i] << "\n";
			if (!ok)
				++failed;
		}
		return failed;
	}

private:
	std::vector<std::string> m_names;
	std::vector<std::function<bool()>> m_fns;
};
#else
#include "test_framework.h"
#endif
#include "../Envy/KadNodesDat.h"

#include <cstdint>
#include <cstring>
#include <vector>

namespace
{

const uint8_t kId1[16] = {
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10
};

void PushU8(std::vector<uint8_t>& o, uint8_t v)
{
	o.push_back(v);
}

void PushU16LE(std::vector<uint8_t>& o, uint16_t v)
{
	o.push_back(static_cast<uint8_t>(v & 0xFF));
	o.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
}

void PushU32LE(std::vector<uint8_t>& o, uint32_t v)
{
	o.push_back(static_cast<uint8_t>(v & 0xFF));
	o.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
	o.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
	o.push_back(static_cast<uint8_t>((v >> 24) & 0xFF));
}

void PushBytes(std::vector<uint8_t>& o, const uint8_t* p, size_t n)
{
	o.insert(o.end(), p, p + n);
}

void PushIp(std::vector<uint8_t>& o, uint8_t a, uint8_t b, uint8_t c, uint8_t d)
{
	PushU8(o, a);
	PushU8(o, b);
	PushU8(o, c);
	PushU8(o, d);
}

void PushId(std::vector<uint8_t>& o, uint8_t nSeed)
{
	uint8_t id[16];
	for (int i = 0; i < 16; ++i)
		id[i] = static_cast<uint8_t>(nSeed + i);
	if (KadNodesDatIdIsZero(id))
		id[0] = 1;
	PushBytes(o, id, 16);
}

void PushV1Contact(
    std::vector<uint8_t>& o,
    uint8_t nSeed,
    uint8_t a, uint8_t b, uint8_t c, uint8_t d,
    uint16_t nUdp, uint16_t nTcp, uint8_t nVer)
{
	PushId(o, nSeed);
	PushIp(o, a, b, c, d);
	PushU16LE(o, nUdp);
	PushU16LE(o, nTcp);
	PushU8(o, nVer);
}

void PushV2Contact(
    std::vector<uint8_t>& o,
    uint8_t nSeed,
    uint8_t a, uint8_t b, uint8_t c, uint8_t d,
    uint16_t nUdp, uint16_t nTcp, uint8_t nVer,
    uint32_t nKey, uint32_t nKeyIp, uint8_t nVerified)
{
	PushV1Contact(o, nSeed, a, b, c, d, nUdp, nTcp, nVer);
	PushU32LE(o, nKey);
	PushU32LE(o, nKeyIp);
	PushU8(o, nVerified);
}

KadNodesDatResult ParseBuf(
    const std::vector<uint8_t>& o,
    KadNodesDatContact* pOut,
    uint32_t nMax,
    const uint8_t* pOwn = nullptr)
{
	return KadNodesDatParse(o.empty() ? nullptr : o.data(), o.size(), pOut, nMax, pOwn);
}

bool ContactIpIs(const KadNodesDatContact& c, uint8_t a, uint8_t b, uint8_t c3, uint8_t d)
{
	return c.ip[0] == a && c.ip[1] == b && c.ip[2] == c3 && c.ip[3] == d;
}

} // namespace

static bool test_count_fits_overflow_and_zero()
{
	if (KadNodesDatCountFits(0, 25, 0) != true)
		return false;
	if (KadNodesDatCountFits(1, 25, 25) != true)
		return false;
	if (KadNodesDatCountFits(1, 25, 24) != false)
		return false;
	if (KadNodesDatCountFits(0xFFFFFFFFu, 25, 100) != false)
		return false;
	if (KadNodesDatCountFits(2, 25, 49) != false)
		return false;
	if (KadNodesDatCountFits(2, 0, 100) != false)
		return false;
	return KadNodesDatCountFits(0xFFFFFFFFu, 1, 0xFFFFFFFFu) == true;
}

static bool test_legacy_v0_parsed_but_kad1_dropped()
{
	std::vector<uint8_t> o;
	PushU32LE(o, 1);
	PushBytes(o, kId1, 16);
	PushIp(o, 203, 0, 113, 5);
	PushU16LE(o, 4672);
	PushU16LE(o, 4662);
	PushU8(o, 2); // type < 4
	KadNodesDatContact c[4] = {};
	const KadNodesDatResult r = ParseBuf(o, c, 4);
	return r.status == KadNodesDatStatus::Ok && r.kind == KadNodesDatKind::LegacyV0 && r.declaredCount == 1 && r.acceptedCount == 0;
}

static bool test_v1_golden_one_contact()
{
	std::vector<uint8_t> o;
	PushU32LE(o, 0);
	PushU32LE(o, 1);
	PushU32LE(o, 1);
	PushBytes(o, kId1, 16);
	PushIp(o, 203, 0, 113, 5);
	PushU16LE(o, 4672);
	PushU16LE(o, 4662);
	PushU8(o, 8);
	KadNodesDatContact c[4] = {};
	const KadNodesDatResult r = ParseBuf(o, c, 4);
	if (r.status != KadNodesDatStatus::Ok || r.kind != KadNodesDatKind::Version1)
		return false;
	if (r.acceptedCount != 1)
		return false;
	if (std::memcmp(c[0].id, kId1, 16) != 0)
		return false;
	if (!ContactIpIs(c[0], 203, 0, 113, 5))
		return false;
	if (c[0].udpPort != 4672 || c[0].tcpPort != 4662 || c[0].contactVersion != 8)
		return false;
	return c[0].udpKey == 0 && c[0].verified == 0;
}

static bool test_v1_two_contacts()
{
	std::vector<uint8_t> o;
	PushU32LE(o, 0);
	PushU32LE(o, 1);
	PushU32LE(o, 2);
	PushV1Contact(o, 1, 203, 0, 113, 5, 4672, 4662, 8);
	PushV1Contact(o, 2, 203, 1, 113, 6, 4673, 4663, 9);
	KadNodesDatContact c[4] = {};
	const KadNodesDatResult r = ParseBuf(o, c, 4);
	return r.status == KadNodesDatStatus::Ok && r.acceptedCount == 2 && c[0].udpPort == 4672 && c[1].udpPort == 4673;
}

static bool test_v2_golden_key_and_verified()
{
	std::vector<uint8_t> o;
	PushU32LE(o, 0);
	PushU32LE(o, 2);
	PushU32LE(o, 1);
	PushBytes(o, kId1, 16);
	PushIp(o, 203, 0, 113, 5);
	PushU16LE(o, 4672);
	PushU16LE(o, 4662);
	PushU8(o, 8);
	PushU32LE(o, 0xAABBCCDDu);
	// 192.0.2.1 s_addr on little-endian (C0 00 02 01) as WriteUInt32.
	PushU32LE(o, 0x010200C0u);
	PushU8(o, 1);
	KadNodesDatContact c[2] = {};
	const KadNodesDatResult r = ParseBuf(o, c, 2);
	if (r.status != KadNodesDatStatus::Ok || r.kind != KadNodesDatKind::Version2)
		return false;
	if (r.acceptedCount != 1)
		return false;
	if (c[0].udpKey != 0xAABBCCDDu || c[0].udpKeyIp != 0x010200C0u)
		return false;
	if (c[0].verified != 1)
		return false;
	if (!ContactIpIs(c[0], 203, 0, 113, 5))
		return false;
	return c[0].udpPort == 4672 && c[0].tcpPort == 4662 && c[0].contactVersion == 8;
}

static bool test_v2_verified_false()
{
	std::vector<uint8_t> o;
	PushU32LE(o, 0);
	PushU32LE(o, 2);
	PushU32LE(o, 1);
	PushV2Contact(o, 1, 203, 0, 113, 5, 4672, 4662, 8, 1, 2, 0);
	KadNodesDatContact c[2] = {};
	const KadNodesDatResult r = ParseBuf(o, c, 2);
	return r.status == KadNodesDatStatus::Ok && r.acceptedCount == 1 && c[0].verified == 0;
}

static bool test_v3_normal()
{
	std::vector<uint8_t> o;
	PushU32LE(o, 0);
	PushU32LE(o, 3);
	PushU32LE(o, 0);
	PushU32LE(o, 1);
	PushV2Contact(o, 1, 203, 0, 113, 5, 4672, 4662, 8, 9, 10, 1);
	KadNodesDatContact c[2] = {};
	const KadNodesDatResult r = ParseBuf(o, c, 2);
	return r.status == KadNodesDatStatus::Ok && r.kind == KadNodesDatKind::Version3Normal && r.bootstrapEdition == false && r.acceptedCount == 1;
}

static bool test_v3_bootstrap_selects_closest()
{
	std::vector<uint8_t> o;
	PushU32LE(o, 0);
	PushU32LE(o, 3);
	PushU32LE(o, 1);
	PushU32LE(o, 4);
	uint8_t own[16] = {};
	own[0] = 0x10;
	// IDs 0x10.. are closer to own than 0x80..
	PushV1Contact(o, 0x80, 203, 1, 1, 5, 4672, 4662, 8);
	PushV1Contact(o, 0x11, 203, 2, 1, 5, 4672, 4662, 8);
	PushV1Contact(o, 0x90, 203, 3, 1, 5, 4672, 4662, 8);
	PushV1Contact(o, 0x12, 203, 4, 1, 5, 4672, 4662, 8);
	KadNodesDatContact c[4] = {};
	const KadNodesDatResult r = KadNodesDatParse(o.data(), o.size(), c, 2, own);
	if (r.status != KadNodesDatStatus::Ok || r.kind != KadNodesDatKind::Version3Bootstrap)
		return false;
	if (r.bootstrapEdition != true || r.acceptedCount != 2)
		return false;
	return c[0].id[0] == 0x11 && c[1].id[0] == 0x12;
}

static bool test_v3_bootstrap_maxout_one()
{
	std::vector<uint8_t> o;
	PushU32LE(o, 0);
	PushU32LE(o, 3);
	PushU32LE(o, 1);
	PushU32LE(o, 2);
	uint8_t own[16] = {};
	own[0] = 0x10;
	PushV1Contact(o, 0x80, 203, 1, 1, 5, 4672, 4662, 8);
	PushV1Contact(o, 0x11, 203, 2, 1, 5, 4672, 4662, 8);
	KadNodesDatContact c[1] = {};
	const KadNodesDatResult r = KadNodesDatParse(o.data(), o.size(), c, 1, own);
	return r.status == KadNodesDatStatus::Ok && r.acceptedCount == 1 && c[0].id[0] == 0x11;
}

static bool test_v3_bootstrap_large_pool_capped()
{
	const uint32_t nPool = 80;
	std::vector<uint8_t> o;
	PushU32LE(o, 0);
	PushU32LE(o, 3);
	PushU32LE(o, 1);
	PushU32LE(o, nPool);
	for (uint32_t i = 0; i < nPool; ++i)
	{
		PushV1Contact(
		    o,
		    static_cast<uint8_t>(i + 1),
		    203,
		    static_cast<uint8_t>(i + 1),
		    1,
		    5,
		    4672,
		    4662,
		    8);
	}
	KadNodesDatContact c[80] = {};
	const KadNodesDatResult r = ParseBuf(o, c, 80);
	return r.status == KadNodesDatStatus::Ok && r.declaredCount == nPool && r.acceptedCount == KadNodesDatBootstrapSelect;
}

static bool test_unknown_version_fail_closed()
{
	std::vector<uint8_t> o;
	PushU32LE(o, 0);
	PushU32LE(o, 4);
	PushU32LE(o, 1);
	PushV1Contact(o, 1, 203, 0, 113, 5, 4672, 4662, 8);
	KadNodesDatContact c[2] = {};
	const KadNodesDatResult r = ParseBuf(o, c, 2);
	return r.status == KadNodesDatStatus::UnknownVersion && r.acceptedCount == 0;
}

static bool test_v3_invalid_edition()
{
	std::vector<uint8_t> o;
	PushU32LE(o, 0);
	PushU32LE(o, 3);
	PushU32LE(o, 2);
	PushU32LE(o, 1);
	PushV1Contact(o, 1, 203, 0, 113, 5, 4672, 4662, 8);
	KadNodesDatContact c[2] = {};
	const KadNodesDatResult r = ParseBuf(o, c, 2);
	return r.status == KadNodesDatStatus::InvalidEdition && r.acceptedCount == 0;
}

static bool test_truncated_headers()
{
	KadNodesDatContact c[1] = {};
	const uint8_t marker3[] = { 0, 0, 0 };
	if (KadNodesDatParse(marker3, 3, c, 1, nullptr).status != KadNodesDatStatus::Truncated)
		return false;
	const uint8_t markerOnly[] = { 0, 0, 0, 0 };
	if (KadNodesDatParse(markerOnly, 4, c, 1, nullptr).status != KadNodesDatStatus::Truncated)
		return false;
	const uint8_t verOnly[] = { 0, 0, 0, 0, 1, 0, 0, 0 };
	if (KadNodesDatParse(verOnly, 8, c, 1, nullptr).status != KadNodesDatStatus::Truncated)
		return false;
	const uint8_t v3ed[] = { 0, 0, 0, 0, 3, 0, 0, 0, 1, 0 };
	if (KadNodesDatParse(v3ed, 10, c, 1, nullptr).status != KadNodesDatStatus::Truncated)
		return false;
	return true;
}

static bool test_v1_truncated_each_field()
{
	std::vector<uint8_t> full;
	PushU32LE(full, 0);
	PushU32LE(full, 1);
	PushU32LE(full, 1);
	PushBytes(full, kId1, 16);
	PushIp(full, 203, 0, 113, 5);
	PushU16LE(full, 4672);
	PushU16LE(full, 4662);
	PushU8(full, 8);
	KadNodesDatContact c[2] = {};
	// Prefixes after the 12-byte header: id, ip, udp, tcp, version.
	const size_t cuts[] = { 12 + 8, 12 + 16, 12 + 18, 12 + 20, 12 + 22, 12 + 24 };
	for (size_t n : cuts)
	{
		std::vector<uint8_t> slice(full.begin(), full.begin() + static_cast<std::ptrdiff_t>(n));
		const KadNodesDatResult r = ParseBuf(slice, c, 2);
		if (r.status != KadNodesDatStatus::CountMismatch && r.status != KadNodesDatStatus::Truncated)
			return false;
		if (r.acceptedCount != 0)
			return false;
	}
	return true;
}

static bool test_v2_truncated_key_fields()
{
	std::vector<uint8_t> full;
	PushU32LE(full, 0);
	PushU32LE(full, 2);
	PushU32LE(full, 1);
	PushV2Contact(full, 1, 203, 0, 113, 5, 4672, 4662, 8, 0x11, 0x22, 1);
	KadNodesDatContact c[2] = {};
	const size_t nFull = full.size();
	if (nFull != 12 + 34)
		return false;
	const size_t cuts[] = {
		nFull - 9, // partial key
		nFull - 5, // key present, partial key IP
		nFull - 1  // missing verified
	};
	for (size_t n : cuts)
	{
		std::vector<uint8_t> slice(full.begin(), full.begin() + static_cast<std::ptrdiff_t>(n));
		const KadNodesDatResult r = ParseBuf(slice, c, 2);
		if (r.status != KadNodesDatStatus::CountMismatch && r.status != KadNodesDatStatus::Truncated)
			return false;
		if (r.acceptedCount != 0)
			return false;
	}
	const KadNodesDatResult exact = ParseBuf(full, c, 2);
	return exact.status == KadNodesDatStatus::Ok && exact.acceptedCount == 1;
}

static bool test_uint32_max_count()
{
	std::vector<uint8_t> o;
	PushU32LE(o, 0);
	PushU32LE(o, 1);
	PushU32LE(o, 0xFFFFFFFFu);
	KadNodesDatContact c[1] = {};
	const KadNodesDatResult r = ParseBuf(o, c, 1);
	return r.status == KadNodesDatStatus::CountMismatch && r.acceptedCount == 0;
}

static bool test_oversized_count_one_byte_short()
{
	std::vector<uint8_t> o;
	PushU32LE(o, 0);
	PushU32LE(o, 1);
	PushU32LE(o, 1);
	PushV1Contact(o, 1, 203, 0, 113, 5, 4672, 4662, 8);
	o.pop_back();
	KadNodesDatContact c[1] = {};
	const KadNodesDatResult r = ParseBuf(o, c, 1);
	return r.status == KadNodesDatStatus::CountMismatch && r.acceptedCount == 0;
}

static bool test_trailing_byte_rejected()
{
	std::vector<uint8_t> o;
	PushU32LE(o, 0);
	PushU32LE(o, 1);
	PushU32LE(o, 1);
	PushV1Contact(o, 1, 203, 0, 113, 5, 4672, 4662, 8);
	PushU8(o, 0xFF);
	KadNodesDatContact c[1] = {};
	const KadNodesDatResult r = ParseBuf(o, c, 1);
	return r.status == KadNodesDatStatus::CountMismatch && r.acceptedCount == 0;
}

static bool test_file_size_limit()
{
	std::vector<uint8_t> o(KadNodesDatMaxFileBytes + 1, 0);
	KadNodesDatContact c[1] = {};
	const KadNodesDatResult r = ParseBuf(o, c, 1);
	return r.status == KadNodesDatStatus::SizeLimit;
}

static bool test_invalid_id_ip_port_version_dup()
{
	std::vector<uint8_t> o;
	PushU32LE(o, 0);
	PushU32LE(o, 1);
	PushU32LE(o, 6);
	// zero ID
	uint8_t zero[16] = {};
	PushBytes(o, zero, 16);
	PushIp(o, 203, 0, 113, 5);
	PushU16LE(o, 4672);
	PushU16LE(o, 4662);
	PushU8(o, 8);
	// loopback
	PushV1Contact(o, 2, 127, 0, 0, 1, 4672, 4662, 8);
	// zero UDP
	PushV1Contact(o, 3, 203, 0, 113, 6, 0, 4662, 8);
	// Kad1
	PushV1Contact(o, 4, 203, 1, 113, 5, 4672, 4662, 1);
	// valid
	PushV1Contact(o, 5, 203, 2, 113, 5, 4672, 4662, 8);
	// duplicate ID of the valid one (seed 5)
	PushV1Contact(o, 5, 203, 3, 113, 5, 4674, 4664, 8);
	KadNodesDatContact c[8] = {};
	const KadNodesDatResult r = ParseBuf(o, c, 8);
	return r.status == KadNodesDatStatus::Ok && r.acceptedCount == 1 && c[0].id[0] == 5;
}

static bool test_udp53_old_version_rejected()
{
	std::vector<uint8_t> o;
	PushU32LE(o, 0);
	PushU32LE(o, 1);
	PushU32LE(o, 1);
	PushV1Contact(o, 1, 203, 0, 113, 5, 53, 4662, 5);
	KadNodesDatContact c[1] = {};
	const KadNodesDatResult r = ParseBuf(o, c, 1);
	return r.status == KadNodesDatStatus::Ok && r.acceptedCount == 0;
}

static bool test_slash24_cap()
{
	std::vector<uint8_t> o;
	PushU32LE(o, 0);
	PushU32LE(o, 1);
	PushU32LE(o, 4);
	PushV1Contact(o, 1, 203, 0, 113, 1, 4672, 4662, 8);
	PushV1Contact(o, 2, 203, 0, 113, 2, 4673, 4663, 8);
	PushV1Contact(o, 3, 203, 0, 113, 3, 4674, 4664, 8);
	PushV1Contact(o, 4, 203, 1, 113, 1, 4675, 4665, 8);
	KadNodesDatContact c[4] = {};
	const KadNodesDatResult r = ParseBuf(o, c, 4);
	return r.status == KadNodesDatStatus::Ok && r.acceptedCount == 3 && ContactIpIs(c[2], 203, 1, 113, 1);
}

static bool test_xor_helper_order()
{
	uint8_t own[16] = {};
	uint8_t close[16] = {};
	uint8_t farId[16] = {};
	own[0] = 0x10;
	close[0] = 0x11;
	farId[0] = 0x80;
	return KadNodesDatXorCmp(own, close, farId) < 0 && KadNodesDatXorCmp(own, farId, close) > 0 && KadNodesDatXorCmp(own, close, close) == 0;
}

static bool test_empty_count()
{
	std::vector<uint8_t> o;
	PushU32LE(o, 0);
	PushU32LE(o, 1);
	PushU32LE(o, 0);
	KadNodesDatContact c[1] = {};
	const KadNodesDatResult r = ParseBuf(o, c, 1);
	return r.status == KadNodesDatStatus::Empty;
}

void register_kad_nodes_dat_tests(TestSuite& suite)
{
	suite.add_test("kad_nodes_dat_count_fits", test_count_fits_overflow_and_zero);
	suite.add_test("kad_nodes_dat_legacy_v0", test_legacy_v0_parsed_but_kad1_dropped);
	suite.add_test("kad_nodes_dat_v1_golden", test_v1_golden_one_contact);
	suite.add_test("kad_nodes_dat_v1_two", test_v1_two_contacts);
	suite.add_test("kad_nodes_dat_v2_golden", test_v2_golden_key_and_verified);
	suite.add_test("kad_nodes_dat_v2_unverified", test_v2_verified_false);
	suite.add_test("kad_nodes_dat_v3_normal", test_v3_normal);
	suite.add_test("kad_nodes_dat_v3_bootstrap_closest", test_v3_bootstrap_selects_closest);
	suite.add_test("kad_nodes_dat_v3_bootstrap_maxout_one", test_v3_bootstrap_maxout_one);
	suite.add_test("kad_nodes_dat_v3_bootstrap_cap", test_v3_bootstrap_large_pool_capped);
	suite.add_test("kad_nodes_dat_unknown_version", test_unknown_version_fail_closed);
	suite.add_test("kad_nodes_dat_invalid_edition", test_v3_invalid_edition);
	suite.add_test("kad_nodes_dat_truncated_headers", test_truncated_headers);
	suite.add_test("kad_nodes_dat_v1_truncated_fields", test_v1_truncated_each_field);
	suite.add_test("kad_nodes_dat_v2_truncated_key", test_v2_truncated_key_fields);
	suite.add_test("kad_nodes_dat_uint32_max_count", test_uint32_max_count);
	suite.add_test("kad_nodes_dat_one_byte_short", test_oversized_count_one_byte_short);
	suite.add_test("kad_nodes_dat_trailing_byte", test_trailing_byte_rejected);
	suite.add_test("kad_nodes_dat_size_limit", test_file_size_limit);
	suite.add_test("kad_nodes_dat_invalid_and_dup", test_invalid_id_ip_port_version_dup);
	suite.add_test("kad_nodes_dat_udp53_old", test_udp53_old_version_rejected);
	suite.add_test("kad_nodes_dat_slash24_cap", test_slash24_cap);
	suite.add_test("kad_nodes_dat_xor_cmp", test_xor_helper_order);
	suite.add_test("kad_nodes_dat_empty_count", test_empty_count);
}

#ifdef ENVY_KAD_NODES_DAT_STANDALONE
int main()
{
	TestSuite suite;
	register_kad_nodes_dat_tests(suite);
	const int failed = suite.run();
	std::cout << (failed == 0 ? "All nodes.dat parser tests passed\n" : "nodes.dat parser tests failed\n");
	return failed == 0 ? 0 : 1;
}
#endif
