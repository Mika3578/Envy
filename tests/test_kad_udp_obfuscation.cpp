//
// test_kad_udp_obfuscation.cpp
//
// Inbound Kad UDP deobfuscation (KadUdpDeobfuscate): round-trips against an
// in-test model of aMule's EncryptSendClient(kad=true) and golden datagrams
// produced by an independent implementation of the same aMule algorithm
// (Python: hashlib.md5 and plain RC4; no aMule build was available to capture
// live packets). Synthetic data only.
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
// SPDX-License-Identifier: AGPL-3.0-or-later
//

#include "test_framework.h"
#include "../Envy/KadUdpObfuscation.h"
#include "../Envy/KadHello.h"

#include <cstring>
#include <vector>

namespace
{

const uint8_t kId[16] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
constexpr uint8_t kKadProtocol = 0xE4; // ED2K_PROTOCOL_KAD
constexpr uint8_t kKadProtocolPacked = 0xE5;
constexpr uint8_t kOpHelloRes = 0x19;       // KADEMLIA2_HELLO_RES
constexpr uint16_t kRandomKeyPart = 0x1234; // in[1..2] on the wire (little-endian)
constexpr uint32_t kRcvKey = 0xDEADBEEFu;
constexpr uint32_t kSndKey = 0xCAFEBABEu;

// TAG_SOURCEUPORT as eMule writes it: type UINT16, name length 1, name 0xFC, value 4672.
const uint8_t kUdpTag[] = { 0x08, 0x01, 0x00, 0xFC, 0x40, 0x12 };
// TAG_KADMISCOPTIONS as eMule writes it: type UINT8, name 0xF2.
const uint8_t kMiscTag[] = { 0x09, 0x01, 0x00, 0xF2, 0x05 };

// Independent RC4 for the encryptor side (keystream from byte 0, as aMule
// SetKey(md5, true) gives for UDP; the first 1024 bytes are not discarded).
class TestRc4
{
public:
	TestRc4(const uint8_t* key, size_t keyLen)
	{
		for (unsigned i = 0; i < 256; ++i)
			m_state[i] = static_cast<uint8_t>(i);
		unsigned j = 0;
		for (unsigned i = 0; i < 256; ++i)
		{
			j = (j + m_state[i] + key[i % keyLen]) & 0xFF;
			const uint8_t tmp = m_state[i];
			m_state[i] = m_state[j];
			m_state[j] = tmp;
		}
	}

	std::vector<uint8_t> Crypt(const uint8_t* in, size_t len)
	{
		std::vector<uint8_t> out(len);
		for (size_t i = 0; i < len; ++i)
			out[i] = in[i] ^ Advance();
		return out;
	}

private:
	uint8_t Advance()
	{
		m_x = (m_x + 1) & 0xFF;
		m_y = (m_y + m_state[m_x]) & 0xFF;
		const uint8_t tmp = m_state[m_x];
		m_state[m_x] = m_state[m_y];
		m_state[m_y] = tmp;
		return m_state[(m_state[m_x] + m_state[m_y]) & 0xFF];
	}

	uint8_t m_state[256];
	unsigned m_x = 0;
	unsigned m_y = 0;
};

void PushU16LE(std::vector<uint8_t>& o, uint16_t v)
{
	o.push_back(static_cast<uint8_t>(v & 0xFF));
	o.push_back(static_cast<uint8_t>(v >> 8));
}

void PushU32LE(std::vector<uint8_t>& o, uint32_t v)
{
	o.push_back(static_cast<uint8_t>(v));
	o.push_back(static_cast<uint8_t>(v >> 8));
	o.push_back(static_cast<uint8_t>(v >> 16));
	o.push_back(static_cast<uint8_t>(v >> 24));
}

void PushU32BE(std::vector<uint8_t>& o, uint32_t v)
{
	o.push_back(static_cast<uint8_t>(v >> 24));
	o.push_back(static_cast<uint8_t>(v >> 16));
	o.push_back(static_cast<uint8_t>(v >> 8));
	o.push_back(static_cast<uint8_t>(v));
}

// Model of aMule CEncryptedDatagramSocket::EncryptSendClient(kad=true):
// <marker plain><random key part plain><RC4(magic)><RC4(padLen)><RC4(padding)>
// <RC4(receiverVerifyKey)><RC4(senderVerifyKey)><RC4(payload)>.
std::vector<uint8_t> EncryptKad(const std::vector<uint8_t>& payload, const uint8_t* kadId,
                                uint16_t randomKeyPart, uint32_t rcvKey, uint32_t sndKey, uint8_t marker, uint8_t padLen = 0,
                                bool useRecvKey = false)
{
	std::vector<uint8_t> keySeed;
	if (useRecvKey)
		PushU32LE(keySeed, rcvKey); // aMule PokeUInt32: little-endian
	else
		keySeed.assign(kadId, kadId + 16);
	PushU16LE(keySeed, randomKeyPart);

	CMD5 md5;
	md5.Add(keySeed.data(), keySeed.size());
	md5.Finish();
	uchar digest[16];
	md5.GetHash(digest);

	TestRc4 stream(digest, sizeof(digest));
	std::vector<uint8_t> out;
	out.push_back(marker);
	PushU16LE(out, randomKeyPart);

	const uint8_t magic[] = { 0x39, 0x5F, 0x2E, 0xC1 }; // big-endian magic on the wire
	const auto magicBytes = stream.Crypt(magic, sizeof(magic));
	out.insert(out.end(), magicBytes.begin(), magicBytes.end());
	const uint8_t padByte = padLen;
	const auto padBytes = stream.Crypt(&padByte, 1);
	out.insert(out.end(), padBytes.begin(), padBytes.end());
	// The padding bytes are part of the datagram (aMule encrypts random bytes
	// into the output buffer); only their content is irrelevant.
	for (uint8_t i = 0; i < padLen; ++i)
	{
		const uint8_t filler = i;
		const auto fillerBytes = stream.Crypt(&filler, 1);
		out.insert(out.end(), fillerBytes.begin(), fillerBytes.end());
	}
	// Verify keys are sent byte-swapped (aMule ENDIAN_SWAP_I_32).
	uint8_t keyBytes[8] = {};
	keyBytes[0] = static_cast<uint8_t>(rcvKey >> 24);
	keyBytes[1] = static_cast<uint8_t>(rcvKey >> 16);
	keyBytes[2] = static_cast<uint8_t>(rcvKey >> 8);
	keyBytes[3] = static_cast<uint8_t>(rcvKey);
	keyBytes[4] = static_cast<uint8_t>(sndKey >> 24);
	keyBytes[5] = static_cast<uint8_t>(sndKey >> 16);
	keyBytes[6] = static_cast<uint8_t>(sndKey >> 8);
	keyBytes[7] = static_cast<uint8_t>(sndKey);
	const auto keyCrypt = stream.Crypt(keyBytes, sizeof(keyBytes));
	out.insert(out.end(), keyCrypt.begin(), keyCrypt.end());
	const auto payloadBytes = stream.Crypt(payload.data(), payload.size());
	out.insert(out.end(), payloadBytes.begin(), payloadBytes.end());
	return out;
}

// The clear HELLO_RES datagram: opcode header + <ID 16><TCP 2><Ver 1><TagCount 1><Tag>*.
std::vector<uint8_t> HelloRes(const std::vector<std::vector<uint8_t>>& tags)
{
	std::vector<uint8_t> payload;
	payload.push_back(kKadProtocol);
	payload.push_back(kOpHelloRes);
	payload.insert(payload.end(), kId, kId + 16);
	PushU16LE(payload, 0x1236);
	payload.push_back(8);
	payload.push_back(static_cast<uint8_t>(tags.size()));
	for (const auto& tag : tags)
		payload.insert(payload.end(), tag.begin(), tag.end());
	return payload;
}

bool Equal(const std::vector<uint8_t>& a, const uint8_t* b, size_t bLen)
{
	return a.size() == bLen && memcmp(a.data(), b, bLen) == 0;
}

bool Equal(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b)
{
	return a.size() == b.size() && memcmp(a.data(), b.data(), a.size()) == 0;
}

// Golden obfuscated HELLO_RES datagrams, NodeID key path (marker 0x40, random
// key part 0x1234, receiver key 0xDEADBEEF, sender key 0xCAFEBABE, padLen 0),
// generated with the independent reference model.
const uint8_t kGoldenHelloRes38[] = { 0x40, 0x34, 0x12, 0x09, 0x8D, 0x9F, 0xA6, 0xD4, 0x2C, 0xD3, 0x16, 0xF5, 0x83, 0x19, 0x22, 0x94, 0x8A, 0x9E, 0x38, 0xDB, 0x59, 0x8F, 0x66, 0xEE, 0xF6, 0xFC, 0x4D, 0x05, 0xED, 0x65, 0x75, 0xAD, 0xCA, 0x83, 0xC5, 0xD4, 0x0B, 0xD8 };
const uint8_t kGoldenHelloRes43[] = { 0x40, 0x34, 0x12, 0x09, 0x8D, 0x9F, 0xA6, 0xD4, 0x2C, 0xD3, 0x16, 0xF5, 0x83, 0x19, 0x22, 0x94, 0x8A, 0x9E, 0x38, 0xDB, 0x59, 0x8F, 0x66, 0xEE, 0xF6, 0xFC, 0x4D, 0x05, 0xED, 0x65, 0x75, 0xAD, 0xCA, 0x83, 0xC5, 0xD4, 0x0B, 0xD9, 0xEB, 0xCA, 0x7A, 0x44, 0x3C };
const uint8_t kGoldenHelloRes44[] = { 0x40, 0x34, 0x12, 0x09, 0x8D, 0x9F, 0xA6, 0xD4, 0x2C, 0xD3, 0x16, 0xF5, 0x83, 0x19, 0x22, 0x94, 0x8A, 0x9E, 0x38, 0xDB, 0x59, 0x8F, 0x66, 0xEE, 0xF6, 0xFC, 0x4D, 0x05, 0xED, 0x65, 0x75, 0xAD, 0xCA, 0x83, 0xC5, 0xD4, 0x0B, 0xD9, 0xEA, 0xCA, 0x7A, 0x4A, 0x79, 0xE1 };
const uint8_t kGoldenHelloRes49[] = { 0x40, 0x34, 0x12, 0x09, 0x8D, 0x9F, 0xA6, 0xD4, 0x2C, 0xD3, 0x16, 0xF5, 0x83, 0x19, 0x22, 0x94, 0x8A, 0x9E, 0x38, 0xDB, 0x59, 0x8F, 0x66, 0xEE, 0xF6, 0xFC, 0x4D, 0x05, 0xED, 0x65, 0x75, 0xAD, 0xCA, 0x83, 0xC5, 0xD4, 0x0B, 0xDA, 0xEA, 0xCA, 0x7A, 0x4A, 0x79, 0xE1, 0x0F, 0x3C, 0x27, 0xDC, 0x11 };
// Receiver-verify-key path (marker 0x42, key MD5(LE32(0xDEADBEEF) | 0x1234)).
const uint8_t kGoldenHelloResRecvKey38[] = { 0x42, 0x34, 0x12, 0x1F, 0xBE, 0x07, 0x9A, 0xB4, 0x2E, 0x2D, 0x83, 0xC3, 0xD4, 0xE6, 0x01, 0x8C, 0x65, 0x0C, 0x47, 0x99, 0x39, 0xB2, 0x63, 0x5C, 0x57, 0xA0, 0x29, 0xFE, 0xB8, 0x41, 0xD9, 0x04, 0x41, 0x50, 0xB6, 0x06, 0x49, 0x36 };

bool DecryptGolden(const uint8_t* golden, size_t goldenLen, const std::vector<uint8_t>& expect,
                   uint32_t ownVerifyKey, uint32_t* rcvOut = nullptr, uint32_t* sndOut = nullptr)
{
	std::vector<uint8_t> out(goldenLen + 16, 0xAB); // oversize scratch, sentinel-filled
	size_t plainLen = 0;
	const KadUdpObfuscationResult result = KadUdpDeobfuscate(
	    golden, goldenLen, kId, ownVerifyKey, out.data(), out.size(), plainLen, rcvOut, sndOut);
	if (result != KadUdpDecrypted)
		return false;
	out.resize(plainLen);
	return Equal(out, expect);
}

bool test_cmd5_matches_reference_digest()
{
	// MD5("abc") anchors CMD5 for the encryptor and the decryptor alike.
	CMD5 md5;
	md5.Add("abc", 3);
	md5.Finish();
	uchar digest[16];
	md5.GetHash(digest);
	static const uint8_t expected[16] = { 0x90, 0x01, 0x50, 0x98, 0x3C, 0xD2, 0x4F, 0xB0,
		                                  0xD6, 0x96, 0x3F, 0x7D, 0x28, 0xE1, 0x7F, 0x72 };
	return memcmp(digest, expected, sizeof(expected)) == 0;
}

bool test_golden_hello_res_lengths()
{
	return DecryptGolden(kGoldenHelloRes38, sizeof(kGoldenHelloRes38), HelloRes({}), 0) &&
	       DecryptGolden(kGoldenHelloRes43, sizeof(kGoldenHelloRes43),
	                     HelloRes({ std::vector<uint8_t>(kMiscTag, kMiscTag + sizeof(kMiscTag)) }), 0) &&
	       DecryptGolden(kGoldenHelloRes44, sizeof(kGoldenHelloRes44),
	                     HelloRes({ std::vector<uint8_t>(kUdpTag, kUdpTag + sizeof(kUdpTag)) }), 0) &&
	       DecryptGolden(kGoldenHelloRes49, sizeof(kGoldenHelloRes49),
	                     HelloRes({ std::vector<uint8_t>(kUdpTag, kUdpTag + sizeof(kUdpTag)),
	                                std::vector<uint8_t>(kMiscTag, kMiscTag + sizeof(kMiscTag)) }),
	                     0);
}

bool test_golden_reports_verify_keys()
{
	uint32_t rcv = 0, snd = 0;
	if (!DecryptGolden(kGoldenHelloRes49, sizeof(kGoldenHelloRes49),
	                   HelloRes({ std::vector<uint8_t>(kUdpTag, kUdpTag + sizeof(kUdpTag)),
	                              std::vector<uint8_t>(kMiscTag, kMiscTag + sizeof(kMiscTag)) }),
	                   0, &rcv, &snd))
		return false;
	return rcv == kRcvKey && snd == kSndKey;
}

bool test_golden_hello_res_parses_as_hello()
{
	std::vector<uint8_t> out(sizeof(kGoldenHelloRes49), 0);
	size_t plainLen = 0;
	if (KadUdpDeobfuscate(kGoldenHelloRes49, sizeof(kGoldenHelloRes49), kId, 0, out.data(),
	                      out.size(), plainLen) != KadUdpDecrypted)
		return false;
	KadHello hello;
	if (!KadParseHello(out.data() + 2, plainLen - 2, hello))
		return false;
	return hello.version == 8 && hello.tcpPort == 0x1236 && hello.udpPort == 4672 &&
	       hello.miscOptions == 0x05 && hello.consumed == plainLen - 2;
}

bool test_golden_recvkey_path()
{
	if (!DecryptGolden(kGoldenHelloResRecvKey38, sizeof(kGoldenHelloResRecvKey38), HelloRes({}),
	                   kRcvKey))
		return false;
	// Envy issues no verify keys yet (0 skips the try), and a wrong one misses.
	size_t plainLen = 0;
	std::vector<uint8_t> out(64, 0xAB);
	if (KadUdpDeobfuscate(kGoldenHelloResRecvKey38, sizeof(kGoldenHelloResRecvKey38), kId, 0,
	                      out.data(), out.size(), plainLen) != KadUdpRejected)
		return false;
	if (KadUdpDeobfuscate(kGoldenHelloResRecvKey38, sizeof(kGoldenHelloResRecvKey38), kId,
	                      0x11223344, out.data(), out.size(), plainLen) != KadUdpRejected)
		return false;
	return true;
}

bool test_round_trip_matches_encryptor()
{
	const std::vector<std::vector<uint8_t>> variants[] = {
		{},
		{ std::vector<uint8_t>(kMiscTag, kMiscTag + sizeof(kMiscTag)) },
		{ std::vector<uint8_t>(kUdpTag, kUdpTag + sizeof(kUdpTag)) },
		{ std::vector<uint8_t>(kUdpTag, kUdpTag + sizeof(kUdpTag)),
		  std::vector<uint8_t>(kMiscTag, kMiscTag + sizeof(kMiscTag)) },
	};
	const size_t obfuscatedLengths[] = { 38, 43, 44, 49 };
	for (size_t i = 0; i < 4; ++i)
	{
		const std::vector<uint8_t> clear = HelloRes(variants[i]);
		const std::vector<uint8_t> obfuscated =
		    EncryptKad(clear, kId, kRandomKeyPart, kRcvKey, kSndKey, 0x40);
		if (obfuscated.size() != obfuscatedLengths[i])
			return false;
		if (KadUdpIsClearProtocolByte(obfuscated[0]))
			return false;
		std::vector<uint8_t> out(64, 0);
		size_t plainLen = 0;
		if (KadUdpDeobfuscate(obfuscated.data(), obfuscated.size(), kId, 0, out.data(),
		                      out.size(), plainLen) != KadUdpDecrypted)
			return false;
		out.resize(plainLen);
		if (!Equal(out, clear))
			return false;
	}
	return true;
}

bool test_round_trip_padding_is_skipped()
{
	// Padding is unused for UDP today, but any length that fits is accepted.
	const std::vector<uint8_t> clear = HelloRes({});
	const std::vector<uint8_t> obfuscated =
	    EncryptKad(clear, kId, kRandomKeyPart, 1, 2, 0x40, 3);
	if (obfuscated.size() != clear.size() + 16 + 3)
		return false;
	std::vector<uint8_t> out(64, 0);
	size_t plainLen = 0;
	if (KadUdpDeobfuscate(obfuscated.data(), obfuscated.size(), kId, 0, out.data(), out.size(),
	                      plainLen) != KadUdpDecrypted)
		return false;
	out.resize(plainLen);
	return Equal(out, clear);
}

bool test_marker_hints_only_order_the_tries()
{
	const std::vector<uint8_t> clear = HelloRes({});
	const uint8_t markers[] = { 0x00, 0x01, 0x02, 0x03, 0x41, 0xE2, 0xFF };
	for (uint8_t marker : markers)
	{
		const std::vector<uint8_t> obfuscated =
		    EncryptKad(clear, kId, kRandomKeyPart, kRcvKey, kSndKey, marker);
		std::vector<uint8_t> out(64, 0);
		size_t plainLen = 0;
		if (KadUdpDeobfuscate(obfuscated.data(), obfuscated.size(), kId, 0, out.data(),
		                      out.size(), plainLen) != KadUdpDecrypted)
			return false;
		out.resize(plainLen);
		if (!Equal(out, clear))
			return false;
	}
	return true;
}

bool test_reject_wrong_node_id()
{
	const uint8_t other[16] = { 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1 };
	const std::vector<uint8_t> obfuscated =
	    EncryptKad(HelloRes({}), kId, kRandomKeyPart, kRcvKey, kSndKey, 0x40);
	std::vector<uint8_t> out(64, 0xAB);
	size_t plainLen = 0;
	return KadUdpDeobfuscate(obfuscated.data(), obfuscated.size(), other, 0, out.data(),
	                         out.size(), plainLen) == KadUdpRejected &&
	       out[0] == 0xAB; // nothing was decrypted into the scratch
}

bool test_reject_bad_magic()
{
	std::vector<uint8_t> obfuscated =
	    EncryptKad(HelloRes({}), kId, kRandomKeyPart, kRcvKey, kSndKey, 0x40);
	obfuscated[4] ^= 0xFF; // one byte of the encrypted magic
	std::vector<uint8_t> out(64, 0xAB);
	size_t plainLen = 0;
	return KadUdpDeobfuscate(obfuscated.data(), obfuscated.size(), kId, 0, out.data(),
	                         out.size(), plainLen) == KadUdpRejected;
}

bool test_reject_padding_overrun()
{
	// Flip the encrypted padLen byte of a valid datagram: the magic still
	// matches, but the padding then eats the whole datagram (n - 8 <= padLen).
	std::vector<uint8_t> obfuscated =
	    EncryptKad(HelloRes({}), kId, kRandomKeyPart, kRcvKey, kSndKey, 0x40);
	obfuscated[7] ^= 0xFF;
	std::vector<uint8_t> out(64, 0xAB);
	size_t plainLen = 0;
	return KadUdpDeobfuscate(obfuscated.data(), obfuscated.size(), kId, 0, out.data(),
	                         out.size(), plainLen) == KadUdpRejected;
}

bool test_reject_truncated_verify_keys()
{
	// A header-only datagram (empty payload, exactly 16 bytes of overhead)
	// leaves no room for a payload; cutting into the key area too.
	const std::vector<uint8_t> bare =
	    EncryptKad({}, kId, kRandomKeyPart, kRcvKey, kSndKey, 0x40);
	if (bare.size() != 16)
		return false;
	std::vector<uint8_t> out(64, 0xAB);
	size_t plainLen = 0;
	if (KadUdpDeobfuscate(bare.data(), bare.size(), kId, 0, out.data(), out.size(),
	                      plainLen) != KadUdpRejected)
		return false;
	if (KadUdpDeobfuscate(bare.data(), 14, kId, 0, out.data(), out.size(), plainLen) !=
	    KadUdpRejected)
		return false;
	if (KadUdpDeobfuscate(bare.data(), 12, kId, 0, out.data(), out.size(), plainLen) !=
	    KadUdpRejected)
		return false;
	return true;
}

bool test_clear_packets_pass_through()
{
	size_t plainLen = 0;
	std::vector<uint8_t> out(64, 0xAB);
	const std::vector<uint8_t> clear = HelloRes({});
	// A clear HELLO_RES, the two-byte bodyless requests and every other known
	// protocol byte are never obfuscated.
	if (KadUdpDeobfuscate(clear.data(), clear.size(), kId, 0, out.data(), out.size(),
	                      plainLen) != KadUdpClearPacket)
		return false;
	const uint8_t bodyless[] = { 0xE4, 0x01 };
	if (KadUdpDeobfuscate(bodyless, sizeof(bodyless), kId, 0, out.data(), out.size(),
	                      plainLen) != KadUdpClearPacket)
		return false;
	const uint8_t protocols[] = { 0xA3, 0xB2, 0xC5, 0xD4, 0xE3, 0xE4, 0xE5 };
	for (uint8_t first : protocols)
	{
		const uint8_t packet[] = { first, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 };
		if (KadUdpDeobfuscate(packet, sizeof(packet), kId, 0, out.data(), out.size(),
		                      plainLen) != KadUdpClearPacket)
			return false;
	}
	// Up to the header length nothing is even attempted.
	if (KadUdpDeobfuscate(clear.data(), 8, kId, 0, out.data(), out.size(), plainLen) !=
	    KadUdpClearPacket)
		return false;
	// Past it, marker-style junk is rejected.
	const uint8_t junk[] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99 };
	return KadUdpDeobfuscate(junk, sizeof(junk), kId, 0, out.data(), out.size(), plainLen) ==
	       KadUdpRejected;
}

bool test_capacity_and_null_inputs()
{
	const std::vector<uint8_t> obfuscated =
	    EncryptKad(HelloRes({}), kId, kRandomKeyPart, kRcvKey, kSndKey, 0x40);
	size_t plainLen = 0;
	std::vector<uint8_t> out(8, 0xAB); // smaller than any HELLO_RES plaintext
	if (KadUdpDeobfuscate(obfuscated.data(), obfuscated.size(), kId, 0, out.data(),
	                      out.size(), plainLen) != KadUdpRejected)
		return false;
	if (out[0] != 0xAB)
		return false;
	// A missing KadID cannot decrypt anything; the datagram stays unhandled.
	return KadUdpDeobfuscate(obfuscated.data(), obfuscated.size(), nullptr, 0, out.data(),
	                         out.size(), plainLen) == KadUdpClearPacket;
}

} // namespace

void register_kad_udp_obfuscation_tests(TestSuite& suite)
{
	suite.add_test("kad_udp_cmd5_reference_digest", test_cmd5_matches_reference_digest);
	suite.add_test("kad_udp_golden_hello_res_38_43_44_49", test_golden_hello_res_lengths);
	suite.add_test("kad_udp_golden_verify_keys", test_golden_reports_verify_keys);
	suite.add_test("kad_udp_golden_parses_as_hello", test_golden_hello_res_parses_as_hello);
	suite.add_test("kad_udp_golden_recvkey_path", test_golden_recvkey_path);
	suite.add_test("kad_udp_round_trip_encryptor", test_round_trip_matches_encryptor);
	suite.add_test("kad_udp_round_trip_padding", test_round_trip_padding_is_skipped);
	suite.add_test("kad_udp_marker_order_only", test_marker_hints_only_order_the_tries);
	suite.add_test("kad_udp_reject_wrong_node_id", test_reject_wrong_node_id);
	suite.add_test("kad_udp_reject_bad_magic", test_reject_bad_magic);
	suite.add_test("kad_udp_reject_padding_overrun", test_reject_padding_overrun);
	suite.add_test("kad_udp_reject_truncated_verify_keys", test_reject_truncated_verify_keys);
	suite.add_test("kad_udp_clear_passthrough", test_clear_packets_pass_through);
	suite.add_test("kad_udp_capacity_and_null_inputs", test_capacity_and_null_inputs);
}
