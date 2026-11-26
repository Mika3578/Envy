//
// KadUdpObfuscation.h
//
// Inbound deobfuscation of the eMule/aMule encrypted Kad2 UDP datagrams
// ("Basic Obfuscation Handshake Protocol, UDP" in EncryptedStreamSocket.h).
// Free of MFC so the byte layout can be tested natively, like KadHello.h.
//
// Envy advertises KADEMLIA_VERSION 8 in a clear HELLO_REQ. aMule and eMule
// answer a requester on Kad version >= 6 with HELLO_RES - and, once a peer has
// learned our NodeID, every further Kad2 packet it sends us - obfuscated with
// RC4 over MD5(<our KadID 16><2 random bytes>), see aMule
// EncryptedDatagramSocket.cpp EncryptSendClient(kad=true) and
// DecryptReceivedClient. Such a datagram starts with a marker byte instead of
// a protocol byte:
//
//   <marker 1 plain><random key part 2 plain><RC4(magic 4)><RC4(padLen 1)>
//   <RC4(padding padLen)><RC4(receiverVerifyKey 4)><RC4(senderVerifyKey 4)>
//   <RC4(clear ED2K/Kad datagram)>
//
// The magic value 0x395F2EC1 and both verify keys travel byte-swapped, i.e.
// big-endian on the wire (the sender encrypts ENDIAN_SWAP_32 values). Padding
// is 0 for UDP today, but any length that fits is accepted, as in the
// references. The marker only hints which key to try first and is explicitly
// not to be trusted, so the NodeID key and, when one is known, the
// receiver-verify-key path are both tried in the marker-guided order; the ED2K
// user-hash key (marker bit 1) is out of scope here. Once the magic matched,
// a padding or verify-key length failure ends the whole attempt, like aMule
// passing the packet through to the junk handling of its receive function.
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
// SPDX-License-Identifier: AGPL-3.0-or-later
//

#pragma once

#include "RC4.h"                // CRC4; windows.h first, the HashLib headers need it
#include "../HashLib/HashLib.h" // CMD5

#include <cstdint>
#include <cstring>

// The value an obfuscated packet carries after the first keystream block;
// aMule encrypts ENDIAN_SWAP_32(MAGICVALUE_UDP_SYNC_CLIENT), so the wire bytes
// are the big-endian encoding.
constexpr uint32_t KadUdpObfuscationMagic = 0x395F2EC1u;

// Marker + random key part + encrypted magic + encrypted padLen.
constexpr size_t KadUdpObfuscationHeaderBytes = 8;

// Encrypted receiver + sender verify keys, Kad packets only.
constexpr size_t KadUdpVerifyKeyBytes = 8;

enum KadUdpObfuscationResult
{
	KadUdpClearPacket = 0, // too short or a clear protocol byte: not obfuscated
	KadUdpDecrypted,       // deobfuscated; the clear ED2K/Kad datagram is in out
	KadUdpRejected         // looked obfuscated but no key, length or padding check passed
};

// First bytes that identify a clear datagram. An obfuscated marker is chosen
// to differ from all of them (aMule EncryptSendClient's "not allowed values"
// plus the ED2K protocol byte), so none of them is worth an MD5 attempt.
inline bool KadUdpIsClearProtocolByte(uint8_t byte)
{
	switch (byte)
	{
	case 0xA3: // OP_UDPRESERVEDPROT1
	case 0xB2: // OP_UDPRESERVEDPROT2
	case 0xC5: // ED2K_PROTOCOL_EMULE
	case 0xD4: // ED2K_PROTOCOL_EMULE_PACKED
	case 0xE3: // ED2K_PROTOCOL_EDONKEY
	case 0xE4: // ED2K_PROTOCOL_KAD
	case 0xE5: // ED2K_PROTOCOL_KAD_PACKED
		return true;
	default:
		return false;
	}
}

namespace KadUdpObfuscationDetail
{

// Big-endian uint32 read; the magic and both verify keys are sent byte-swapped.
inline uint32_t ReadBigEndian(const uint8_t* p)
{
	return (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) |
	       (static_cast<uint32_t>(p[2]) << 8) | static_cast<uint32_t>(p[3]);
}

enum KeyAttempt
{
	KeyNoMagic = 0, // this seed did not produce the magic value: try the next one
	KeyRejected,    // magic matched but padding or verify-key lengths are invalid
	KeyDecrypted    // plaintext written to out, length returned
};

// One key attempt: RC4 over MD5(keySeed | in[1..2]). keySeed is the base key
// only (16 KadID bytes, or the 4 receiver-verify-key bytes); the random key
// part from the datagram is appended here. Returns the plaintext length for
// KeyDecrypted, otherwise 0.
inline KeyAttempt TryKey(const uint8_t* keySeed, size_t keySeedLen, const uint8_t* in, size_t n,
                         uint8_t* out, size_t outCap, size_t& outLen, uint32_t* receiverVerifyKeyOut,
                         uint32_t* senderVerifyKeyOut)
{
	CMD5 md5;
	md5.Add(keySeed, keySeedLen);
	md5.Add(in + 1, 2);
	md5.Finish();
	uchar digest[16];
	md5.GetHash(digest);

	CRC4 rc4;
	rc4.Init(digest, sizeof(digest));
	if (!rc4.IsInitialized())
		return KeyNoMagic;

	uint8_t magic[4];
	memcpy(magic, in + 3, sizeof(magic));
	rc4.Process(magic, sizeof(magic));
	if (ReadBigEndian(magic) != KadUdpObfuscationMagic)
		return KeyNoMagic;

	uint8_t padByte = in[7];
	rc4.Process(&padByte, 1);
	const size_t padLen = padByte;

	// aMule passes the datagram through when the padding would eat the rest.
	if (n - KadUdpObfuscationHeaderBytes <= padLen)
		return KeyRejected;

	// Padding is skipped without output; the keystream still has to advance.
	for (size_t i = 0; i < padLen; ++i)
	{
		uint8_t sink = in[KadUdpObfuscationHeaderBytes + i];
		rc4.Process(&sink, 1);
	}

	const size_t tail = n - KadUdpObfuscationHeaderBytes - padLen;
	if (tail <= KadUdpVerifyKeyBytes) // the two verify keys cannot fit
		return KeyRejected;

	uint8_t keys[KadUdpVerifyKeyBytes];
	memcpy(keys, in + KadUdpObfuscationHeaderBytes + padLen, sizeof(keys));
	rc4.Process(keys, sizeof(keys));

	const size_t plainLen = tail - KadUdpVerifyKeyBytes;
	if (plainLen > outCap)
		return KeyRejected;

	memcpy(out, in + KadUdpObfuscationHeaderBytes + padLen + KadUdpVerifyKeyBytes, plainLen);
	rc4.Process(out, plainLen);
	outLen = plainLen;

	if (receiverVerifyKeyOut)
		*receiverVerifyKeyOut = ReadBigEndian(keys);
	if (senderVerifyKeyOut)
		*senderVerifyKeyOut = ReadBigEndian(keys + 4);
	return KeyDecrypted;
}

} // namespace KadUdpObfuscationDetail

// Deobfuscates one inbound Kad UDP datagram. ownKadId is the 16 KadID bytes as
// they are written into HELLO_REQ (wire order); ownUdpVerifyKeyForIp is the UDP
// verify key Envy issued for the sender's IP, 0 while none exists (the
// receiver-key try is skipped rather than run against a zero key). The clear
// datagram is written to out, which must not alias in; outLen receives its
// length and the header verify keys are reported in host byte order when the
// output pointers are given.
inline KadUdpObfuscationResult KadUdpDeobfuscate(const uint8_t* in, size_t n,
                                                 const uint8_t* ownKadId, uint32_t ownUdpVerifyKeyForIp, uint8_t* out, size_t outCap,
                                                 size_t& outLen, uint32_t* receiverVerifyKeyOut = nullptr,
                                                 uint32_t* senderVerifyKeyOut = nullptr)
{
	outLen = 0;

	// aMule treats anything up to the header length and every clear protocol
	// byte as an unencrypted packet.
	if (in == nullptr || out == nullptr || n <= KadUdpObfuscationHeaderBytes ||
	    KadUdpIsClearProtocolByte(in[0]))
		return KadUdpClearPacket;

	if (ownKadId == nullptr)
		return KadUdpClearPacket; // without a KadID no key can be derived

	uint8_t verifyKeySeed[4];

	// The marker bits only order the attempts; old clients set them at random.
	// Try 0 = Kad with our NodeID, 1 = ED2K with the user hash (out of scope),
	// 2 = Kad with the receiver verify key bound to this IP.
	unsigned marker = in[0] & 0x03u;
	if (marker == 3)
		marker = 1;

	for (unsigned attempt = 0; attempt < 3; ++attempt)
	{
		const unsigned currentTry = (marker + attempt) % 3;
		if (currentTry == 1)
			continue; // ED2K user-hash key, out of scope (see file comment)

		size_t plainLen = 0;
		KadUdpObfuscationDetail::KeyAttempt attemptResult = KadUdpObfuscationDetail::KeyNoMagic;

		if (currentTry == 0)
		{
			attemptResult = KadUdpObfuscationDetail::TryKey(ownKadId, 16, in, n, out, outCap,
			                                                plainLen, receiverVerifyKeyOut, senderVerifyKeyOut);
		}
		else if (ownUdpVerifyKeyForIp != 0)
		{
			// aMule PokeUInt32: the verify key enters the seed little-endian.
			verifyKeySeed[0] = static_cast<uint8_t>(ownUdpVerifyKeyForIp);
			verifyKeySeed[1] = static_cast<uint8_t>(ownUdpVerifyKeyForIp >> 8);
			verifyKeySeed[2] = static_cast<uint8_t>(ownUdpVerifyKeyForIp >> 16);
			verifyKeySeed[3] = static_cast<uint8_t>(ownUdpVerifyKeyForIp >> 24);
			attemptResult = KadUdpObfuscationDetail::TryKey(verifyKeySeed, sizeof(verifyKeySeed),
			                                                in, n, out, outCap, plainLen, receiverVerifyKeyOut, senderVerifyKeyOut);
		}
		// A zero verify key means none was issued for this source IP yet, so the
		// receiver-key try is skipped rather than run against a fixed zero key.

		if (attemptResult == KadUdpObfuscationDetail::KeyDecrypted)
		{
			outLen = plainLen;
			return KadUdpDecrypted;
		}
		if (attemptResult == KadUdpObfuscationDetail::KeyRejected)
			return KadUdpRejected; // aMule stops at the first magic match, whatever follows
	}

	return KadUdpRejected;
}
