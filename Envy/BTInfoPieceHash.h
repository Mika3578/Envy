//
// BTInfoPieceHash.h
//
// Pure helpers for CBTInfo piece-hash metadata invariants (count, block size,
// vector length). Shared by Envy/BTInfo.cpp and EnvyTests — no MFC.
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//

#pragma once

#include <cstddef>
#include <cstdint>

// Matches CBTInfo::LoadTorrentTree upper bound (Envy/BTInfo.cpp).
constexpr uint32_t BTINFO_MAX_PIECE_COUNT = 209716u;

// Hashes::BtPureHash::byteCount (SHA-1 piece digest in v1 torrents).
constexpr size_t BTINFO_PIECE_HASH_BYTES = 20u;

inline bool BtPieceHashDeclaredCountValid(uint32_t blockCount)
{
	return blockCount <= BTINFO_MAX_PIECE_COUNT;
}

inline bool BtPieceHashCountsMatch(uint32_t blockCount, size_t vectorSize)
{
	return static_cast<size_t>(blockCount) == vectorSize;
}

inline bool BtPieceHashStorageConsistent(uint32_t blockCount, size_t vectorSize)
{
	return BtPieceHashCountsMatch(blockCount, vectorSize);
}

// Bytes required to store blockCount piece hashes; false on overflow.
inline bool BtPieceHashTotalBytes(uint32_t blockCount, size_t& outBytes)
{
	outBytes = 0;
	if (blockCount == 0)
		return true;
	if (!BtPieceHashDeclaredCountValid(blockCount))
		return false;
	const size_t n = static_cast<size_t>(blockCount) * BTINFO_PIECE_HASH_BYTES;
	if (n / BTINFO_PIECE_HASH_BYTES != static_cast<size_t>(blockCount))
		return false;
	outBytes = n;
	return true;
}

// Count to write on Serialize(store): vector is authoritative when metadata diverged.
inline uint32_t BtPieceHashSerializeStoreCount(uint32_t blockCount, size_t vectorSize)
{
	if (vectorSize > static_cast<size_t>(BTINFO_MAX_PIECE_COUNT))
		return 0;
	if (!BtPieceHashStorageConsistent(blockCount, vectorSize))
		return static_cast<uint32_t>(vectorSize);
	return blockCount;
}

// After Clear(): empty vector and zero metadata.
inline bool BtPieceHashClearStateValid(uint32_t blockCount, uint32_t blockSize, size_t vectorSize)
{
	return blockCount == 0 && blockSize == 0 && vectorSize == 0;
}

// FinishBlockTest / random access: use vector size when count metadata is stale.
inline bool BtPieceHashBlockIndexInRange(uint32_t blockCount, size_t vectorSize, uint32_t blockIndex)
{
	const size_t n = vectorSize;
	if (n == 0)
		return false;
	if (!BtPieceHashStorageConsistent(blockCount, vectorSize))
		return blockIndex < static_cast<uint32_t>(n);
	return blockIndex < blockCount;
}

// Validate before committing a deserialized or parsed piece-hash buffer.
inline bool BtPieceHashReadyToCommit(uint32_t newBlockCount, size_t newVectorSize)
{
	if (!BtPieceHashCountsMatch(newBlockCount, newVectorSize))
		return false;
	if (newBlockCount != 0 && !BtPieceHashDeclaredCountValid(newBlockCount))
		return false;
	size_t bytes = 0;
	return BtPieceHashTotalBytes(newBlockCount, bytes);
}
