//
// test_btinfo_piece_hash_smoke.cpp
//
// Regression smoke tests for CBTInfo piece-hash metadata invariants (#118).
// Pure helpers only — no MFC / CArchive.
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//

#include "test_framework.h"
#include "../Envy/BTInfoPieceHash.h"

static bool test_clear_state_valid()
{
	return BtPieceHashClearStateValid(0, 0, 0);
}

static bool test_clear_state_rejects_stale_count()
{
	return !BtPieceHashClearStateValid(5, 0, 0) && !BtPieceHashClearStateValid(0, 0, 3);
}

static bool test_serialize_count_zero_blocks()
{
	return BtPieceHashSerializeStoreCount(0, 0) == 0 && BtPieceHashStorageConsistent(0, 0);
}

static bool test_serialize_count_one_block()
{
	return BtPieceHashSerializeStoreCount(1, 1) == 1;
}

static bool test_serialize_count_many_blocks()
{
	return BtPieceHashSerializeStoreCount(100, 100) == 100;
}

static bool test_serialize_prefers_vector_when_count_stale()
{
	// Clear() bug class: empty vector but non-zero count.
	return BtPieceHashSerializeStoreCount(10, 0) == 0;
}

static bool test_serialize_vector_larger_than_count()
{
	return BtPieceHashSerializeStoreCount(2, 5) == 5;
}

static bool test_declared_count_max_valid()
{
	return BtPieceHashDeclaredCountValid(BTINFO_MAX_PIECE_COUNT);
}

static bool test_declared_count_over_max_invalid()
{
	return !BtPieceHashDeclaredCountValid(BTINFO_MAX_PIECE_COUNT + 1);
}

static bool test_total_bytes_zero()
{
	size_t n = 99;
	return BtPieceHashTotalBytes(0, n) && n == 0;
}

static bool test_total_bytes_one()
{
	size_t n = 0;
	return BtPieceHashTotalBytes(1, n) && n == BTINFO_PIECE_HASH_BYTES;
}

static bool test_total_bytes_over_max_rejected()
{
	size_t n = 0;
	return !BtPieceHashTotalBytes(0xFFFFFFFFu, n);
}

static bool test_load_commit_consistent()
{
	return BtPieceHashReadyToCommit(3, 3);
}

static bool test_load_commit_rejects_count_vector_mismatch()
{
	return !BtPieceHashReadyToCommit(3, 2);
}

static bool test_load_commit_rejects_over_max()
{
	return !BtPieceHashReadyToCommit(BTINFO_MAX_PIECE_COUNT + 1, BTINFO_MAX_PIECE_COUNT + 1);
}

static bool test_block_index_in_range_consistent()
{
	return BtPieceHashBlockIndexInRange(4, 4, 3) && !BtPieceHashBlockIndexInRange(4, 4, 4);
}

static bool test_block_index_uses_vector_when_stale_count()
{
	return BtPieceHashBlockIndexInRange(99, 2, 1) && !BtPieceHashBlockIndexInRange(99, 2, 2);
}

static bool test_truncated_load_class_rejected()
{
	// Declared 5 hashes but only 3 vector entries are present — commit must fail.
	return !BtPieceHashReadyToCommit(5, 3);
}

static bool test_reuse_after_clear_metadata()
{
	uint32_t count = 7;
	uint32_t blockSize = 16384;
	size_t vec = 7;
	if (BtPieceHashClearStateValid(count, blockSize, vec))
		return false;

	count = 0;
	blockSize = 0;
	vec = 0;
	return BtPieceHashClearStateValid(count, blockSize, vec);
}

void register_btinfo_piece_hash_smoke_tests(TestSuite& suite)
{
	suite.add_test("BTInfo piece hash clear state valid", test_clear_state_valid);
	suite.add_test("BTInfo piece hash clear rejects stale count", test_clear_state_rejects_stale_count);
	suite.add_test("BTInfo piece hash serialize count zero", test_serialize_count_zero_blocks);
	suite.add_test("BTInfo piece hash serialize count one", test_serialize_count_one_block);
	suite.add_test("BTInfo piece hash serialize count many", test_serialize_count_many_blocks);
	suite.add_test("BTInfo piece hash serialize prefers vector over stale count", test_serialize_prefers_vector_when_count_stale);
	suite.add_test("BTInfo piece hash serialize vector larger than count", test_serialize_vector_larger_than_count);
	suite.add_test("BTInfo piece hash max piece count valid", test_declared_count_max_valid);
	suite.add_test("BTInfo piece hash over max piece count invalid", test_declared_count_over_max_invalid);
	suite.add_test("BTInfo piece hash total bytes zero", test_total_bytes_zero);
	suite.add_test("BTInfo piece hash total bytes one block", test_total_bytes_one);
	suite.add_test("BTInfo piece hash total bytes over max rejected", test_total_bytes_over_max_rejected);
	suite.add_test("BTInfo piece hash load commit consistent", test_load_commit_consistent);
	suite.add_test("BTInfo piece hash load commit rejects mismatch", test_load_commit_rejects_count_vector_mismatch);
	suite.add_test("BTInfo piece hash load commit rejects over max", test_load_commit_rejects_over_max);
	suite.add_test("BTInfo piece hash block index in range", test_block_index_in_range_consistent);
	suite.add_test("BTInfo piece hash block index uses vector when count stale", test_block_index_uses_vector_when_stale_count);
	suite.add_test("BTInfo piece hash truncated load rejected", test_truncated_load_class_rejected);
	suite.add_test("BTInfo piece hash reuse after clear metadata", test_reuse_after_clear_metadata);
}
