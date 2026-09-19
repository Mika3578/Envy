//
// test_ed2k_lowid_callback_smoke.cpp
//
// Deterministic smoke tests for ED2K PUBLICIP / C2C CALLBACK / LowID identity
// helpers (#87 phase-1). No live network / MFC client.
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//

#include "test_framework.h"
#include "../Envy/Ed2kLowIdCallback.h"

#include <string.h>

// ---- PUBLICIP ----

static bool test_publicip_req_empty_ok()
{
	return Ed2kPublicIpReqPayloadOk(0) == TRUE && Ed2kPublicIpReqPayloadOk(1) == FALSE;
}

static bool test_publicip_answer_exact_4()
{
	return Ed2kPublicIpAnswerPayloadOk(4) == TRUE && Ed2kPublicIpAnswerPayloadOk(0) == FALSE && Ed2kPublicIpAnswerPayloadOk(1) == FALSE && Ed2kPublicIpAnswerPayloadOk(3) == FALSE && Ed2kPublicIpAnswerPayloadOk(5) == FALSE;
}

static bool test_publicip_answer_byte_order()
{
	// 1.2.3.4 as sockaddr s_addr on LE = 0x04030201 → wire bytes 01 02 03 04
	BYTE encoded[4] = {};
	if (!Ed2kPublicIpAnswerEncode(0x04030201u, encoded))
		return false;
	if (encoded[0] != 0x01 || encoded[1] != 0x02 || encoded[2] != 0x03 || encoded[3] != 0x04)
		return false;

	DWORD nDecoded = 0;
	if (!Ed2kPublicIpAnswerDecode(encoded, 4, &nDecoded))
		return false;
	return nDecoded == 0x04030201u;
}

static bool test_publicip_answer_truncated_decode()
{
	BYTE raw[3] = { 1, 2, 3 };
	DWORD nIp = 0xFFFFFFFFu;
	return Ed2kPublicIpAnswerDecode(raw, 3, &nIp) == FALSE && Ed2kPublicIpAnswerDecode(raw, 0, &nIp) == FALSE;
}

static bool test_publicip_unsolicited_rejected()
{
	return Ed2kPublicIpAnswerMayApply(FALSE, 0, 0x04030201u) == FALSE;
}

static bool test_publicip_duplicate_after_known_ip()
{
	return Ed2kPublicIpAnswerMayApply(TRUE, 0x08080808u, 0x04030201u) == FALSE;
}

static bool test_publicip_lowid_shaped_rejected()
{
	// LowID-shaped dword must not become a public IP
	return Ed2kPublicIpAnswerMayApply(TRUE, 0, 5u) == FALSE;
}

static bool test_publicip_query_state_consume_and_expire()
{
	Ed2kPublicIpQueryState st;
	st.MarkRequested(1000);
	if (!st.bOutstanding || st.bConsumed)
		return false;
	if (st.TryConsumeAnswer(1000 + Ed2kPublicIpQueryTimeoutMs() + 1))
		return false; // expired
	st.MarkRequested(2000);
	if (!st.TryConsumeAnswer(2100))
		return false;
	if (st.bOutstanding || !st.bConsumed)
		return false;
	if (st.TryConsumeAnswer(2200)) // duplicate
		return false;
	st.OnDisconnect();
	return !st.bOutstanding && !st.bConsumed;
}

// ---- CALLBACK ----

static bool test_callback_exact_38()
{
	return Ed2kC2cCallbackExactBytes() == 38u && Ed2kC2cCallbackPayloadOk(38) == TRUE && Ed2kC2cCallbackPayloadOk(34) == FALSE && Ed2kC2cCallbackPayloadOk(0) == FALSE && Ed2kC2cCallbackPayloadOk(39) == FALSE;
}

static bool test_callback_parse_valid_and_truncations()
{
	BYTE raw[38] = {};
	for (int i = 0; i < 16; ++i)
		raw[i] = (BYTE)(0xA0 + i); // kad check
	for (int i = 0; i < 16; ++i)
		raw[16 + i] = (BYTE)(0x10 + i); // file hash
	raw[32] = 0x01;
	raw[33] = 0x02;
	raw[34] = 0x03;
	raw[35] = 0x04; // IP LE
	raw[36] = 0x36;
	raw[37] = 0x12; // port 0x1236 LE

	Ed2kC2cCallbackFields f = {};
	if (!Ed2kC2cCallbackParse(raw, 38, &f))
		return false;
	if (f.nIp != 0x04030201u || f.nTcpPort != 0x1236)
		return false;
	if (memcmp(f.fileHash, raw + 16, 16) != 0)
		return false;

	// Truncation at every field boundary
	for (DWORD n = 0; n < 38; ++n)
	{
		if (Ed2kC2cCallbackParse(raw, n, &f))
			return false;
	}
	return true;
}

static bool test_callback_kad_xor_match()
{
	BYTE own[16] = {};
	for (int i = 0; i < 16; ++i)
		own[i] = (BYTE)(i + 1);
	BYTE check[16];
	memcpy(check, own, 16);
	Ed2kXorKadIdWithOnes(check);
	if (!Ed2kCallbackKadIdMatches(check, own))
		return false;
	check[0] ^= 0x01;
	return Ed2kCallbackKadIdMatches(check, own) == FALSE;
}

static bool test_callback_zero_port_and_bad_ip()
{
	return Ed2kCallbackEndpointOk(0x04030201u, 0) == FALSE && Ed2kCallbackEndpointOk(0, 4662) == FALSE && Ed2kCallbackEndpointOk(0xFFFFFFFFu, 4662) == FALSE && Ed2kCallbackEndpointOk(5u, 4662) == FALSE // LowID-shaped
	       && Ed2kCallbackEndpointOk(0x04030201u, 4662) == TRUE;
}

static bool test_callback_empty_file_hash()
{
	BYTE zeros[16] = {};
	BYTE nonzero[16] = { 1 };
	return Ed2kCallbackFileHashNonEmpty(zeros) == FALSE && Ed2kCallbackFileHashNonEmpty(nonzero) == TRUE;
}

static bool test_callback_consume_duplicate_and_unrelated()
{
	Ed2kC2cCallbackConsumeGuard g;
	BYTE hashA[16] = { 1, 2, 3 };
	BYTE hashB[16] = { 9, 8, 7 };
	const DWORD ipA = 0x04030201u;
	const DWORD ipB = 0x08080808u;

	if (!g.TryConsumeOnce(1000, ipA, 4662, hashA))
		return false;
	if (g.TryConsumeOnce(1100, ipA, 4662, hashA)) // duplicate
		return false;
	if (!g.TryConsumeOnce(1200, ipB, 4662, hashB)) // unrelated peer/file OK
		return false;

	// Expired window clears and allows reuse of prior target
	g.Clear();
	g.TryConsumeOnce(2000, ipA, 4662, hashA);
	if (g.IsExpired(2000 + Ed2kC2cCallbackPendingTimeoutMs() + 1))
		g.Clear();
	return g.TryConsumeOnce(2000 + Ed2kC2cCallbackPendingTimeoutMs() + 2, ipA, 4662, hashA) == TRUE;
}

static bool test_callback_disconnect_clears()
{
	Ed2kC2cCallbackConsumeGuard g;
	BYTE hash[16] = { 1 };
	g.TryConsumeOnce(1, 0x04030201u, 1, hash);
	g.OnDisconnect();
	return g.bArmed == FALSE && g.bConsumed == FALSE;
}

// ---- LowID identity / classic server callback ----

static bool test_server_callback_requested_parse()
{
	BYTE raw[6] = { 0x01, 0x02, 0x03, 0x04, 0x36, 0x12 };
	DWORD nIp = 0;
	WORD nPort = 0;
	if (!Ed2kServerCallbackRequestedParse(raw, 6, &nIp, &nPort))
		return false;
	if (nIp != 0x04030201u || nPort != 0x1236)
		return false;
	return Ed2kServerCallbackRequestedParse(raw, 5, &nIp, &nPort) == FALSE;
}

static bool test_lowid_connect_uses_server_push()
{
	return Ed2kLowIdConnectUsesServerPush(12345u) == TRUE && Ed2kLowIdConnectUsesServerPush(0x04030201u) == FALSE;
}

static bool test_lowid_same_id_different_server_no_collide()
{
	const DWORD nId = 100u;
	const DWORD nSrvA = 0x01010101u;
	const DWORD nSrvB = 0x02020202u;
	if (Ed2kLowIdPeersEqual(nId, nSrvA, nId, nSrvA) != TRUE)
		return false;
	if (Ed2kLowIdPeersEqual(nId, nSrvA, nId, nSrvB) != FALSE)
		return false;
	return Ed2kLowIdSameIdDifferentServerCollide(nId, nSrvA, nId, nSrvB) == TRUE;
}

static bool test_reask_min_bytes_documented()
{
	return Ed2kReaskCallbackTcpMinBytes() == 22u;
}

void register_ed2k_lowid_callback_smoke_tests(TestSuite& suite)
{
	suite.add_test("ed2k_publicip_req_empty", test_publicip_req_empty_ok);
	suite.add_test("ed2k_publicip_answer_exact_4", test_publicip_answer_exact_4);
	suite.add_test("ed2k_publicip_answer_byte_order", test_publicip_answer_byte_order);
	suite.add_test("ed2k_publicip_answer_truncated", test_publicip_answer_truncated_decode);
	suite.add_test("ed2k_publicip_unsolicited", test_publicip_unsolicited_rejected);
	suite.add_test("ed2k_publicip_known_ip_blocks", test_publicip_duplicate_after_known_ip);
	suite.add_test("ed2k_publicip_lowid_shaped", test_publicip_lowid_shaped_rejected);
	suite.add_test("ed2k_publicip_query_state", test_publicip_query_state_consume_and_expire);
	suite.add_test("ed2k_callback_exact_38", test_callback_exact_38);
	suite.add_test("ed2k_callback_parse_truncations", test_callback_parse_valid_and_truncations);
	suite.add_test("ed2k_callback_kad_xor", test_callback_kad_xor_match);
	suite.add_test("ed2k_callback_endpoint", test_callback_zero_port_and_bad_ip);
	suite.add_test("ed2k_callback_file_hash", test_callback_empty_file_hash);
	suite.add_test("ed2k_callback_consume_guard", test_callback_consume_duplicate_and_unrelated);
	suite.add_test("ed2k_callback_disconnect_clear", test_callback_disconnect_clears);
	suite.add_test("ed2k_server_callback_parse", test_server_callback_requested_parse);
	suite.add_test("ed2k_lowid_uses_server_push", test_lowid_connect_uses_server_push);
	suite.add_test("ed2k_lowid_identity_no_collide", test_lowid_same_id_different_server_no_collide);
	suite.add_test("ed2k_reask_min_bytes", test_reask_min_bytes_documented);
}
