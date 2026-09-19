//
// test_dc_nmdc_text_smoke.cpp
//
// Smoke tests for NMDC hub text encode/decode (#224).
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//

#include "test_framework.h"
#include "../Envy/DcNmdcText.h"
#include "../Envy/DcPacketLengthValidate.h"

#include <cstring>

static bool test_dc_resolve_zero_is_acp()
{
	return DcResolveNmdcCodePage(0) == CP_ACP && DcResolveNmdcCodePage(1251) == 1251 && DcResolveNmdcCodePage(CP_UTF8) == CP_UTF8;
}

static bool test_dc_resolve_invalid_falls_back_to_acp()
{
	// 6501 is not a valid Windows code page (UTF-8 is 65001).
	return DcResolveNmdcCodePage(6501) == CP_ACP && DecodeNmdcText("AB", 2, 6501) == L"AB";
}

static bool test_dc_nmdc_ascii_roundtrip()
{
	const char kAscii[] = "HubName ASCII";
	const std::wstring w = DecodeNmdcText(kAscii, (int)sizeof(kAscii) - 1, CP_UTF8);
	if (w != L"HubName ASCII")
		return false;
	const std::string round = EncodeNmdcText(w.c_str(), CP_UTF8);
	return round == kAscii;
}

static bool test_dc_nmdc_utf8_cyrillic()
{
	// U+041F U+0440 U+0438 U+0432 U+0435 U+0442 = "Privet" in Cyrillic
	const char kUtf8[] = "\xD0\x9F\xD1\x80\xD0\xB8\xD0\xB2\xD0\xB5\xD1\x82";
	const std::wstring w = DecodeNmdcText(kUtf8, (int)sizeof(kUtf8) - 1, CP_UTF8);
	if (w != L"\x041F\x0440\x0438\x0432\x0435\x0442")
		return false;
	const std::string round = EncodeNmdcText(w.c_str(), CP_UTF8);
	return round == std::string(kUtf8, sizeof(kUtf8) - 1);
}

static bool test_dc_nmdc_cp1251_roundtrip()
{
	// CP1251 bytes for "Привет"
	const char kCp1251[] = "\xCF\xF0\xE8\xE2\xE5\xF2";
	const std::wstring w = DecodeNmdcText(kCp1251, (int)sizeof(kCp1251) - 1, 1251);
	if (w != L"\x041F\x0440\x0438\x0432\x0435\x0442")
		return false;
	const std::string round = EncodeNmdcText(w.c_str(), 1251);
	return round == std::string(kCp1251, sizeof(kCp1251) - 1);
}

static bool test_dc_nmdc_wrong_charset_not_silent_utf8()
{
	const char kCp1251[] = "\xCF\xF0\xE8\xE2\xE5\xF2";
	const std::wstring asLegacy = DecodeNmdcText(kCp1251, (int)sizeof(kCp1251) - 1, 1251);
	const std::wstring asUtf8 = DecodeNmdcText(kCp1251, (int)sizeof(kCp1251) - 1, CP_UTF8);
	return asLegacy == L"\x041F\x0440\x0438\x0432\x0435\x0442" && asUtf8 != asLegacy;
}

static bool test_dc_nmdc_explicit_length_ignores_trailer()
{
	const char kBuf[] = "AB\xCF\xF0"
	                    "XX";
	// Only first 2 bytes ("AB")
	const std::wstring w = DecodeNmdcText(kBuf, 2, 1251);
	return w == L"AB";
}

static bool test_dc_nmdc_empty_length()
{
	const char kBuf[] = "x";
	return DecodeNmdcText(kBuf, 0, 1251).empty() && DecodeNmdcText(nullptr, 5, 1251).empty() && EncodeNmdcText(L"", 1251).empty() && EncodeNmdcText(nullptr, 1251).empty();
}

static bool test_dc_nmdc_unrepresentable_becomes_question()
{
	// U+4E2D (CJK) is not in CP1252; encode policy substitutes '?'
	const std::string enc = EncodeNmdcText(L"\x4E2D", 1252);
	return enc.size() == 1 && enc[0] == '?';
}

static bool test_dc_nmdc_hubname_fixture_cp1251()
{
	// "$HubName " + CP1251 title + "|"
	const char kTitle[] = "\xCF\xF0\xE8\xE2\xE5\xF2";
	char frame[64];
	const char kPrefix[] = "$HubName ";
	std::memcpy(frame, kPrefix, sizeof(kPrefix) - 1);
	std::memcpy(frame + (sizeof(kPrefix) - 1), kTitle, sizeof(kTitle) - 1);
	frame[sizeof(kPrefix) - 1 + sizeof(kTitle) - 1] = '|';
	const DWORD nLength = static_cast<DWORD>(sizeof(kPrefix) - 1 + sizeof(kTitle) - 1 + 1);
	if (!DcPrefixedPayloadLengthOk(nLength, DC_HUBNAME_PREFIX_LEN))
		return false;
	const DWORD nBytes = DcPrefixedPayloadBytes(nLength, DC_HUBNAME_PREFIX_LEN);
	const std::wstring name = DecodeNmdcText(frame + DC_HUBNAME_PREFIX_LEN, static_cast<int>(nBytes), 1251);
	return name == L"\x041F\x0440\x0438\x0432\x0435\x0442";
}

static bool test_dc_nmdc_myinfo_nick_fixture_cp1251()
{
	const char kNick[] = "\xC1\xEE\xF2"; // "Бот" in CP1251
	const std::wstring nick = DecodeNmdcText(kNick, (int)sizeof(kNick) - 1, 1251);
	return nick == L"\x0411\x043E\x0442";
}

static bool test_dc_nmdc_chat_fixture_cp1251()
{
	// "<nick> msg" payload after leading '<'
	const char kPayload[] = "\xC1\xEE\xF2> \xCF\xF0\xE8\xE2\xE5\xF2";
	const std::wstring msg = DecodeNmdcText(kPayload, (int)sizeof(kPayload) - 1, 1251);
	return msg.find(L"\x0411\x043E\x0442>") == 0 && msg.find(L"\x041F\x0440\x0438\x0432\x0435\x0442") != std::wstring::npos;
}

static bool test_dc_nmdc_ascii_regression_unchanged()
{
	const char kHub[] = "Public Hub";
	const std::wstring wAcp = DecodeNmdcText(kHub, (int)sizeof(kHub) - 1, 0);
	const std::wstring wUtf = DecodeNmdcText(kHub, (int)sizeof(kHub) - 1, CP_UTF8);
	return wAcp == L"Public Hub" && wUtf == L"Public Hub" && EncodeNmdcText(L"Public Hub", 0) == kHub;
}

void register_dc_nmdc_text_smoke_tests(TestSuite& suite)
{
	suite.add_test("dc_resolve_zero_is_acp", test_dc_resolve_zero_is_acp);
	suite.add_test("dc_resolve_invalid_falls_back_to_acp", test_dc_resolve_invalid_falls_back_to_acp);
	suite.add_test("dc_nmdc_ascii_roundtrip", test_dc_nmdc_ascii_roundtrip);
	suite.add_test("dc_nmdc_utf8_cyrillic", test_dc_nmdc_utf8_cyrillic);
	suite.add_test("dc_nmdc_cp1251_roundtrip", test_dc_nmdc_cp1251_roundtrip);
	suite.add_test("dc_nmdc_wrong_charset_not_silent_utf8", test_dc_nmdc_wrong_charset_not_silent_utf8);
	suite.add_test("dc_nmdc_explicit_length_ignores_trailer", test_dc_nmdc_explicit_length_ignores_trailer);
	suite.add_test("dc_nmdc_empty_length", test_dc_nmdc_empty_length);
	suite.add_test("dc_nmdc_unrepresentable_becomes_question", test_dc_nmdc_unrepresentable_becomes_question);
	suite.add_test("dc_nmdc_hubname_fixture_cp1251", test_dc_nmdc_hubname_fixture_cp1251);
	suite.add_test("dc_nmdc_myinfo_nick_fixture_cp1251", test_dc_nmdc_myinfo_nick_fixture_cp1251);
	suite.add_test("dc_nmdc_chat_fixture_cp1251", test_dc_nmdc_chat_fixture_cp1251);
	suite.add_test("dc_nmdc_ascii_regression_unchanged", test_dc_nmdc_ascii_regression_unchanged);
}
