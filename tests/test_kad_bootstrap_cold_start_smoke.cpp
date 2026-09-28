//
// test_kad_bootstrap_cold_start_smoke.cpp
//
// Policy tests for Kad cold-start nodes.dat validation helpers.
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//

#include "test_framework.h"

#include <windows.h>

#define KAD_BOOTSTRAP_TEST_HEADER_ONLY
#include "../Envy/KadBootstrapColdStart.h"
#include "../Envy/KadNodesDat.h"

#include <array>
#include <cstring>
#include <string>
#include <vector>

namespace
{

const uint8_t kId1[16] = {
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10
};

void PushU32LE(std::vector<uint8_t>& o, uint32_t v)
{
	o.push_back(static_cast<uint8_t>(v & 0xFF));
	o.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
	o.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
	o.push_back(static_cast<uint8_t>((v >> 24) & 0xFF));
}

void PushU16LE(std::vector<uint8_t>& o, uint16_t v)
{
	o.push_back(static_cast<uint8_t>(v & 0xFF));
	o.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
}

void PushIp(std::vector<uint8_t>& o, uint8_t a, uint8_t b, uint8_t c, uint8_t d)
{
	o.push_back(a);
	o.push_back(b);
	o.push_back(c);
	o.push_back(d);
}

std::vector<uint8_t> MakeGoldenV1OneContact()
{
	std::vector<uint8_t> o;
	PushU32LE(o, 0);
	PushU32LE(o, 1);
	PushU32LE(o, 1);
	o.insert(o.end(), kId1, kId1 + 16);
	PushIp(o, 203, 0, 113, 5);
	PushU16LE(o, 4672);
	PushU16LE(o, 4662);
	o.push_back(8);
	return o;
}

bool WriteBinaryFile(const std::wstring& path, const std::vector<uint8_t>& data)
{
	HANDLE h = CreateFileW(
	    path.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (h == INVALID_HANDLE_VALUE)
		return false;
	DWORD written = 0;
	const BOOL ok = WriteFile(h, data.data(), static_cast<DWORD>(data.size()), &written, NULL);
	CloseHandle(h);
	return ok && written == data.size();
}

bool ReadBinaryFile(const std::wstring& path, std::vector<uint8_t>& out)
{
	out.clear();
	HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
	                       FILE_ATTRIBUTE_NORMAL, NULL);
	if (h == INVALID_HANDLE_VALUE)
		return false;
	const DWORD nSize = GetFileSize(h, NULL);
	if (nSize == INVALID_FILE_SIZE)
	{
		CloseHandle(h);
		return false;
	}
	out.resize(nSize);
	DWORD read = 0;
	const BOOL ok = ReadFile(h, out.data(), nSize, &read, NULL);
	CloseHandle(h);
	return ok && read == nSize;
}

std::wstring MakeTempBootstrapDir()
{
	wchar_t tempPath[MAX_PATH] = {};
	if (GetTempPathW(MAX_PATH, tempPath) == 0)
		return L"";
	wchar_t dir[MAX_PATH] = {};
	if (GetTempFileNameW(tempPath, L"ekb", 0, dir) == 0)
		return L"";
	DeleteFileW(dir);
	if (!CreateDirectoryW(dir, NULL))
		return L"";
	return dir;
}

bool CommitCandidateLikeProduction(
    bool bHadPrior,
    const std::wstring& strFile,
    const std::wstring& strTemp,
    const std::wstring& strLkg,
    const std::vector<uint8_t>& candidate)
{
	if (!WriteBinaryFile(strTemp, candidate))
		return false;
	if (bHadPrior && !CopyFileW(strFile.c_str(), strLkg.c_str(), FALSE))
	{
		DeleteFileW(strTemp.c_str());
		return false;
	}
	if (!MoveFileExW(strTemp.c_str(), strFile.c_str(), MOVEFILE_REPLACE_EXISTING))
	{
		DeleteFileW(strTemp.c_str());
		return false;
	}
	return true;
}

void CleanupBootstrapDir(const std::wstring& dir)
{
	DeleteFileW((dir + L"\\nodes.dat").c_str());
	DeleteFileW((dir + L"\\nodes.dat.tmp").c_str());
	DeleteFileW((dir + L"\\nodes.dat.lkg").c_str());
	RemoveDirectoryW(dir.c_str());
}

} // namespace

static bool test_backoff_monotonic()
{
	const uint32_t a0 = KadBootstrapBackoffMs(0, 1000, 60000);
	const uint32_t a1 = KadBootstrapBackoffMs(1, 1000, 60000);
	const uint32_t a2 = KadBootstrapBackoffMs(2, 1000, 60000);
	const uint32_t a3 = KadBootstrapBackoffMs(3, 1000, 60000);
	return a0 == 0 && a1 == 1000 && a2 == 2000 && a3 == 4000;
}

static bool test_backoff_cap()
{
	return KadBootstrapBackoffMs(10, 1000, 5000) == 5000;
}

static bool test_tick_wrap_elapsed()
{
	const uint32_t dwDeadline = 0xFFFFFFF0u;
	const uint32_t dwNowBefore = 0xFFFFFF00u;
	const uint32_t dwNowAfter = 0x00000020u;
	return !KadBootstrapTickElapsed(dwNowBefore, dwDeadline)
		&& KadBootstrapTickElapsed(dwNowAfter, dwDeadline);
}

static bool test_validate_rejects_empty()
{
	KadNodesDatResult r = {};
	return KadBootstrapValidateDownloadedBody(nullptr, 0, &r) == KadBootstrapAcquireEmptyBody;
}

static bool test_validate_rejects_oversized()
{
	std::array<uint8_t, 8> tiny = {};
	KadNodesDatResult r = {};
	const uint32_t fakeLen = KadBootstrapHttpMaxBytes() + 1u;
	return KadBootstrapValidateDownloadedBody(tiny.data(), fakeLen, &r) == KadBootstrapAcquireOversized;
}

static bool test_validate_accepts_golden_v1()
{
	const std::vector<uint8_t> body = MakeGoldenV1OneContact();
	KadNodesDatResult r = {};
	return KadBootstrapValidateDownloadedBody(body.data(), static_cast<uint32_t>(body.size()), &r)
		== KadBootstrapAcquireOk && r.acceptedCount >= 1;
}

static bool test_validate_rejects_truncated()
{
	std::vector<uint8_t> body = MakeGoldenV1OneContact();
	body.resize(body.size() - 4);
	KadNodesDatResult r = {};
	return KadBootstrapValidateDownloadedBody(body.data(), static_cast<uint32_t>(body.size()), &r)
		== KadBootstrapAcquireParseFailed;
}

static bool test_validate_max_plus_one_rejected()
{
	std::vector<uint8_t> body = MakeGoldenV1OneContact();
	KadNodesDatResult r = {};
	const uint32_t nLen = KadBootstrapHttpMaxBytes() + 1u;
	return KadBootstrapValidateDownloadedBody(body.data(), nLen, &r) == KadBootstrapAcquireOversized;
}

static bool test_phase_no_contacts_maps_to_contacts_rejected()
{
	return KadBootstrapPhaseFromAcquireResult(KadBootstrapAcquireNoAcceptedContacts)
		== KadBootstrapPhaseContactsRejected;
}

static bool test_restore_prior_nodes_dat_byte_for_byte()
{
	const std::wstring dir = MakeTempBootstrapDir();
	if (dir.empty())
		return false;
	const std::wstring file = dir + L"\\nodes.dat";
	const std::wstring temp = file + L".tmp";
	const std::wstring lkg = file + L".lkg";
	const std::vector<uint8_t> prior = { 'o', 'l', 'd', '-', 'b', 'o', 'o', 't' };
	const std::vector<uint8_t> candidate = MakeGoldenV1OneContact();
	if (!WriteBinaryFile(file, prior))
		return false;
	if (!CommitCandidateLikeProduction(true, file, temp, lkg, candidate))
		return false;
	if (!KadBootstrapRestoreNodesDatAfterRejectedImport(true, file.c_str(), lkg.c_str()))
		return false;
	std::vector<uint8_t> restored;
	if (!ReadBinaryFile(file, restored) || restored != prior)
		return false;
	CleanupBootstrapDir(dir);
	return true;
}

static bool test_restore_without_prior_deletes_rejected_candidate()
{
	const std::wstring dir = MakeTempBootstrapDir();
	if (dir.empty())
		return false;
	const std::wstring file = dir + L"\\nodes.dat";
	const std::wstring temp = file + L".tmp";
	const std::wstring lkg = file + L".lkg";
	const std::vector<uint8_t> candidate = MakeGoldenV1OneContact();
	if (!CommitCandidateLikeProduction(false, file, temp, lkg, candidate))
		return false;
	if (!KadBootstrapRestoreNodesDatAfterRejectedImport(false, file.c_str(), lkg.c_str()))
		return false;
	if (GetFileAttributesW(file.c_str()) != INVALID_FILE_ATTRIBUTES)
		return false;
	CleanupBootstrapDir(dir);
	return true;
}

static bool test_restore_failure_when_lkg_missing()
{
	const std::wstring dir = MakeTempBootstrapDir();
	if (dir.empty())
		return false;
	const std::wstring file = dir + L"\\nodes.dat";
	const std::wstring temp = file + L".tmp";
	const std::wstring lkg = file + L".lkg";
	const std::vector<uint8_t> prior = { 1, 2, 3 };
	const std::vector<uint8_t> candidate = MakeGoldenV1OneContact();
	if (!WriteBinaryFile(file, prior))
		return false;
	if (!CommitCandidateLikeProduction(true, file, temp, lkg, candidate))
		return false;
	DeleteFileW(lkg.c_str());
	if (KadBootstrapRestoreNodesDatAfterRejectedImport(true, file.c_str(), lkg.c_str()))
		return false;
	CleanupBootstrapDir(dir);
	return true;
}

static bool test_successful_commit_keeps_candidate_without_restore()
{
	const std::wstring dir = MakeTempBootstrapDir();
	if (dir.empty())
		return false;
	const std::wstring file = dir + L"\\nodes.dat";
	const std::wstring temp = file + L".tmp";
	const std::wstring lkg = file + L".lkg";
	const std::vector<uint8_t> prior = { 'o', 'l', 'd' };
	const std::vector<uint8_t> candidate = MakeGoldenV1OneContact();
	if (!WriteBinaryFile(file, prior))
		return false;
	if (!CommitCandidateLikeProduction(true, file, temp, lkg, candidate))
		return false;
	std::vector<uint8_t> active;
	if (!ReadBinaryFile(file, active) || active != candidate)
		return false;
	CleanupBootstrapDir(dir);
	return true;
}

void register_kad_bootstrap_cold_start_smoke_tests(TestSuite& suite)
{
	suite.add_test("kad_bootstrap_backoff_monotonic", test_backoff_monotonic);
	suite.add_test("kad_bootstrap_backoff_cap", test_backoff_cap);
	suite.add_test("kad_bootstrap_tick_wrap", test_tick_wrap_elapsed);
	suite.add_test("kad_bootstrap_validate_empty", test_validate_rejects_empty);
	suite.add_test("kad_bootstrap_validate_oversized", test_validate_rejects_oversized);
	suite.add_test("kad_bootstrap_validate_golden_v1", test_validate_accepts_golden_v1);
	suite.add_test("kad_bootstrap_validate_truncated", test_validate_rejects_truncated);
	suite.add_test("kad_bootstrap_validate_max_plus_one", test_validate_max_plus_one_rejected);
	suite.add_test("kad_bootstrap_phase_no_contacts", test_phase_no_contacts_maps_to_contacts_rejected);
	suite.add_test("kad_bootstrap_restore_prior_nodes_dat", test_restore_prior_nodes_dat_byte_for_byte);
	suite.add_test("kad_bootstrap_restore_no_prior_deletes_candidate", test_restore_without_prior_deletes_rejected_candidate);
	suite.add_test("kad_bootstrap_restore_fails_without_lkg", test_restore_failure_when_lkg_missing);
	suite.add_test("kad_bootstrap_commit_keeps_candidate_on_success", test_successful_commit_keeps_candidate_without_restore);
}
