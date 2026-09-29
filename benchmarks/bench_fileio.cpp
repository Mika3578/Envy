//
// bench_fileio.cpp
//
// Baseline sequential temp-file I/O (no TransferFiles / locking).
// Read workloads prepare input files in setup (outside timing) and only
// measure sequential reads in the timed path.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

#include "StdAfx.h"

#include "bench_harness.h"

#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <memory>
#include <string>
#include <vector>

namespace
{

bool BenchPathIsReparsePoint(const std::filesystem::path& path);
bool BenchPathHasNoReparseAncestors(const std::filesystem::path& path);
bool BenchExistingAncestorsSafeBeforeCreate(const std::filesystem::path& path);

std::filesystem::path BenchScratchRoot()
{
	wchar_t local_app_data[MAX_PATH] = {};
	const DWORD length = GetEnvironmentVariableW(L"LOCALAPPDATA", local_app_data, MAX_PATH);
	if (length == 0 || length >= MAX_PATH)
		return {};
	if (!BenchPathHasNoReparseAncestors(std::filesystem::path(local_app_data)))
		return {};

	std::filesystem::path root =
		std::filesystem::path(local_app_data) / L"Envy" / L"BenchmarkScratch";
	if (!BenchExistingAncestorsSafeBeforeCreate(root))
		return {};
	std::error_code ec;
	std::filesystem::create_directories(root, ec);
	if (ec)
		return {};
	if (!BenchPathHasNoReparseAncestors(root))
		return {};
	return root;
}

std::filesystem::path BenchUniqueWorkloadRoot(const std::filesystem::path& scratch_root,
                                              const wchar_t* label)
{
	const std::wstring leaf = std::wstring(label) + L"-" + std::to_wstring(GetTickCount64()) +
	                          L"-" + std::to_wstring(GetCurrentProcessId());
	return scratch_root / leaf;
}

std::vector<std::uint8_t> MakePayload(std::size_t size)
{
	std::vector<std::uint8_t> data(size);
	for (std::size_t i = 0; i < size; ++i)
		data[i] = static_cast<std::uint8_t>((i * 17u) & 0xFFu);
	return data;
}

void ReportFileIoFailure(const char* detail)
{
	std::fprintf(stderr, "fileio workload failure: %s\n", detail);
}

bool BenchPathIsReparsePoint(const std::filesystem::path& path)
{
	const DWORD attr = GetFileAttributesW(path.c_str());
	if (attr == INVALID_FILE_ATTRIBUTES)
		return false;
	return (attr & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
}

bool BenchPathHasNoReparseAncestors(const std::filesystem::path& path)
{
	if (path.empty())
		return false;

	std::filesystem::path current;
	for (const auto& part : path)
	{
		current /= part;
		if (BenchPathIsReparsePoint(current))
			return false;
	}
	return true;
}

bool BenchExistingAncestorsSafeBeforeCreate(const std::filesystem::path& path)
{
	if (path.empty())
		return false;

	std::filesystem::path current;
	for (const auto& part : path)
	{
		current /= part;
		std::error_code ec;
		if (!std::filesystem::exists(current, ec) || ec)
			continue;
		if (BenchPathIsReparsePoint(current))
			return false;
	}
	return BenchPathHasNoReparseAncestors(path);
}

bool BenchPathConfinedUnder(const std::filesystem::path& root, const std::filesystem::path& candidate)
{
	std::error_code ec;
	const auto root_canon = std::filesystem::weakly_canonical(root, ec);
	if (ec)
		return false;
	const auto file_canon = std::filesystem::weakly_canonical(candidate, ec);
	if (ec)
		return false;
	const auto root_prefix = root_canon.native();
	const auto file_prefix = file_canon.native();
	if (file_prefix.size() < root_prefix.size())
		return false;
	if (file_prefix.compare(0, root_prefix.size(), root_prefix) != 0)
		return false;
	if (file_prefix.size() > root_prefix.size())
	{
		const wchar_t next = file_prefix[root_prefix.size()];
		if (next != L'\\' && next != L'/')
			return false;
	}
	return true;
}

bool BenchWritePayloadExclusive(const std::filesystem::path& path,
                                const std::vector<std::uint8_t>& payload)
{
	if (BenchPathIsReparsePoint(path))
		return false;

	const HANDLE hFile = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
	                                 FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
	                                 nullptr);
	if (hFile == INVALID_HANDLE_VALUE)
		return false;

	BY_HANDLE_FILE_INFORMATION info{};
	if (!GetFileInformationByHandle(hFile, &info) ||
	    (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
	{
		CloseHandle(hFile);
		DeleteFileW(path.c_str());
		return false;
	}

	DWORD written = 0;
	const BOOL ok = WriteFile(hFile, payload.data(), static_cast<DWORD>(payload.size()), &written,
	                          nullptr);
	if (!ok || written != payload.size())
	{
		CloseHandle(hFile);
		DeleteFileW(path.c_str());
		return false;
	}
	if (!FlushFileBuffers(hFile))
	{
		CloseHandle(hFile);
		DeleteFileW(path.c_str());
		return false;
	}
	CloseHandle(hFile);
	return true;
}

bool BenchReadFilePayload(const std::filesystem::path& path, std::vector<std::uint8_t>& out)
{
	if (BenchPathIsReparsePoint(path))
		return false;

	const HANDLE hFile = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
	                                 OPEN_EXISTING,
	                                 FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
	                                 nullptr);
	if (hFile == INVALID_HANDLE_VALUE)
		return false;

	BY_HANDLE_FILE_INFORMATION info{};
	if (!GetFileInformationByHandle(hFile, &info) ||
	    (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
	{
		CloseHandle(hFile);
		return false;
	}

	LARGE_INTEGER file_size = {};
	file_size.QuadPart = static_cast<LONGLONG>(out.size());
	LARGE_INTEGER actual_size{};
	if (!GetFileSizeEx(hFile, &actual_size) || actual_size.QuadPart != file_size.QuadPart)
	{
		CloseHandle(hFile);
		return false;
	}

	DWORD read = 0;
	const BOOL ok =
	    ReadFile(hFile, out.data(), static_cast<DWORD>(out.size()), &read, nullptr);
	CloseHandle(hFile);
	return ok && read == out.size();
}

bool BenchRewritePayload(const std::filesystem::path& path,
                         const std::vector<std::uint8_t>& payload)
{
	if (BenchPathIsReparsePoint(path))
		return false;

	const HANDLE hFile = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, TRUNCATE_EXISTING,
	                                 FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
	                                 nullptr);
	if (hFile == INVALID_HANDLE_VALUE)
		return false;

	BY_HANDLE_FILE_INFORMATION info{};
	if (!GetFileInformationByHandle(hFile, &info) ||
	    (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
	{
		CloseHandle(hFile);
		return false;
	}

	DWORD written = 0;
	const BOOL ok = WriteFile(hFile, payload.data(), static_cast<DWORD>(payload.size()), &written,
	                          nullptr);
	if (!ok || written != payload.size())
	{
		CloseHandle(hFile);
		return false;
	}
	if (!FlushFileBuffers(hFile))
	{
		CloseHandle(hFile);
		return false;
	}
	CloseHandle(hFile);
	return true;
}

struct WriteFixture
{
	std::filesystem::path root;
	std::size_t bytes = 0;
	std::size_t files = 0;
	std::vector<std::uint8_t> payload;
};

bool PrepareWriteFiles(const std::shared_ptr<WriteFixture>& fixture)
{
	if (!fixture)
		return false;

	const auto scratch_root = BenchScratchRoot();
	if (scratch_root.empty())
	{
		ReportFileIoFailure("LOCALAPPDATA / scratch root unavailable");
		return false;
	}

	fixture->payload = MakePayload(fixture->bytes);
	fixture->root = BenchUniqueWorkloadRoot(scratch_root, L"write");
	std::error_code ec;
	if (!BenchExistingAncestorsSafeBeforeCreate(fixture->root))
	{
		ReportFileIoFailure("write scratch path blocked");
		return false;
	}
	std::filesystem::create_directories(fixture->root, ec);
	if (ec || !BenchPathHasNoReparseAncestors(fixture->root) ||
	    BenchPathIsReparsePoint(fixture->root))
	{
		ReportFileIoFailure("create write scratch directory");
		return false;
	}

	for (std::size_t f = 0; f < fixture->files; ++f)
	{
		const auto path = fixture->root / ("bench-" + std::to_string(f) + ".bin");
		if (!BenchPathConfinedUnder(fixture->root, path) ||
		    !BenchWritePayloadExclusive(path, fixture->payload))
		{
			ReportFileIoFailure("create write target");
			return false;
		}
	}
	return true;
}

void CleanupWriteFiles(const std::shared_ptr<WriteFixture>& fixture)
{
	if (!fixture || fixture->root.empty())
		return;
	std::error_code ec;
	std::filesystem::remove_all(fixture->root, ec);
	fixture->root.clear();
}

BenchWorkloadResult SequentialWriteOnly(const std::shared_ptr<WriteFixture>& fixture)
{
	if (!fixture || fixture->root.empty() || fixture->bytes == 0 || fixture->files == 0 ||
	    fixture->payload.size() != fixture->bytes)
	{
		ReportFileIoFailure("write fixture not prepared");
		return BenchFail();
	}

	std::uint64_t sink = 0;
	for (std::size_t f = 0; f < fixture->files; ++f)
	{
		const auto path = fixture->root / ("bench-" + std::to_string(f) + ".bin");
		if (!BenchPathConfinedUnder(fixture->root, path) || BenchPathIsReparsePoint(path) ||
		    !BenchRewritePayload(path, fixture->payload))
		{
			ReportFileIoFailure("rewrite write target");
			return BenchFail();
		}
		sink ^= static_cast<std::uint64_t>(fixture->payload.size()) ^
		        static_cast<std::uint64_t>(f + 1);
	}
	return BenchOk(sink);
}

struct ReadFixture
{
	std::filesystem::path root;
	std::size_t bytes = 0;
	std::size_t files = 0;
	std::vector<std::uint8_t> scratch;
};

bool PrepareReadFiles(const std::shared_ptr<ReadFixture>& fixture)
{
	if (!fixture)
		return false;

	const auto payload = MakePayload(fixture->bytes);
	const auto scratch_root = BenchScratchRoot();
	if (scratch_root.empty())
	{
		ReportFileIoFailure("LOCALAPPDATA / scratch root unavailable");
		return false;
	}

	fixture->root = BenchUniqueWorkloadRoot(scratch_root, L"read");
	std::error_code ec;
	if (!BenchExistingAncestorsSafeBeforeCreate(fixture->root))
	{
		ReportFileIoFailure("read scratch path blocked");
		return false;
	}
	std::filesystem::create_directories(fixture->root, ec);
	if (ec || !BenchPathHasNoReparseAncestors(fixture->root) ||
	    BenchPathIsReparsePoint(fixture->root))
	{
		ReportFileIoFailure("create read scratch directory");
		return false;
	}

	for (std::size_t f = 0; f < fixture->files; ++f)
	{
		const auto path = fixture->root / ("bench-" + std::to_string(f) + ".bin");
		if (!BenchPathConfinedUnder(fixture->root, path) ||
		    !BenchWritePayloadExclusive(path, payload))
		{
			ReportFileIoFailure("open read-setup target");
			return false;
		}
	}

	fixture->scratch.assign(fixture->bytes, 0);
	return true;
}

void CleanupReadFiles(const std::shared_ptr<ReadFixture>& fixture)
{
	if (!fixture || fixture->root.empty())
		return;
	std::error_code ec;
	std::filesystem::remove_all(fixture->root, ec);
	fixture->root.clear();
}

BenchWorkloadResult SequentialReadOnly(const std::shared_ptr<ReadFixture>& fixture)
{
	if (!fixture || fixture->root.empty() || fixture->bytes == 0 || fixture->files == 0)
	{
		ReportFileIoFailure("read fixture not prepared");
		return BenchFail();
	}

	if (fixture->scratch.size() != fixture->bytes)
	{
		ReportFileIoFailure("read scratch not prepared");
		return BenchFail();
	}

	std::uint64_t sink = 0;
	for (std::size_t f = 0; f < fixture->files; ++f)
	{
		const auto path = fixture->root / ("bench-" + std::to_string(f) + ".bin");
		if (!BenchPathConfinedUnder(fixture->root, path) || BenchPathIsReparsePoint(path))
		{
			ReportFileIoFailure("read target outside scratch");
			return BenchFail();
		}
		if (!BenchReadFilePayload(path, fixture->scratch))
		{
			ReportFileIoFailure("read payload");
			return BenchFail();
		}
		sink ^= fixture->scratch[0] ^
		        static_cast<std::uint64_t>(fixture->scratch.size()) ^
		        static_cast<std::uint64_t>(f + 1);
	}
	return BenchOk(sink);
}

void RegisterWrite(BenchRegistry& registry,
                   const char* name,
                   std::size_t bytes,
                   std::size_t files)
{
	auto fixture = std::make_shared<WriteFixture>();
	fixture->bytes = bytes;
	fixture->files = files;

	BenchRegistry::Entry e{};
	e.group = "fileio";
	e.name = name;
	e.setup = [fixture]()
	{ return PrepareWriteFiles(fixture); };
	e.teardown = [fixture]()
	{ CleanupWriteFiles(fixture); };
	e.workload = [fixture]()
	{ return SequentialWriteOnly(fixture); };
	e.warmup_samples = 1;
	e.timed_samples = 5;
	e.iterations_per_sample = 1;
	e.bytes_per_iteration = bytes * files;
	e.ops_per_iteration = files;
	registry.Register(std::move(e));
}

void RegisterRead(BenchRegistry& registry,
                  const char* name,
                  std::size_t bytes,
                  std::size_t files)
{
	auto fixture = std::make_shared<ReadFixture>();
	fixture->bytes = bytes;
	fixture->files = files;

	BenchRegistry::Entry e{};
	e.group = "fileio";
	e.name = name;
	e.setup = [fixture]()
	{ return PrepareReadFiles(fixture); };
	e.teardown = [fixture]()
	{ CleanupReadFiles(fixture); };
	e.workload = [fixture]()
	{ return SequentialReadOnly(fixture); };
	e.warmup_samples = 1;
	e.timed_samples = 5;
	e.iterations_per_sample = 1;
	e.bytes_per_iteration = bytes * files;
	e.ops_per_iteration = files;
	registry.Register(std::move(e));
}

} // namespace

void BenchRegisterFileIoWorkloads(BenchRegistry& registry)
{
	const std::size_t chunk = 256 * 1024;
	const std::size_t multi = 8;

	RegisterWrite(registry, "write/256KiB", chunk, 1);
	RegisterRead(registry, "read/256KiB", chunk, 1);
	RegisterWrite(registry, "write/8x256KiB", chunk, multi);
	RegisterRead(registry, "read/8x256KiB", chunk, multi);
}
