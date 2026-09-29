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

std::filesystem::path BenchScratchRoot()
{
	wchar_t local_app_data[MAX_PATH] = {};
	const DWORD length = GetEnvironmentVariableW(L"LOCALAPPDATA", local_app_data, MAX_PATH);
	if (length == 0 || length >= MAX_PATH)
		return {};

	std::filesystem::path root =
		std::filesystem::path(local_app_data) / L"Envy" / L"BenchmarkScratch";
	std::error_code ec;
	std::filesystem::create_directories(root, ec);
	if (ec)
		return {};
	return root;
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

BenchWorkloadResult SequentialWrite(std::size_t bytes, std::size_t files)
{
	const auto payload = MakePayload(bytes);
	const auto scratch_root = BenchScratchRoot();
	if (scratch_root.empty())
	{
		ReportFileIoFailure("LOCALAPPDATA / scratch root unavailable");
		return BenchFail();
	}

	const auto root = scratch_root / "write";
	std::error_code ec;
	std::filesystem::remove_all(root, ec);
	std::filesystem::create_directories(root, ec);
	if (ec)
	{
		ReportFileIoFailure("create write scratch directory");
		return BenchFail();
	}

	std::uint64_t sink = 0;
	for (std::size_t f = 0; f < files; ++f)
	{
		const auto path = root / ("bench-" + std::to_string(f) + ".bin");
		std::ofstream out(path, std::ios::binary | std::ios::trunc);
		if (!out)
		{
			ReportFileIoFailure("open write target");
			return BenchFail();
		}
		out.write(reinterpret_cast<const char*>(payload.data()),
		          static_cast<std::streamsize>(payload.size()));
		out.flush();
		if (!out.good())
		{
			ReportFileIoFailure("write/flush payload");
			return BenchFail();
		}
		// Do not inspect stream state after close(); flush already published durable bytes.
		out.close();
		sink ^= static_cast<std::uint64_t>(payload.size()) ^ static_cast<std::uint64_t>(f + 1);
	}

	std::filesystem::remove_all(root, ec);
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

	fixture->root = scratch_root / "read";
	std::error_code ec;
	std::filesystem::remove_all(fixture->root, ec);
	std::filesystem::create_directories(fixture->root, ec);
	if (ec)
	{
		ReportFileIoFailure("create read scratch directory");
		return false;
	}

	for (std::size_t f = 0; f < fixture->files; ++f)
	{
		const auto path = fixture->root / ("bench-" + std::to_string(f) + ".bin");
		std::ofstream out(path, std::ios::binary | std::ios::trunc);
		if (!out)
		{
			ReportFileIoFailure("open read-setup target");
			return false;
		}
		out.write(reinterpret_cast<const char*>(payload.data()),
		          static_cast<std::streamsize>(payload.size()));
		out.flush();
		if (!out.good())
		{
			ReportFileIoFailure("write/flush read-setup payload");
			return false;
		}
		out.close();
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
		std::ifstream in(path, std::ios::binary);
		if (!in)
		{
			ReportFileIoFailure("open read target");
			return BenchFail();
		}
		in.read(reinterpret_cast<char*>(fixture->scratch.data()),
		        static_cast<std::streamsize>(fixture->scratch.size()));
		if (!in.good() && !in.eof())
		{
			ReportFileIoFailure("read payload");
			return BenchFail();
		}
		if (in.gcount() != static_cast<std::streamsize>(fixture->scratch.size()))
		{
			ReportFileIoFailure("short read");
			return BenchFail();
		}
		sink ^= fixture->scratch[0] ^ static_cast<std::uint64_t>(in.gcount()) ^
		        static_cast<std::uint64_t>(f + 1);
	}
	return BenchOk(sink);
}

void RegisterWrite(BenchRegistry& registry,
                   const char* name,
                   std::size_t bytes,
                   std::size_t files)
{
	BenchRegistry::Entry e{};
	e.group = "fileio";
	e.name = name;
	e.workload = [bytes, files]()
	{ return SequentialWrite(bytes, files); };
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
