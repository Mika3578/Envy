//
// bench_fileio.cpp
//
// Baseline sequential temp-file I/O (no TransferFiles / locking).
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

#include "bench_harness.h"

#include "StdAfx.h"

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

namespace
{

std::filesystem::path BenchScratchRoot()
{
	const char* local = std::getenv("LOCALAPPDATA");
	if (local == nullptr || local[0] == '\0')
		return {};

	std::filesystem::path root = std::filesystem::path(local) / "Envy" / "BenchmarkScratch";
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

std::uint64_t SequentialWrite(std::size_t bytes, std::size_t files)
{
	const auto payload = MakePayload(bytes);
	const auto scratch_root = BenchScratchRoot();
	if (scratch_root.empty())
		return 0;

	const auto root = scratch_root / "write";
	std::error_code ec;
	std::filesystem::remove_all(root, ec);
	std::filesystem::create_directories(root, ec);
	if (ec)
		return 0;

	std::uint64_t sink = 0;
	for (std::size_t f = 0; f < files; ++f)
	{
		const auto path = root / ("bench-" + std::to_string(f) + ".bin");
		std::ofstream out(path, std::ios::binary | std::ios::trunc);
		if (!out)
			return 0;
		out.write(reinterpret_cast<const char*>(payload.data()),
		          static_cast<std::streamsize>(payload.size()));
		if (!out.good())
			return 0;
		sink ^= static_cast<std::uint64_t>(out.tellp());
	}

	std::filesystem::remove_all(root, ec);
	return sink;
}

std::uint64_t SequentialRead(std::size_t bytes, std::size_t files)
{
	const auto payload = MakePayload(bytes);
	const auto scratch_root = BenchScratchRoot();
	if (scratch_root.empty())
		return 0;

	const auto root = scratch_root / "read";
	std::error_code ec;
	std::filesystem::remove_all(root, ec);
	std::filesystem::create_directories(root, ec);
	if (ec)
		return 0;

	for (std::size_t f = 0; f < files; ++f)
	{
		const auto path = root / ("bench-" + std::to_string(f) + ".bin");
		std::ofstream out(path, std::ios::binary | std::ios::trunc);
		if (!out)
			return 0;
		out.write(reinterpret_cast<const char*>(payload.data()),
		          static_cast<std::streamsize>(payload.size()));
		if (!out.good())
			return 0;
	}

	std::uint64_t sink = 0;
	std::vector<std::uint8_t> scratch(bytes);
	for (std::size_t f = 0; f < files; ++f)
	{
		const auto path = root / ("bench-" + std::to_string(f) + ".bin");
		std::ifstream in(path, std::ios::binary);
		if (!in)
			return 0;
		in.read(reinterpret_cast<char*>(scratch.data()), static_cast<std::streamsize>(scratch.size()));
		if (!in.good() && !in.eof())
			return 0;
		if (in.gcount() != static_cast<std::streamsize>(scratch.size()))
			return 0;
		sink ^= scratch[0] ^ static_cast<std::uint64_t>(in.gcount());
	}

	std::filesystem::remove_all(root, ec);
	return sink;
}

void RegisterFile(BenchRegistry& registry,
                  const char* name,
                  std::size_t bytes,
                  std::size_t files,
                  BenchWorkloadFn fn)
{
	BenchRegistry::Entry e{};
	e.group = "fileio";
	e.name = name;
	e.workload = std::move(fn);
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

	RegisterFile(registry,
	             "write/256KiB",
	             chunk,
	             1,
	             [chunk]()
	             { return SequentialWrite(chunk, 1); });
	RegisterFile(registry,
	             "read/256KiB",
	             chunk,
	             1,
	             [chunk]()
	             { return SequentialRead(chunk, 1); });
	RegisterFile(registry,
	             "write/8x256KiB",
	             chunk,
	             multi,
	             [chunk, multi]()
	             { return SequentialWrite(chunk, multi); });
	RegisterFile(registry,
	             "read/8x256KiB",
	             chunk,
	             multi,
	             [chunk, multi]()
	             { return SequentialRead(chunk, multi); });
}
