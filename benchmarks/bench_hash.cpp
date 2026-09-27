//
// bench_hash.cpp
//
// Production HashLib algorithms (same seam as EnvyTests).
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

#include "StdAfx.h"

#include "bench_harness.h"

#ifdef WIN64
#define NTDDI_VERSION 0x06000000
#define _WIN32_WINNT 0x0600
#else
#define NTDDI_VERSION 0x05010200
#define _WIN32_WINNT 0x0501
#endif
#include <sdkddkver.h>

#include "../HashLib/HashLib.h"

#include <array>
#include <cstdint>
#include <cstring>
#include <vector>

namespace
{

std::vector<std::uint8_t> MakePayload(std::size_t size)
{
	std::vector<std::uint8_t> data(size);
	for (std::size_t i = 0; i < size; ++i)
		data[i] = static_cast<std::uint8_t>((i * 131u) & 0xFFu);
	return data;
}

template<typename Hasher, std::size_t HashLen>
std::uint64_t HashBuffer(const std::vector<std::uint8_t>& data, std::size_t repeats)
{
	std::array<std::uint8_t, HashLen> digest{};
	std::uint64_t sink = 0;
	for (std::size_t r = 0; r < repeats; ++r)
	{
		Hasher hasher;
		hasher.Reset();
		hasher.Add(data.data(), data.size());
		hasher.Finish();
		hasher.GetHash(digest.data());
		sink ^= digest[0];
	}
	return sink;
}

std::uint64_t HashEd2k(const std::vector<std::uint8_t>& data, std::size_t repeats)
{
	std::uint64_t sink = 0;
	for (std::size_t r = 0; r < repeats; ++r)
	{
		CED2K ed2k;
		ed2k.BeginFile(static_cast<uint64>(data.size()));
		ed2k.AddToFile(data.data(), static_cast<uint32>(data.size()));
		if (!ed2k.FinishFile())
			return 0;
		std::array<std::uint8_t, 16> digest{};
		ed2k.GetRoot(digest.data());
		sink ^= digest[0];
	}
	return sink;
}

std::uint64_t HashTiger(const std::vector<std::uint8_t>& data, std::size_t repeats)
{
	std::uint64_t sink = 0;
	for (std::size_t r = 0; r < repeats; ++r)
	{
		CTigerTree tiger;
		tiger.BeginFile(9, static_cast<uint64>(data.size()));
		if (!data.empty())
			tiger.AddToFile(data.data(), static_cast<uint32>(data.size()));
		if (!tiger.FinishFile())
			return 0;
		std::array<std::uint8_t, 24> digest{};
		if (!tiger.GetRoot(digest.data()))
			return 0;
		sink ^= digest[0];
	}
	return sink;
}

void RegisterHashCase(BenchRegistry& registry,
                      const char* name,
                      const std::vector<std::uint8_t>& payload,
                      std::size_t repeats,
                      BenchWorkloadFn fn)
{
	BenchRegistry::Entry e{};
	e.group = "hash";
	e.name = name;
	e.workload = std::move(fn);
	e.warmup_samples = 2;
	e.timed_samples = 7;
	e.iterations_per_sample = repeats;
	e.bytes_per_iteration = payload.size();
	e.ops_per_iteration = 1;
	registry.Register(std::move(e));
}

} // namespace

void BenchRegisterHashWorkloads(BenchRegistry& registry)
{
	const auto small = MakePayload(256);
	const auto piece = MakePayload(256 * 1024);
	const auto large = MakePayload(4 * 1024 * 1024);

	RegisterHashCase(registry,
	                 "sha1/256B",
	                 small,
	                 5000,
	                 [small]()
	                 { return HashBuffer<CSHA, 20>(small, 1); });
	RegisterHashCase(registry,
	                 "md5/256B",
	                 small,
	                 5000,
	                 [small]()
	                 { return HashBuffer<CMD5, 16>(small, 1); });
	RegisterHashCase(registry,
	                 "md4/256B",
	                 small,
	                 5000,
	                 [small]()
	                 { return HashBuffer<CMD4, 16>(small, 1); });

	RegisterHashCase(registry,
	                 "sha1/256KiB",
	                 piece,
	                 200,
	                 [piece]()
	                 { return HashBuffer<CSHA, 20>(piece, 1); });
	RegisterHashCase(registry,
	                 "ed2k/256KiB",
	                 piece,
	                 200,
	                 [piece]()
	                 { return HashEd2k(piece, 1); });
	RegisterHashCase(registry,
	                 "tiger/256KiB",
	                 piece,
	                 200,
	                 [piece]()
	                 { return HashTiger(piece, 1); });

	RegisterHashCase(registry,
	                 "sha1/4MiB",
	                 large,
	                 10,
	                 [large]()
	                 { return HashBuffer<CSHA, 20>(large, 1); });
	RegisterHashCase(registry,
	                 "ed2k/4MiB",
	                 large,
	                 10,
	                 [large]()
	                 { return HashEd2k(large, 1); });
}
