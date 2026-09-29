//
// bench_buffer.cpp
//
// Production CBuffer workloads (Envy/Buffer.cpp linked into this target).
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

#include "StdAfx.h"

#include "bench_harness.h"

#include "../Envy/Buffer.h"

#include <array>
#include <cstdint>
#include <vector>

namespace
{

constexpr unsigned kPayloadSeed = 0xC0FFEEu;

std::vector<std::uint8_t> MakePayload(std::size_t size)
{
	std::vector<std::uint8_t> data(size);
	std::uint32_t state = kPayloadSeed;
	for (std::size_t i = 0; i < size; ++i)
	{
		state = state * 1664525u + 1013904223u;
		data[i] = static_cast<std::uint8_t>(state & 0xFFu);
	}
	return data;
}

BenchWorkloadResult RunAppend(const std::vector<std::uint8_t>& chunk, std::size_t repeats)
{
	CBuffer buffer;
	std::uint64_t sink = 0;
	for (std::size_t r = 0; r < repeats; ++r)
	{
		buffer.Add(chunk.data(), chunk.size());
		sink ^= buffer.m_nLength;
	}
	return BenchOk(sink);
}

BenchWorkloadResult RunRemoveFront(const std::vector<std::uint8_t>& chunk, std::size_t cycles)
{
	CBuffer buffer;
	buffer.Add(chunk.data(), chunk.size());
	std::uint64_t sink = 0;
	const std::size_t step = chunk.empty() ? 1 : chunk.size();
	for (std::size_t i = 0; i < cycles; ++i)
	{
		if (buffer.m_nLength < step)
			buffer.Add(chunk.data(), chunk.size());
		buffer.Remove(step);
		// Include capacity so a drained buffer still produces a nonzero sink.
		sink ^= buffer.m_nLength ^ buffer.GetBufferSize() ^ static_cast<std::uint64_t>(i + 1);
	}
	return BenchOk(sink);
}

BenchWorkloadResult RunAlternating(const std::vector<std::uint8_t>& chunk, std::size_t cycles)
{
	CBuffer buffer;
	std::uint64_t sink = 0;
	for (std::size_t i = 0; i < cycles; ++i)
	{
		buffer.Add(chunk.data(), chunk.size());
		if (buffer.m_nLength >= chunk.size())
			buffer.Remove(chunk.size() / 2 + 1);
		sink ^= buffer.m_nLength ^ buffer.GetBufferSize();
	}
	return BenchOk(sink);
}

BenchWorkloadResult RunPacketLike(const std::vector<std::uint8_t>& payload, std::size_t packet_count)
{
	CBuffer buffer;
	std::uint64_t sink = 0;
	for (std::size_t i = 0; i < packet_count; ++i)
	{
		buffer.Add(payload.data(), payload.size());
		if (buffer.m_nLength > 256)
			buffer.Remove(256);
		sink ^= buffer.m_nLength;
	}
	return BenchOk(sink);
}

void RegisterOne(BenchRegistry& registry,
                 const char* name,
                 std::size_t iterations,
                 std::uint64_t warmup,
                 std::uint64_t samples,
                 BenchWorkloadFn fn,
                 std::uint64_t bytes_per_iter,
                 std::uint64_t ops_per_iter)
{
	BenchRegistry::Entry e{};
	e.group = "buffer";
	e.name = name;
	e.workload = std::move(fn);
	e.warmup_samples = warmup;
	e.timed_samples = samples;
	e.iterations_per_sample = iterations;
	e.bytes_per_iteration = bytes_per_iter;
	e.ops_per_iteration = ops_per_iter;
	registry.Register(std::move(e));
}

} // namespace

void BenchRegisterBufferWorkloads(BenchRegistry& registry)
{
	struct SizeCase
	{
		const char* tag;
		std::size_t size;
		std::size_t iterations;
	};

	const SizeCase cases[] = {
		{ "64B", 64, 200000 },
		{ "1KiB", 1024, 50000 },
		{ "16KiB", 16 * 1024, 5000 },
		{ "64KiB", 64 * 1024, 1000 },
		{ "1MiB", 1024 * 1024, 40 },
	};

	for (const SizeCase& sc : cases)
	{
		const auto payload = MakePayload(sc.size);
		// Batch production ops inside one workload call so the timed sample
		// measures CBuffer work, not per-iteration harness/result overhead.
		const std::string append_name = std::string("append/") + sc.tag;
		RegisterOne(registry, append_name.c_str(), 1, 2, 7,
		            [payload, n = sc.iterations]()
		            { return RunAppend(payload, n); },
		            sc.size * sc.iterations, sc.iterations);

		const std::size_t remove_cycles = 4 * (sc.iterations / 2 + 1);
		const std::string remove_name = std::string("remove/") + sc.tag;
		RegisterOne(registry, remove_name.c_str(), 1, 2, 7,
		            [payload, remove_cycles]()
		            { return RunRemoveFront(payload, remove_cycles); },
		            remove_cycles * sc.size, remove_cycles);

		const std::size_t alt_cycles = 8 * (sc.iterations / 4 + 1);
		const std::string alt_name = std::string("alt/") + sc.tag;
		RegisterOne(registry, alt_name.c_str(), 1, 2, 7,
		            [payload, alt_cycles]()
		            { return RunAlternating(payload, alt_cycles); },
		            alt_cycles * sc.size, alt_cycles);
	}

	const auto packet_payload = MakePayload(512);
	RegisterOne(registry, "packet/stream", 1, 2, 7,
	            [packet_payload]()
	            { return RunPacketLike(packet_payload, 200 * 5000); },
	            512ull * 200 * 5000, 200ull * 5000);

	const auto large = MakePayload(2 * 1024 * 1024);
	RegisterOne(registry, "retained/2MiB", 20, 2, 5, [large]()
	            {
			CBuffer buffer;
			buffer.Add(large.data(), large.size());
			std::uint64_t sink = buffer.m_nLength ^ buffer.GetBufferSize();
			buffer.Remove(large.size() / 4);
			sink ^= buffer.m_nLength;
			return BenchOk(sink); }, large.size(), 2);
}
