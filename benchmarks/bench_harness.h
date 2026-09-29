//
// bench_harness.h
//
// First-party runtime benchmark harness (timing, statistics, registry).
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

#pragma once

#include <chrono>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

struct BenchRunOptions
{
	bool ci_mode = false;
	std::string filter_prefix;
};

struct BenchEnvironment
{
	std::string schema_version = "1";
	std::string architecture;
	std::string configuration;
	std::string platform;
	std::string toolset;
	std::string compiler;
};

struct BenchMeasurement
{
	std::string group;
	std::string name;
	std::uint64_t iterations_per_sample = 0;
	std::uint64_t sample_count = 0;
	double median_ns = 0.0;
	double min_ns = 0.0;
	double max_ns = 0.0;
	std::uint64_t bytes_per_sample = 0;
	std::uint64_t ops_per_sample = 0;
	double throughput_bytes_per_sec = 0.0;
	std::uint64_t checksum_sink = 0;
};

// Workload success is separate from the anti-DCE checksum sink.
// A failed sample must abort the suite (do not publish timings).
struct BenchWorkloadResult
{
	bool ok = false;
	std::uint64_t checksum = 0;
};

inline BenchWorkloadResult BenchOk(std::uint64_t checksum)
{
	return BenchWorkloadResult{ true, checksum };
}

inline BenchWorkloadResult BenchFail()
{
	return BenchWorkloadResult{ false, 0 };
}

// std::function is intentional: workloads capture fixtures/payloads at
// registration. Type-erasure cost is negligible next to the timed work
// (file I/O, hashing, large CBuffer batches); keep the registry simple.
using BenchWorkloadFn = std::function<BenchWorkloadResult()>;
using BenchSetupFn = std::function<bool()>;
using BenchTeardownFn = std::function<void()>;

class BenchRegistry
{
public:
	struct Entry
	{
		std::string group;
		std::string name;
		BenchWorkloadFn workload;
		BenchSetupFn setup;
		BenchTeardownFn teardown;
		std::uint64_t warmup_samples = 2;
		std::uint64_t timed_samples = 7;
		std::uint64_t iterations_per_sample = 1;
		std::uint64_t bytes_per_iteration = 0;
		std::uint64_t ops_per_iteration = 1;
	};

	void Register(Entry entry);
	const std::vector<Entry>& Entries() const { return m_entries; }

private:
	std::vector<Entry> m_entries;
};

BenchEnvironment CaptureBenchEnvironment();
bool RunBenchmarkSuite(const BenchRunOptions& options, std::vector<BenchMeasurement>& out);
bool BenchSelfTest();

double BenchMedianNanoseconds(std::vector<double>& samples_ns);
bool BenchParseDoubleStrict(const char* text, double& out_value);

void BenchRegisterBufferWorkloads(BenchRegistry& registry);
void BenchRegisterProtocolWorkloads(BenchRegistry& registry);
void BenchRegisterHashWorkloads(BenchRegistry& registry);
void BenchRegisterFileIoWorkloads(BenchRegistry& registry);

extern BenchRegistry g_bench_registry;
