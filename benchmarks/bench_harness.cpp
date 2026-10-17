//
// bench_harness.cpp
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

#include "StdAfx.h"

#include "bench_harness.h"

#include "bench_cli.h"
#include "bench_json.h"

#include <algorithm>
#include <cerrno>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <limits>
#include <numeric>

BenchRegistry g_bench_registry;

namespace
{

using Clock = std::chrono::steady_clock;

double ToNanoseconds(const Clock::duration& d)
{
	return static_cast<double>(
	    std::chrono::duration_cast<std::chrono::nanoseconds>(d).count());
}

bool MatchesFilter(const std::string& group, const std::string& name, const std::string& prefix)
{
	if (prefix.empty())
		return true;
	const std::string full = group + "/" + name;
	if (full.rfind(prefix, 0) == 0)
		return true;
	if (group.rfind(prefix, 0) == 0)
		return true;
	return false;
}

bool InvokeWorkload(const BenchWorkloadFn& workload, std::uint64_t& checksum)
{
	const BenchWorkloadResult result = workload();
	if (!result.ok)
		return false;
	checksum ^= result.checksum;
	return true;
}

} // namespace

void BenchRegistry::Register(Entry entry)
{
	m_entries.push_back(std::move(entry));
}

BenchEnvironment CaptureBenchEnvironment()
{
	BenchEnvironment env;
#if defined(_M_X64)
	env.architecture = "x64";
#elif defined(_M_IX86)
	env.architecture = "x86";
#elif defined(_M_ARM64)
	env.architecture = "arm64";
#else
	env.architecture = "unknown";
#endif

#if defined(NDEBUG)
	env.configuration = "Release";
#else
	env.configuration = "Debug";
#endif

	env.platform = "windows";

#if defined(_MSC_VER)
	env.compiler = "msvc";
	env.toolset = std::to_string(_MSC_VER);
#else
	env.compiler = "unknown";
#endif

	return env;
}

double BenchMedianNanoseconds(std::vector<double>& samples_ns)
{
	if (samples_ns.empty())
		return 0.0;
	std::sort(samples_ns.begin(), samples_ns.end());
	const std::size_t mid = samples_ns.size() / 2;
	if (samples_ns.size() % 2 == 1)
		return samples_ns[mid];
	return (samples_ns[mid - 1] + samples_ns[mid]) / 2.0;
}

bool BenchParseDoubleStrict(const char* text, double& out_value)
{
	if (text == nullptr || *text == '\0')
		return false;
	char* end = nullptr;
	errno = 0;
	const double v = std::strtod(text, &end);
	if (errno != 0 || end == text || *end != '\0')
		return false;
	if (!std::isfinite(v))
		return false;
	out_value = v;
	return true;
}

bool RunBenchmarkSuite(const BenchRunOptions& options, std::vector<BenchMeasurement>& out)
{
	out.clear();

	for (const BenchRegistry::Entry& entry : g_bench_registry.Entries())
	{
		if (!MatchesFilter(entry.group, entry.name, options.filter_prefix))
			continue;

		const std::uint64_t warmup = options.ci_mode ? std::min<std::uint64_t>(entry.warmup_samples, 1)
		                                             : entry.warmup_samples;
		const std::uint64_t samples = options.ci_mode ? std::min<std::uint64_t>(entry.timed_samples, 3)
		                                              : entry.timed_samples;

		if (samples == 0 || entry.iterations_per_sample == 0)
			return false;

		struct TeardownGuard
		{
			const BenchTeardownFn* fn = nullptr;
			~TeardownGuard() noexcept
			{
				if (fn == nullptr || !*fn)
					return;
				try
				{
					(*fn)();
				}
				catch (...)
				{
					// Destructors must not throw (Sonar cpp:S1048).
				}
			}
		} teardown_guard{ entry.teardown ? &entry.teardown : nullptr };

		// Teardown runs even when setup fails so partial scratch is cleaned up.
		if (entry.setup && !entry.setup())
		{
			std::fprintf(stderr, "benchmark setup failed: %s/%s\n",
			             entry.group.c_str(), entry.name.c_str());
			return false;
		}

		std::uint64_t checksum = 0;
		for (std::uint64_t w = 0; w < warmup; ++w)
		{
			if (!InvokeWorkload(entry.workload, checksum))
			{
				std::fprintf(stderr, "benchmark workload failed during warmup: %s/%s\n",
				             entry.group.c_str(), entry.name.c_str());
				return false;
			}
		}

		std::vector<double> sample_ns;
		sample_ns.reserve(static_cast<std::size_t>(samples));

		for (std::uint64_t s = 0; s < samples; ++s)
		{
			const auto t0 = Clock::now();
			for (std::uint64_t i = 0; i < entry.iterations_per_sample; ++i)
			{
				if (!InvokeWorkload(entry.workload, checksum))
				{
					std::fprintf(stderr, "benchmark workload failed: %s/%s\n",
					             entry.group.c_str(), entry.name.c_str());
					return false;
				}
			}
			const auto t1 = Clock::now();
			sample_ns.push_back(ToNanoseconds(t1 - t0));
		}

		const double median = BenchMedianNanoseconds(sample_ns);
		const double min_v = *std::min_element(sample_ns.begin(), sample_ns.end());
		const double max_v = *std::max_element(sample_ns.begin(), sample_ns.end());

		const std::uint64_t bytes_total = entry.bytes_per_iteration * entry.iterations_per_sample;
		const std::uint64_t ops_total = entry.ops_per_iteration * entry.iterations_per_sample;

		double throughput = 0.0;
		if (median > 0.0 && bytes_total > 0)
			throughput = (static_cast<double>(bytes_total) * 1e9) / median;

		BenchMeasurement m{};
		m.group = entry.group;
		m.name = entry.name;
		m.iterations_per_sample = entry.iterations_per_sample;
		m.sample_count = samples;
		m.median_ns = median;
		m.min_ns = min_v;
		m.max_ns = max_v;
		m.bytes_per_sample = bytes_total;
		m.ops_per_sample = ops_total;
		m.throughput_bytes_per_sec = throughput;
		m.checksum_sink = checksum;
		out.push_back(m);
	}

	return true;
}

bool BenchSelfTest()
{
	{
		std::vector<double> v{ 10.0, 1.0, 5.0 };
		const double med = BenchMedianNanoseconds(v);
		if (med != 5.0)
			return false;
	}

	{
		double parsed = 0.0;
		if (!BenchParseDoubleStrict("123.45", parsed) || parsed != 123.45)
			return false;
		if (BenchParseDoubleStrict("12x", parsed))
			return false;
		if (BenchParseDoubleStrict("", parsed))
			return false;
	}

	{
		BenchCliOptions cli{};
		std::string error;
		char exe0[] = "EnvyBenchmarks.exe";
		char json_flag[] = "--json";
		char bad_percent_name[] = "out%.json";
		char* bad_percent[] = { exe0, json_flag, bad_percent_name };
		if (BenchParseArgs(3, bad_percent, cli, error))
			return false;
		char bad_dotdot_name[] = "..out.json";
		char* bad_dotdot[] = { exe0, json_flag, bad_dotdot_name };
		if (BenchParseArgs(3, bad_dotdot, cli, error))
			return false;
		char bad_slash_name[] = "dir/out.json";
		char* bad_slash[] = { exe0, json_flag, bad_slash_name };
		if (BenchParseArgs(3, bad_slash, cli, error))
			return false;
		char good_name[] = "results.json";
		char* good[] = { exe0, json_flag, good_name };
		if (!BenchParseArgs(3, good, cli, error))
			return false;
		if (cli.json_output_path != "results.json")
			return false;
	}

	BenchEnvironment env;
	env.architecture = "x64";
	env.configuration = "Release";
	std::vector<BenchMeasurement> one;
	BenchMeasurement m{};
	m.group = "test";
	m.name = "unit";
	m.iterations_per_sample = 1;
	m.sample_count = 1;
	m.median_ns = 100.0;
	m.min_ns = 90.0;
	m.max_ns = 110.0;
	m.bytes_per_sample = 64;
	m.ops_per_sample = 1;
	m.throughput_bytes_per_sec = 640000000.0;
	m.checksum_sink = 42;
	one.push_back(m);

	std::string json;
	if (!BenchWriteResultsJson(env, one, json))
		return false;
	if (json.find("\"schema_version\"") == std::string::npos)
		return false;

	return true;
}
