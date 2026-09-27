//
// bench_cli.cpp
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

#include "bench_cli.h"

#include <cstdio>
#include <cstring>

namespace
{

bool IsOption(const char* arg, const char* name)
{
	return std::strcmp(arg, name) == 0;
}

bool HasPathTraversal(const std::string& path)
{
	if (path.find("..") != std::string::npos)
		return true;
	return false;
}

} // namespace

bool BenchParseArgs(int argc, char** argv, BenchCliOptions& out, std::string& error_message)
{
	out = BenchCliOptions{};
	for (int i = 1; i < argc; ++i)
	{
		const char* arg = argv[i];
		if (IsOption(arg, "--help") || IsOption(arg, "-h"))
		{
			out.show_help = true;
			continue;
		}
		if (IsOption(arg, "--list"))
		{
			out.list_only = true;
			continue;
		}
		if (IsOption(arg, "--self-test"))
		{
			out.self_test = true;
			continue;
		}
		if (IsOption(arg, "--ci"))
		{
			out.ci_mode = true;
			continue;
		}
		if (IsOption(arg, "--filter"))
		{
			if (i + 1 >= argc)
			{
				error_message = "Missing value for --filter";
				return false;
			}
			out.filter_prefix = argv[++i];
			if (out.filter_prefix.size() > 256)
			{
				error_message = "Filter prefix too long";
				return false;
			}
			continue;
		}
		if (IsOption(arg, "--json"))
		{
			if (i + 1 >= argc)
			{
				error_message = "Missing path for --json";
				return false;
			}
			out.json_output_path = argv[++i];
			if (out.json_output_path.empty() || out.json_output_path.size() > 260 ||
			    HasPathTraversal(out.json_output_path))
			{
				error_message = "Invalid --json output path";
				return false;
			}
			continue;
		}

		error_message = std::string("Unknown argument: ") + arg;
		return false;
	}
	return true;
}

void BenchPrintHelp()
{
	std::printf("EnvyBenchmarks — reproducible Release x64 runtime baselines\n\n");
	std::printf("Usage:\n");
	std::printf("  EnvyBenchmarks.exe [options]\n\n");
	std::printf("Options:\n");
	std::printf("  --list              List benchmark names and exit\n");
	std::printf("  --filter <prefix>   Run benchmarks whose group/name matches prefix\n");
	std::printf("  --json <file>       Write machine-readable JSON results\n");
	std::printf("  --ci                Shorter sample counts for hosted CI\n");
	std::printf("  --self-test         Run harness infrastructure self-tests\n");
	std::printf("  --help              Show this help\n");
}

void BenchPrintHumanResults(const std::vector<BenchMeasurement>& measurements)
{
	std::printf("Benchmark results (median of timed samples; not for nanosecond claims on VMs)\n");
	std::printf("%-40s %12s %12s %14s\n", "name", "samples", "median_ms", "MB/s");
	std::printf("%-40s %12s %12s %14s\n", "----", "-------", "---------", "----");

	for (const BenchMeasurement& m : measurements)
	{
		const std::string full = m.group + "/" + m.name;
		const double median_ms = m.median_ns / 1e6;
		const double mbps = m.throughput_bytes_per_sec / (1024.0 * 1024.0);
		std::printf("%-40s %12llu %12.4f %14.2f\n",
		            full.c_str(),
		            static_cast<unsigned long long>(m.sample_count),
		            median_ms,
		            mbps);
	}
}
