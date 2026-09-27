//
// main.cpp
//
// EnvyBenchmarks entry point.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

#include "bench_cli.h"
#include "bench_harness.h"
#include "bench_json.h"

#include <cstdio>
#include <string>

int main(int argc, char** argv)
{
	BenchCliOptions cli{};
	std::string error;
	if (!BenchParseArgs(argc, argv, cli, error))
	{
		std::fprintf(stderr, "EnvyBenchmarks: %s\n", error.c_str());
		std::fprintf(stderr, "Try --help\n");
		return 1;
	}

	if (cli.show_help)
	{
		BenchPrintHelp();
		return 0;
	}

	if (cli.self_test)
	{
		if (!BenchSelfTest())
		{
			std::fprintf(stderr, "EnvyBenchmarks self-test failed\n");
			return 1;
		}
		std::printf("EnvyBenchmarks self-test passed\n");
		return 0;
	}

	BenchRegisterBufferWorkloads(g_bench_registry);
	BenchRegisterProtocolWorkloads(g_bench_registry);
	BenchRegisterHashWorkloads(g_bench_registry);
	BenchRegisterFileIoWorkloads(g_bench_registry);

	if (cli.list_only)
	{
		for (const BenchRegistry::Entry& e : g_bench_registry.Entries())
			std::printf("%s/%s\n", e.group.c_str(), e.name.c_str());
		return 0;
	}

	BenchRunOptions run{};
	run.ci_mode = cli.ci_mode;
	run.filter_prefix = cli.filter_prefix;

	std::vector<BenchMeasurement> results;
	if (!RunBenchmarkSuite(run, results))
	{
		std::fprintf(stderr, "EnvyBenchmarks: benchmark run failed\n");
		return 1;
	}

	if (results.empty())
	{
		std::fprintf(stderr, "EnvyBenchmarks: no benchmarks matched filter\n");
		return 1;
	}

	BenchPrintHumanResults(results);

	const BenchEnvironment env = CaptureBenchEnvironment();
	if (!cli.json_output_path.empty())
	{
		if (!BenchWriteResultsJsonToFile(env, results, cli.json_output_path.c_str()))
		{
			std::fprintf(stderr, "EnvyBenchmarks: failed to write JSON output\n");
			return 1;
		}
	}

	return 0;
}
