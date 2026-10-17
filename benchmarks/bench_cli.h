//
// bench_cli.h
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

#pragma once

#include "bench_harness.h"

#include <string>

struct BenchCliOptions
{
	bool show_help = false;
	bool list_only = false;
	bool self_test = false;
	bool ci_mode = false;
	std::string filter_prefix;
	std::string json_output_path;
};

bool BenchParseArgs(int argc, char** argv, BenchCliOptions& out, std::string& error_message);

void BenchPrintHelp();
void BenchPrintHumanResults(const std::vector<BenchMeasurement>& measurements);
