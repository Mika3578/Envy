//
// bench_json.h
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

#pragma once

#include "bench_harness.h"

#include <string>
#include <vector>

bool BenchWriteResultsJson(const BenchEnvironment& env,
                           const std::vector<BenchMeasurement>& measurements,
                           std::string& out_json);

bool BenchWriteResultsJsonToFile(const BenchEnvironment& env,
                                 const std::vector<BenchMeasurement>& measurements,
                                 const char* path);
