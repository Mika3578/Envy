//
// buffer_production_tu.cpp
//
// Compiles production Envy/Buffer.cpp with the benchmark PCH (Envy/ always
// wins quoted "StdAfx.h" when the primary source file lives under Envy/).
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

#include "StdAfx.h"

#define ENVY_BENCHMARK_SKIP_STDAX
#include "../Envy/Buffer.cpp"
