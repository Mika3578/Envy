//
// bench_json.cpp
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

#include "StdAfx.h"

#include "bench_json.h"

#include <cstdio>
#include <fstream>
#include <limits>

namespace
{

void AppendEscapedString(std::string& out, const std::string& value)
{
	out.push_back('"');
	for (const char c : value)
	{
		switch (c)
		{
		case '\\':
			out += "\\\\";
			break;
		case '"':
			out += "\\\"";
			break;
		case '\n':
			out += "\\n";
			break;
		case '\r':
			out += "\\r";
			break;
		case '\t':
			out += "\\t";
			break;
		default:
			if (static_cast<unsigned char>(c) < 0x20)
			{
				char buf[8];
				std::snprintf(buf, sizeof(buf), "\\u%04x", static_cast<unsigned char>(c));
				out += buf;
			}
			else
				out.push_back(c);
		}
	}
	out.push_back('"');
}

void AppendFiniteDouble(std::string& out, double value)
{
	if (!std::isfinite(value))
		value = 0.0;
	char buf[64];
	std::snprintf(buf, sizeof(buf), "%.17g", value);
	out += buf;
}

} // namespace

bool BenchWriteResultsJson(const BenchEnvironment& env,
                           const std::vector<BenchMeasurement>& measurements,
                           std::string& out_json)
{
	out_json.clear();
	out_json.reserve(4096);
	out_json += "{\n  \"schema_version\": ";
	AppendEscapedString(out_json, env.schema_version);
	out_json += ",\n  \"environment\": {\n";
	out_json += "    \"architecture\": ";
	AppendEscapedString(out_json, env.architecture);
	out_json += ",\n    \"configuration\": ";
	AppendEscapedString(out_json, env.configuration);
	out_json += ",\n    \"platform\": ";
	AppendEscapedString(out_json, env.platform);
	out_json += ",\n    \"toolset\": ";
	AppendEscapedString(out_json, env.toolset);
	out_json += ",\n    \"compiler\": ";
	AppendEscapedString(out_json, env.compiler);
	out_json += "\n  },\n  \"benchmarks\": [\n";

	for (std::size_t i = 0; i < measurements.size(); ++i)
	{
		const BenchMeasurement& m = measurements[i];
		if (i > 0)
			out_json += ",\n";
		out_json += "    {\n";
		out_json += "      \"group\": ";
		AppendEscapedString(out_json, m.group);
		out_json += ",\n      \"name\": ";
		AppendEscapedString(out_json, m.name);
		out_json += ",\n      \"iterations_per_sample\": ";
		out_json += std::to_string(m.iterations_per_sample);
		out_json += ",\n      \"sample_count\": ";
		out_json += std::to_string(m.sample_count);
		out_json += ",\n      \"median_ns\": ";
		AppendFiniteDouble(out_json, m.median_ns);
		out_json += ",\n      \"min_ns\": ";
		AppendFiniteDouble(out_json, m.min_ns);
		out_json += ",\n      \"max_ns\": ";
		AppendFiniteDouble(out_json, m.max_ns);
		out_json += ",\n      \"bytes_per_sample\": ";
		out_json += std::to_string(m.bytes_per_sample);
		out_json += ",\n      \"ops_per_sample\": ";
		out_json += std::to_string(m.ops_per_sample);
		out_json += ",\n      \"throughput_bytes_per_sec\": ";
		AppendFiniteDouble(out_json, m.throughput_bytes_per_sec);
		out_json += ",\n      \"checksum_sink\": ";
		out_json += std::to_string(m.checksum_sink);
		out_json += "\n    }";
	}

	out_json += "\n  ]\n}\n";
	return true;
}

bool BenchWriteResultsJsonToFile(const BenchEnvironment& env,
                                 const std::vector<BenchMeasurement>& measurements,
                                 const char* path)
{
	if (path == nullptr || path[0] == '\0')
		return false;

	std::string json;
	if (!BenchWriteResultsJson(env, measurements, json))
		return false;

	std::ofstream out(path, std::ios::binary | std::ios::trunc);
	if (!out)
		return false;
	out.write(json.data(), static_cast<std::streamsize>(json.size()));
	return out.good();
}
