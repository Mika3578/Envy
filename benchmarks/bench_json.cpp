//
// bench_json.cpp
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

#include "StdAfx.h"

#include "bench_json.h"

#include <cmath>
#include <cstdio>
#include <filesystem>
#include <limits>
#include <string>
#include <vector>

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

bool PathHasSymlinkComponent(const std::filesystem::path& path)
{
	std::error_code ec;
	const std::filesystem::path absolute = std::filesystem::absolute(path, ec);
	if (ec)
		return true;

	std::vector<std::filesystem::path> parts;
	for (const auto& part : absolute)
		parts.push_back(part);
	if (parts.empty())
		return true;

	std::filesystem::path current;
	for (std::size_t i = 0; i < parts.size(); ++i)
	{
		if (current.empty())
			current = parts[i];
		else
			current /= parts[i];

		const std::filesystem::file_status status =
			std::filesystem::symlink_status(current, ec);
		if (ec)
		{
			// Missing leaf is fine for create; missing intermediate is an error.
			return i + 1 != parts.size();
		}
		if (std::filesystem::is_symlink(status))
			return true;
	}
	return false;
}

bool WriteExclusiveReplace(const std::filesystem::path& final_path, const std::string& json)
{
	if (json.size() > static_cast<std::size_t>((std::numeric_limits<DWORD>::max)()))
		return false;

	std::filesystem::path parent = final_path.parent_path();
	if (parent.empty())
		parent = std::filesystem::path(L".");

	// Unique temp name: never delete a colliding path (could be unrelated data).
	FILETIME ft{};
	GetSystemTimeAsFileTime(&ft);
	const std::filesystem::path temp_path =
		parent /
		(final_path.filename().wstring() + L".tmp." + std::to_wstring(GetCurrentProcessId()) + L"." +
		 std::to_wstring((static_cast<std::uint64_t>(ft.dwHighDateTime) << 32) |
		                 ft.dwLowDateTime));

	const std::wstring temp_w = temp_path.wstring();
	const std::wstring final_w = final_path.wstring();

	// CREATE_NEW + OPEN_REPARSE_POINT: exclusive create that will not follow a
	// pre-existing symlink at the temp path (and fails closed if one appears).
	HANDLE handle = CreateFileW(temp_w.c_str(),
	                            GENERIC_WRITE,
	                            0,
	                            nullptr,
	                            CREATE_NEW,
	                            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
	                            nullptr);
	if (handle == INVALID_HANDLE_VALUE)
		return false;

	BY_HANDLE_FILE_INFORMATION info{};
	if (!GetFileInformationByHandle(handle, &info) ||
	    (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
	{
		CloseHandle(handle);
		DeleteFileW(temp_w.c_str());
		return false;
	}

	DWORD written = 0;
	const BOOL write_ok = WriteFile(handle,
	                                json.data(),
	                                static_cast<DWORD>(json.size()),
	                                &written,
	                                nullptr);
	const BOOL flush_ok = write_ok ? FlushFileBuffers(handle) : FALSE;
	CloseHandle(handle);

	if (!write_ok || !flush_ok || written != static_cast<DWORD>(json.size()))
	{
		DeleteFileW(temp_w.c_str());
		return false;
	}

	if (!MoveFileExW(temp_w.c_str(),
	                 final_w.c_str(),
	                 MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
	{
		DeleteFileW(temp_w.c_str());
		return false;
	}
	return true;
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

	const std::filesystem::path final_path(path);
	if (PathHasSymlinkComponent(final_path))
		return false;

	std::string json;
	if (!BenchWriteResultsJson(env, measurements, json))
		return false;

	return WriteExclusiveReplace(final_path, json);
}
