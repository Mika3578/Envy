//
// test_gzip_resources_smoke.cpp
//
// Regression coverage for the tracked gzip HTML resources. Each build
// output must remain a valid gzip member whose payload equals the tracked
// HTML source, with the deterministic header fields the -n compressor
// flag produces, so a truncated or corrupt resource committed to the
// repository fails here instead of shipping broken embedded HTML.
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
// License: GNU Affero General Public License v3.0 (AGPLv3)
//

#include "test_framework.h"

#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>

#ifdef _WIN32
#include <windows.h>
#endif

#include <zlib.h>

/// Locate the repository root above the executable or the working directory.
static std::filesystem::path find_repository_root()
{
	std::filesystem::path executable;
#ifdef _WIN32
	wchar_t buffer[MAX_PATH] = {};
	const DWORD length = GetModuleFileNameW(nullptr, buffer, _countof(buffer));
	if (length != 0 && length < _countof(buffer))
		executable = std::filesystem::path(buffer).parent_path();
#endif

	const std::filesystem::path roots[] = { executable, std::filesystem::current_path() };
	for (const std::filesystem::path& root : roots)
	{
		std::filesystem::path path = root;
		for (int nLevel = 0; nLevel < 8 && !path.empty(); ++nLevel)
		{
			if (std::filesystem::is_directory(path / L"Envy" / L"Res"))
				return path;
			path = path.parent_path();
		}
	}

	return std::filesystem::path();
}

/// Read a whole file as bytes; false reports a missing or unreadable file.
static bool read_file_bytes(const std::filesystem::path& path, std::string& data)
{
	std::ifstream file(path, std::ios::binary);
	if (!file)
		return false;

	data.assign((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
	return !data.empty();
}

/// Strip carriage returns so CRLF and LF checkouts compare equal.
static void normalize_newlines(std::string& data)
{
	std::size_t out = 0;
	for (std::size_t in = 0; in < data.size(); ++in)
	{
		if (data[in] != '\r')
			data[out++] = data[in];
	}
	data.resize(out);
}

/// Compare a little-endian 32-bit field with a value.
static bool little_endian_dword_matches(const unsigned char* field, unsigned long value)
{
	return field[0] == (value & 0xFFUL) && field[1] == ((value >> 8) & 0xFFUL) && field[2] == ((value >> 16) & 0xFFUL) && field[3] == ((value >> 24) & 0xFFUL);
}

/// Inflate one gzip member and require exact equality with the tracked source.
static bool gzip_resource_matches_source(const wchar_t* name)
{
	const std::filesystem::path root = find_repository_root();
	if (root.empty())
		return false;

	std::string rawHtml, gzData;
	if (!read_file_bytes(root / L"Envy" / L"Res" / name, rawHtml))
		return false;
	if (!read_file_bytes(root / L"Envy" / L"Res" / (std::wstring(name) + L".gz"), gzData))
		return false;

	// The -n flag writes this header prefix (magic, deflate, no optional
	// fields, zero MTIME, default XFL) so repeated builds stay
	// byte-identical. The OS byte differs between compressor builds and is
	// deliberately not pinned. With FLG clear the deflate payload starts
	// right after the fixed 10-byte header.
	static const unsigned char header[9] = { 0x1F, 0x8B, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	if (gzData.size() < 18 || std::memcmp(gzData.data(), header, sizeof(header)) != 0)
		return false;

	// Inflate the raw deflate payload (windowBits -MAX_WBITS) instead of
	// zlib's gzip mode: the bundled zlibwapi.dll is built with the
	// assembler inflate fast path (ASMINF), which crashes inside gzip-mode
	// inflate on Windows, while the raw path is what the Unpacker's zip
	// reader exercises. The wrapper is checked explicitly here: with FLG
	// clear the payload starts right after the fixed 10-byte header, and
	// the trailer carries the CRC32 and the stored length.
	const Bytef* payload = reinterpret_cast<const Bytef*>(gzData.data()) + 10;
	const uInt payloadSize = static_cast<uInt>(gzData.size() - 18);

	z_stream stream = {};
	if (inflateInit2(&stream, -MAX_WBITS) != Z_OK)
		return false;

	std::string html;
	char chunk[16384];
	bool ok = false;
	stream.next_in = const_cast<Bytef*>(payload);
	stream.avail_in = payloadSize;
	for (;;)
	{
		stream.next_out = reinterpret_cast<Bytef*>(chunk);
		stream.avail_out = sizeof(chunk);
		const int result = inflate(&stream, Z_NO_FLUSH);
		html.append(chunk, sizeof(chunk) - stream.avail_out);
		if (result == Z_STREAM_END)
		{
			ok = true;
			break;
		}
		if (result != Z_OK || stream.avail_out != 0)
			break;
	}
	inflateEnd(&stream);
	if (!ok)
		return false;

	// Trailer: CRC32 of the stored payload bytes and the payload length.
	const unsigned char* trailer = reinterpret_cast<const unsigned char*>(gzData.data()) + gzData.size() - 8;
	const uLong crc = crc32(crc32(0L, Z_NULL, 0), reinterpret_cast<const Bytef*>(html.data()),
	                        static_cast<uInt>(html.size()));
	if (!little_endian_dword_matches(trailer, crc))
		return false;
	if (!little_endian_dword_matches(trailer + 4, static_cast<unsigned long>(html.size())))
		return false;

	// The payload was compressed from a Windows CRLF working tree while
	// checkouts differ, so both sides normalize to LF before comparing.
	normalize_newlines(html);
	normalize_newlines(rawHtml);
	return html == rawHtml;
}

/// Register gzip resource integrity regressions for the staged build outputs.
void register_gzip_resources_smoke_tests(TestSuite& suite)
{
	suite.add_test("Gzip resources: About.htm.gz inflates to the tracked source with a deterministic header",
	               []
	               { return gzip_resource_matches_source(L"About.htm"); });
	suite.add_test("Gzip resources: Browser.htm.gz inflates to the tracked source with a deterministic header",
	               []
	               { return gzip_resource_matches_source(L"Browser.htm"); });
}
