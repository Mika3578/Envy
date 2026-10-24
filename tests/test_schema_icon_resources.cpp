//
// test_schema_icon_resources.cpp
//
// Regression coverage for schema icon resources, fallback and draw indices.
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
// License: GNU Affero General Public License v3.0 (AGPLv3)
//

#include "test_framework.h"
#include "../Envy/SchemaIconPolicy.h"

#include <array>
#include <filesystem>
#include <fstream>
#include <limits>
#include <regex>
#include <set>
#include <string>

#ifdef _WIN32
#include <windows.h>
#include <shellapi.h>
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "user32.lib")
#endif

/// Find checked-in schema resources above the executable or current working directory.
static std::filesystem::path find_schema_directory()
{
	std::filesystem::path executable;
#ifdef _WIN32
	wchar_t buffer[MAX_PATH] = {};
	const DWORD length = GetModuleFileNameW(nullptr, buffer, _countof(buffer));
	if (length != 0 && length < _countof(buffer))
		executable = std::filesystem::path(buffer).parent_path();
#endif

	// Tests may change the working directory; anchor the repository lookup to this executable first.
	const std::filesystem::path roots[] = { executable, std::filesystem::current_path() };
	for (const std::filesystem::path& root : roots)
	{
		std::filesystem::path path = root;
		for (int nLevel = 0; nLevel < 8 && !path.empty(); ++nLevel)
		{
			const std::filesystem::path schemas = path / L"Schemas";
			if (std::filesystem::is_directory(schemas))
				return schemas;
			path = path.parent_path();
		}
	}

	return std::filesystem::path();
}

/// Require every XML icon reference to resolve, including the Collection descriptor resource.
static bool test_schema_descriptor_icons_exist()
{
	const std::filesystem::path schemas = find_schema_directory();
	if (schemas.empty())
		return false;

	// Match `path` anywhere inside the <icon> element (any attribute order)
	// and both quote styles the XML loader accepts (CXMLAttribute::ParseString).
	const std::regex iconPattern(R"REGEX(<icon\b[^>]*\bpath\s*=\s*(?:"([^"]*)"|'([^']*)'))REGEX");
	bool bFoundIcon = false;

	for (const std::filesystem::directory_entry& entry : std::filesystem::directory_iterator(schemas))
	{
		if (entry.path().extension() != L".xml")
			continue;

		std::ifstream file(entry.path(), std::ios::binary);
		if (!file)
			return false;

		const std::string xml((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
		for (std::sregex_iterator it(xml.begin(), xml.end(), iconPattern), end; it != end; ++it)
		{
			const std::string& sPath = (*it)[1].matched ? (*it)[1].str() : (*it)[2].str();
			bFoundIcon = true;
			if (!std::filesystem::is_regular_file(schemas / sPath))
				return false;
		}
	}

	return bFoundIcon;
}

// Model only resource availability and image-list insertion results at the OS boundary.
// Selection, per-size index updates and draw validation use the production policy helpers.
struct IconCandidateFixture
{
	std::array<bool, 3> frames{};
	std::array<int, 3> inserted{ -1, -1, -1 };
};

struct SchemaIconFixture
{
	static constexpr int generic = 0; // SHI_FILE in ShellIcons.
	std::array<IconCandidateFixture, 4> candidates{};
	std::array<int, 3> indices{ generic, generic, generic };
	std::vector<SchemaIconCandidate> attempts;

	/// Run production selection and insertion policies with deterministic frame/insertion results.
	bool load(bool alternate)
	{
		return LoadSchemaIconFallback(alternate, [&](SchemaIconCandidate candidate)
		                              {
			attempts.push_back(candidate);
			const IconCandidateFixture& icon = candidates[static_cast<std::size_t>(candidate)];
			return LoadSchemaIconFrames(indices[0], indices[1], indices[2], generic, [&](int size)
			{
				const std::size_t frame = size == 16 ? 0 : (size == 32 ? 1 : 2);
				return icon.frames[frame] ? icon.inserted[frame] : -1;
			}); });
	}
};

/// Check each missing-candidate prefix, all resources missing, alternate opt-in and early stopping.
static bool test_schema_icon_fallback_order()
{
	for (bool alternate : { false, true })
	{
		const std::vector<SchemaIconCandidate> order = alternate
		                                                   ? std::vector<SchemaIconCandidate>{ SchemaIconCandidate::Skin, SchemaIconCandidate::Alternate, SchemaIconCandidate::Default, SchemaIconCandidate::Safe }
		                                                   : std::vector<SchemaIconCandidate>{ SchemaIconCandidate::Skin, SchemaIconCandidate::Default, SchemaIconCandidate::Safe };
		for (std::size_t missing = 0; missing <= order.size(); ++missing)
		{
			SchemaIconFixture fixture;
			// Every candidate after the missing prefix exists, so an extra load changes the result.
			for (std::size_t i = missing; i < order.size(); ++i)
				fixture.candidates[static_cast<std::size_t>(order[i])] = { { true, true, true }, { static_cast<int>(i) + 1, 5, 6 } };
			if (!alternate)
				fixture.candidates[1] = { { true, true, true }, { 99, 99, 99 } };
			const bool loaded = fixture.load(alternate);
			const bool expected = missing < order.size();
			const std::size_t attempted = expected ? missing + 1 : order.size();
			if (loaded != expected || fixture.attempts != std::vector<SchemaIconCandidate>(order.begin(), order.begin() + attempted))
				return false;
			const std::array<int, 3> expectedIndices = expected
			                                               ? std::array<int, 3>{ static_cast<int>(missing) + 1, 5, 6 }
			                                               : std::array<int, 3>{ 0, 0, 0 };
			if (fixture.indices != expectedIndices) return false;
		}
	}
	return true;
}

/// A candidate containing only larger frames must continue fallback until a 16px entry is inserted.
static bool test_schema_icon_missing_16px()
{
	for (std::size_t next = 1; next <= 4; ++next)
	{
		SchemaIconFixture fixture;
		for (std::size_t i = 0; i < next; ++i)
			fixture.candidates[i] = { { false, true, true }, { -1, 7, 8 } };
		if (next < 4)
			fixture.candidates[next] = { { true, false, false }, { 9, -1, -1 } };
		if (fixture.load(true) != (next < 4)) return false;
		if (fixture.indices != std::array<int, 3>{ next < 4 ? 9 : 0, 7, 8 }) return false;
		if (fixture.attempts.size() != (next < 4 ? next + 1 : 4)) return false;
	}
	return true;
}

/// Missing frames and failed insertions keep generic entries; only 16px failure continues fallback.
static bool test_schema_icon_failed_insertion()
{
	for (bool missing : { false, true })
	{
		for (std::size_t failed = 0; failed < 3; ++failed)
		{
			SchemaIconFixture fixture;
			fixture.candidates[0] = { { true, true, true }, { 4, 5, 6 } };
			if (missing)
				fixture.candidates[0].frames[failed] = false;
			else
				fixture.candidates[0].inserted[failed] = -1;
			fixture.candidates[2] = { { true, false, false }, { 9, -1, -1 } };
			if (!fixture.load(false)) return false;
			const std::array<int, 3> expected{ failed == 0 ? 9 : 4, failed == 1 ? 0 : 5, failed == 2 ? 0 : 6 };
			if (fixture.indices != expected || fixture.attempts.size() != (failed == 0 ? 2u : 1u)) return false;
		}
	}
	return true;
}

/// A later candidate's missing or failed large frames must preserve indices from an earlier candidate.
static bool test_schema_icon_preserves_prior_entries()
{
	SchemaIconFixture fixture;
	fixture.candidates[0] = { { false, true, true }, { -1, 7, 8 } };
	fixture.candidates[1] = { { true, true, false }, { 9, -1, -1 } };
	return fixture.load(true) && fixture.indices == std::array<int, 3>{ 9, 7, 8 } && fixture.attempts.size() == 2;
}

/// Total insertion failure repairs negative indices; an old 16px entry cannot make a candidate succeed.
static bool test_schema_icon_generic_and_existing_entries()
{
	SchemaIconFixture fixture;
	fixture.indices = { -1, -2, -3 };
	for (IconCandidateFixture& candidate : fixture.candidates)
		candidate.frames = { true, true, true };
	if (fixture.load(true) || fixture.indices != std::array<int, 3>{ 0, 0, 0 } || fixture.attempts.size() != 4)
		return false;
	fixture.indices = { 4, 5, 6 };
	fixture.attempts.clear();
	if (fixture.load(true) || fixture.indices != std::array<int, 3>{ 4, 5, 6 } || fixture.attempts.size() != 4)
		return false;
	// Index zero is a successful insertion, not an error sentinel.
	fixture.candidates[0] = { { true, true, true }, { 0, 0, 0 } };
	return fixture.load(true) && fixture.indices == std::array<int, 3>{ 0, 0, 0 };
}

/// Reject absent/empty lists and invalid generic entries; bound every requested index before drawing.
static bool test_schema_icon_draw_indices()
{
	const int requests[] = { (std::numeric_limits<int>::min)(), -1, 0, 1, 2, 3, (std::numeric_limits<int>::max)() };
	for (int count : { -1, 0, 1, 3 })
	{
		for (int requested : requests)
		{
			const int expected = count <= 0 ? -1 : (requested >= 0 && requested < count ? requested : 0);
			if (GetSchemaIconDrawIndex(count, requested, SchemaIconFixture::generic) != expected) return false;
		}
	}
	return GetSchemaIconDrawIndex(3, -1, -1) == -1 && GetSchemaIconDrawIndex(3, 3, 3) == -1 &&
	       GetSchemaIconDrawIndex(3, -1, 2) == 2 && GetSchemaIconDrawIndex(3, 1, -1) == 1;
}

/// Root selection: only a manifest-complete executable folder wins; partial sets fall back to General.Path.
static bool test_schema_root_selection()
{
	// complete, has schemas, configured has schemas
	return SelectSchemaRoot(true, true, true) == 0 && SelectSchemaRoot(true, true, false) == 0 &&
	       // partial build copy: use the configured install when it has schemas
	       SelectSchemaRoot(false, true, true) == 1 && SelectSchemaRoot(false, false, true) == 1 &&
	       // only a partial build copy exists: last resort
	       SelectSchemaRoot(false, true, false) == 0 &&
	       // nothing anywhere
	       SelectSchemaRoot(false, false, false) == -1;
}

/// Manifest entries must be plain schema file names that cannot leave the Schemas folder.
static bool test_schema_manifest_names()
{
	const char* good[] = { "Application.xsd", "Application.xml", "AllFilesFolder.Safe.ico", "A-b_1.ICO" };
	const char* bad[] = { "", ".hidden.xsd", "..\\evil.xsd", "../evil.xsd", "sub/a.xsd", "C:a.xsd", "a..b.xsd",
		                  "name with space.xsd", "a.dll", "noext", "caf\xC3\xA9.xsd", "Schemas.manifest" };
	for (const char* name : good)
		if (!IsSchemaManifestName(name)) return false;
	for (const char* name : bad)
		if (IsSchemaManifestName(name)) return false;
	return !IsSchemaManifestName(std::string(129, 'a') + ".xsd");
}

/// Stale, partial and malformed staged folders are never reported as complete.
static bool test_schema_manifest_completeness()
{
	std::set<std::string> present = { "A.xsd", "A.xml", "A.ico", "B.xsd" };
	const auto exists = [&](const std::string& name) { return present.count(name) != 0; };

	if (!IsSchemaManifestComplete("A.xsd\r\nA.xml\r\nA.ico\r\nB.xsd\r\n", exists)) return false;
	if (!IsSchemaManifestComplete("\xEF\xBB\xBF" "A.xsd\n\nB.xsd", exists)) return false; // BOM, LF, blank line

	// Partial staging: a listed resource is missing.
	if (IsSchemaManifestComplete("A.xsd\nA.xml\nC.xsd\n", exists)) return false;
	present.erase("A.ico");
	if (IsSchemaManifestComplete("A.xsd\nA.ico\n", exists)) return false;

	// Extra files that the manifest does not list (stale output) do not make the listed set incomplete.
	present.insert("Removed.xsd");
	if (!IsSchemaManifestComplete("A.xsd\nB.xsd\n", exists)) return false;

	// Empty or malformed manifests are untrusted, including entries that try to leave the folder.
	return !IsSchemaManifestComplete("", exists) && !IsSchemaManifestComplete("\r\n\r\n", exists) &&
	       !IsSchemaManifestComplete("A.xsd\n..\\A.xsd\n", exists) && !IsSchemaManifestComplete("A.xsd\nnotes.txt\n", exists);
}

/// The project must write the manifest the runtime reads and delete only entries it recorded earlier.
static bool test_stage_schemas_target_matches_runtime()
{
	std::filesystem::path path = find_schema_directory();
	if (path.empty()) return false;
	std::ifstream file(path.parent_path() / L"Envy" / L"Envy.vcxproj", std::ios::binary);
	if (!file) return false;
	const std::string project((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
	const std::wstring wide = GetSchemaManifestName();
	const std::string name(wide.begin(), wide.end());
	const std::size_t target = project.find("<Target Name=\"StageSchemas\"");
	if (target == std::string::npos) return false;
	const std::string body = project.substr(target, project.find("</Target>", target) - target);
	const std::size_t read = body.find("<ReadLinesFromFile");
	const std::size_t del = body.find("<Delete ");
	const std::size_t copy = body.find("<Copy ");
	const std::size_t write = body.find("<WriteLinesToFile");
	return body.find(name) != std::string::npos && read != std::string::npos && read < del && del < copy &&
	       copy < write && body.find("%(Filename)%(Extension)") != std::string::npos;
}

#ifdef _WIN32
/// Count 16px frames declared by an ICO directory; reject truncated or non-icon data.
static int count_ico_16px_frames(const std::filesystem::path& path)
{
	std::ifstream file(path, std::ios::binary);
	std::string data((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
	if (data.size() < 6 || data[2] != 1 || data[3] != 0) return -1;
	const std::size_t count = static_cast<unsigned char>(data[4]) | (static_cast<unsigned char>(data[5]) << 8);
	if (count == 0 || data.size() < 6 + count * 16) return -1;
	int frames = 0;
	for (std::size_t i = 0; i < count; ++i)
	{
		const unsigned char* entry = reinterpret_cast<const unsigned char*>(data.data()) + 6 + i * 16;
		const std::size_t size = entry[8] | (entry[9] << 8) | (entry[10] << 16) | (static_cast<std::size_t>(entry[11]) << 24);
		const std::size_t offset = entry[12] | (entry[13] << 8) | (entry[14] << 16) | (static_cast<std::size_t>(entry[15]) << 24);
		if (offset > data.size() || size > data.size() - offset) return -1;
		if (entry[0] == 16) ++frames;
	}
	return frames;
}

/// Load an ICO the way CSchema::LoadIcon does. PrivateExtractIcons substitutes the nearest available frame,
/// so has48 only proves the file is loadable at that size, not that it contains a 48px frame.
static bool load_icon_with_windows(const std::filesystem::path& path, bool& has16, bool& has48)
{
	HICON hLarge = nullptr, hSmall = nullptr, hHuge = nullptr, hExact16 = nullptr;
	UINT id = 0;
	ExtractIconExW(path.c_str(), 0, &hLarge, &hSmall, 1);
	PrivateExtractIconsW(path.c_str(), 0, 16, 16, &hExact16, &id, 1, 0);
	PrivateExtractIconsW(path.c_str(), 0, 48, 48, &hHuge, &id, 1, 0);
	has16 = hSmall != nullptr && hExact16 != nullptr;
	has48 = hHuge != nullptr;
	for (HICON h : { hLarge, hSmall, hHuge, hExact16 })
		if (h) DestroyIcon(h);
	return true;
}

/// Every shipped schema icon must declare a 16px frame and load through the real Windows loaders, so the
/// download-group combo never falls back to the generic icon because of an unreadable resource.
static bool test_schema_icons_load_with_windows()
{
	const std::filesystem::path schemas = find_schema_directory();
	if (schemas.empty()) return false;
	int checked = 0;
	for (const std::filesystem::directory_entry& entry : std::filesystem::directory_iterator(schemas))
	{
		if (entry.path().extension() != L".ico") continue;
		bool has16 = false, has48 = false;
		if (count_ico_16px_frames(entry.path()) < 1) return false;
		load_icon_with_windows(entry.path(), has16, has48);
		if (!has16 || !has48) return false; // has48: loadable at 48px, possibly scaled from another frame.
		++checked;
	}
	return checked > 0;
}

/// Absent, empty, truncated and non-icon files yield no handle, so the generic fallback applies.
static bool test_schema_icons_invalid_files()
{
	// Keep scratch files out of shared, publicly writable temp folders: use a fresh directory beside the test
	// executable (or the working directory) and fail if the name already exists.
	std::filesystem::path root = std::filesystem::current_path();
	wchar_t exePath[MAX_PATH] = {};
	const DWORD length = GetModuleFileNameW(nullptr, exePath, _countof(exePath));
	if (length != 0 && length < _countof(exePath))
		root = std::filesystem::path(exePath).parent_path();

	std::filesystem::path dir;
	std::error_code ec;
	for (unsigned nAttempt = 0; nAttempt < 16 && dir.empty(); ++nAttempt)
	{
		const std::filesystem::path candidate = root /
			(L"envy_schema_icon_test_" + std::to_wstring(GetCurrentProcessId()) + L"_" +
			 std::to_wstring(GetTickCount64()) + L"_" + std::to_wstring(nAttempt));
		if (std::filesystem::create_directory(candidate, ec) && !ec)
			dir = candidate;
	}
	if (dir.empty()) return false;
	bool ok = true;
	const std::pair<const wchar_t*, std::string> files[] = {
		{ L"empty.ico", std::string() },
		{ L"truncated.ico", std::string("\0\0\1\0\1\0\x10\x10", 8) },
		{ L"notico.ico", std::string("this is not an icon file") },
	};
	for (const auto& file : files)
	{
		std::ofstream(dir / file.first, std::ios::binary) << file.second;
		bool has16 = true, has48 = true;
		load_icon_with_windows(dir / file.first, has16, has48);
		ok = ok && !has16 && !has48;
	}
	bool has16 = true, has48 = true;
	load_icon_with_windows(dir / L"absent.ico", has16, has48);
	ok = ok && !has16 && !has48;
	std::filesystem::remove_all(dir, ec);
	return ok;
}
#endif

/// Register descriptor-resource coverage and deterministic production-policy regressions.
void register_schema_icon_resource_tests(TestSuite& suite)
{
	suite.add_test("Schema icons: every descriptor reference has a resource",
	               test_schema_descriptor_icons_exist);
	suite.add_test("Schema icons: missing Skin/Alt/default/Safe fallback order", test_schema_icon_fallback_order);
	suite.add_test("Schema icons: missing 16px frames continue fallback", test_schema_icon_missing_16px);
	suite.add_test("Schema icons: failed image-list insertions", test_schema_icon_failed_insertion);
	suite.add_test("Schema icons: preserve earlier per-size entries", test_schema_icon_preserves_prior_entries);
	suite.add_test("Schema icons: generic fallback and existing entries", test_schema_icon_generic_and_existing_entries);
	suite.add_test("Schema icons: invalid draw indices and unavailable lists", test_schema_icon_draw_indices);
	suite.add_test("Schema icons: only a complete staged Schemas folder wins over the install path", test_schema_root_selection);
	suite.add_test("Schema icons: manifest names stay inside the Schemas folder", test_schema_manifest_names);
	suite.add_test("Schema icons: stale, partial and malformed manifests are incomplete", test_schema_manifest_completeness);
	suite.add_test("Schema icons: StageSchemas manifest and cleanup match the runtime", test_stage_schemas_target_matches_runtime);
#ifdef _WIN32
	suite.add_test("Schema icons: every shipped ICO loads through ExtractIconEx/PrivateExtractIcons", test_schema_icons_load_with_windows);
	suite.add_test("Schema icons: absent or malformed ICO files yield no handle", test_schema_icons_invalid_files);
#endif
}
