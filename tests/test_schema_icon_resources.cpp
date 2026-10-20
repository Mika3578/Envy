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
#include <string>

#ifdef _WIN32
#include <windows.h>
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
}
