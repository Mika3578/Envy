//
// SchemaIconPolicy.h
//
// Schema icon selection and image-list index policies shared with EnvyTests.
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
// License: GNU Affero General Public License v3.0 (AGPLv3)
//

#pragma once

#include <cstddef>
#include <string>

enum class SchemaIconCandidate
{
	Skin,
	Alternate,
	Default,
	Safe
};

/// Try candidates in skin preference order; load succeeds only for a newly inserted 16px frame.
template<typename LoadCandidate>
bool LoadSchemaIconFallback(bool bAlternate, LoadCandidate load)
{
	if (load(SchemaIconCandidate::Skin)) return true;
	if (bAlternate && load(SchemaIconCandidate::Alternate)) return true;
	if (load(SchemaIconCandidate::Default)) return true;
	return load(SchemaIconCandidate::Safe);
}

/// Add each available frame, preserving earlier indices on failure and repairing negative indices.
/// addFrame(size) returns the inserted index, or -1 for a missing frame or failed insertion.
/// Return true only when this candidate supplies a new 16px entry, even if one existed before.
template<typename AddFrame>
bool LoadSchemaIconFrames(int& nIcon16, int& nIcon32, int& nIcon48, int nGeneric, AddFrame addFrame)
{
	int* indices[] = { &nIcon16, &nIcon32, &nIcon48 };
	const int sizes[] = { 16, 32, 48 };
	bool bLoaded = false;
	for (int i = 0; i < 3; ++i)
	{
		const int nAdded = addFrame(sizes[i]);
		if (nAdded >= 0)
		{
			*indices[i] = nAdded;
			if (i == 0) bLoaded = true;
		}
		else if (*indices[i] < 0)
			*indices[i] = nGeneric;
	}
	return bLoaded;
}

/// Return an in-range draw index, the available generic entry, or -1 when drawing must stop.
inline int GetSchemaIconDrawIndex(int nImageCount, int nIcon, int nGeneric)
{
	if (nImageCount <= 0) return -1;
	if (nIcon < 0 || nIcon >= nImageCount) nIcon = nGeneric;
	return nIcon >= 0 && nIcon < nImageCount ? nIcon : -1;
}

/// Name of the file the build writes into a staged Schemas folder, listing one staged file per line.
/// Keep in sync with StageSchemas in Envy.vcxproj.
inline const wchar_t* GetSchemaManifestName()
{
	return L"Schemas.manifest";
}

/// A manifest entry is a plain file name with a schema extension (.xsd, .xml, .ico): no separators, drive
/// letters, "..", spaces or non-ASCII characters, so it can only name a file inside the Schemas folder.
inline bool IsSchemaManifestName(const std::string& sName)
{
	if (sName.empty() || sName.size() > 128 || sName[0] == '.') return false;
	for (char c : sName)
	{
		const bool bOk = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' ||
		                 c == '_' || c == '-';
		if (!bOk) return false;
	}
	if (sName.find("..") != std::string::npos) return false;
	const std::size_t nDot = sName.rfind('.');
	if (nDot == std::string::npos) return false;
	std::string sExt = sName.substr(nDot);
	for (char& c : sExt)
		if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
	return sExt == ".xsd" || sExt == ".xml" || sExt == ".ico";
}

/// True when the manifest text is valid and every listed file exists. exists(name) checks one entry.
/// An empty, unreadable or malformed manifest is never complete, so the caller falls back to another root.
/// Files present but not listed are ignored: the build, not the runtime, owns removing stale ones.
template<typename FileExists>
bool IsSchemaManifestComplete(const std::string& sText, FileExists exists)
{
	std::size_t nPos = sText.compare(0, 3, "\xEF\xBB\xBF") == 0 ? 3 : 0;
	std::size_t nEntries = 0;
	while (nPos < sText.size())
	{
		std::size_t nEnd = sText.find('\n', nPos);
		if (nEnd == std::string::npos) nEnd = sText.size();
		std::string sLine = sText.substr(nPos, nEnd - nPos);
		nPos = nEnd + 1;
		if (!sLine.empty() && sLine.back() == '\r') sLine.pop_back();
		if (sLine.empty()) continue;
		if (!IsSchemaManifestName(sLine) || !exists(sLine)) return false;
		++nEntries;
	}
	return nEntries > 0;
}

/// Pick the directory that holds the Schemas folder to load.
/// A build stages Schemas beside its own executable together with a manifest of what it staged; a persisted
/// General.Path can still name an older installation. The executable's set wins only when the manifest
/// proves it complete. Otherwise General.Path is used when it has schemas (an installed copy, where both
/// folders are the same, behaves as before), and a partial executable set is only a last resort.
/// Return 0 for the executable folder, 1 for General.Path, -1 when neither has schemas.
inline int SelectSchemaRoot(bool bModuleComplete, bool bModuleHasSchemas, bool bConfiguredHasSchemas)
{
	if (bModuleComplete) return 0;
	if (bConfiguredHasSchemas) return 1;
	return bModuleHasSchemas ? 0 : -1;
}
