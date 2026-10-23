//
// SchemaIconPolicy.h
//
// Schema icon selection and image-list index policies shared with EnvyTests.
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
// License: GNU Affero General Public License v3.0 (AGPLv3)
//

#pragma once

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

/// Pick the directory that holds the Schemas folder to load.
/// A build stages Schemas beside its own executable; a persisted General.Path can still name an older
/// installation, so the executable's own set wins when it contains at least one .xsd (completeness is not
/// verified; the build stages the full set). An installed copy is unchanged
/// because its executable folder and General.Path are the same.
/// Return 0 for the executable folder, 1 for General.Path, -1 when neither has schemas.
inline int SelectSchemaRoot(bool bModuleHasSchemas, bool bConfiguredHasSchemas)
{
	if (bModuleHasSchemas) return 0;
	return bConfiguredHasSchemas ? 1 : -1;
}
