//
// FlagsState.h
//
// Pure CFlags dimension/index helpers (no CImageList / skin I/O).
// Missing Flags.png must degrade to an empty, drawable-safe object.
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//

#pragma once

struct FlagsDimensions
{
	int Height;
	int Width;
	int ImageListHeight;
	int ImageListWidth;
};

inline void FlagsResetDimensions(FlagsDimensions& dims)
{
	dims.Height = 0;
	dims.Width = 0;
	dims.ImageListHeight = 0;
	dims.ImageListWidth = 0;
}

inline bool FlagsDimensionsAreEmpty(const FlagsDimensions& dims)
{
	return dims.Height <= 0 || dims.Width <= 0 ||
	       dims.ImageListHeight <= 0 || dims.ImageListWidth <= 0;
}

// CImageList::Create rejects non-positive sizes; keep an upper bound so a
// corrupt Flags.png cannot request an enormous list.
inline bool FlagsImageListCreateArgsOk(int cx, int cy, int nInitialCount)
{
	if (cx <= 0 || cy <= 0 || nInitialCount < 0)
		return false;
	if (cx > 256 || cy > 256)
		return false;
	return true;
}

inline int FlagsCountOrZero(bool bHasImageList, int nImageCount)
{
	if (!bHasImageList || nImageCount < 0)
		return 0;
	return nImageCount;
}

inline bool FlagsIndexIsValid(int nIndex, int nCount)
{
	return nIndex >= 0 && nCount > 0 && nIndex < nCount;
}

// Country codes map onto the 26x26 Flags.png matrix. Unknown codes stay -1.
inline int FlagsIndexFromCountryCode(wchar_t nFirst, wchar_t nSecond)
{
	const int nCol = static_cast<int>(nFirst - L'A');
	const int nRow = static_cast<int>(nSecond - L'A');
	if (nCol >= 0 && nCol < 26 && nRow >= 0 && nRow < 26)
		return nCol * 26 + nRow;
	return -1;
}
