//
// AdaptiveListColumns.h
//
// Pure report-list column width allocation for DPI-aware layouts.
// Shared with EnvyTests — no MFC dependency.
//
// Column kinds:
//   Fixed    — small fields (ports, counts); preferred == min == max after scale
//   Bounded  — address / time / client / country; start at preferred, shrink toward
//              min when the row is too wide; max clamps sticky/preferred (no leftover grow)
//   Flexible — name / description / title; absorb leftover width by weight
//
// Sticky widths (user-resized) are kept and clamped to the scaled [min, max]
// for that column (fixed/bounded max matters; flexible max is usually INT_MAX).
// No registry I/O belongs here — callers must not SaveList from WM_SIZE.
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//

#pragma once

#include <climits>

#ifndef FALSE
inline constexpr int FALSE = 0;
inline constexpr int TRUE = 1;
using BOOL = int;
#endif

enum class AdaptiveColumnKind
{
	Fixed = 0,
	Bounded = 1,
	Flexible = 2
};

// C++17 stand-ins for `using enum AdaptiveColumnKind` (C++20 / cpp:S6177).
inline constexpr AdaptiveColumnKind AdaptiveColumnFixed = AdaptiveColumnKind::Fixed;
inline constexpr AdaptiveColumnKind AdaptiveColumnBounded = AdaptiveColumnKind::Bounded;
inline constexpr AdaptiveColumnKind AdaptiveColumnFlexible = AdaptiveColumnKind::Flexible;

struct AdaptiveColumnSpec
{
	AdaptiveColumnKind nKind;
	int nPreferred;   // Design pixels at 100% scaling
	int nMin;         // Design pixels at 100% scaling
	int nMax;         // Design pixels at 100% scaling (INT_MAX ok for flex)
	int nWeight;      // Flexible weight; ignored for Fixed
	BOOL bSticky;     // Preserve nStickyWidth when TRUE
	int nStickyWidth; // Current user width when bSticky
	BOOL bHidden;     // Force width 0 (e.g. unused Flow / debug cols)
};

// Match StdAfx.h SCALE(): under 110% keep design pixels.
inline int AdaptiveScalePx(int nDesignPx, int nScalePercent)
{
	if (nDesignPx <= 0)
		return 0;
	if (nScalePercent < 110)
		return nDesignPx;
	// Saturating multiply in 64-bit: design * scale / 100, clamp to INT_MAX.
	const long long nScaled =
	    ((long long)nDesignPx * (long long)nScalePercent) / 100LL;
	if (nScaled >= (long long)INT_MAX)
		return INT_MAX;
	return (int)nScaled;
}

inline int AdaptiveClampInt(int nValue, int nMin, int nMax)
{
	if (nValue < nMin)
		return nMin;
	if (nValue > nMax)
		return nMax;
	return nValue;
}

inline int AdaptiveScaledMaxPx(int nMaxDesign, int nMinScaled, int nScalePercent)
{
	int nMax = (nMaxDesign >= INT_MAX / 2)
	               ? INT_MAX
	               : AdaptiveScalePx(nMaxDesign, nScalePercent);
	if (nMax < nMinScaled)
		nMax = nMinScaled;
	return nMax;
}

inline bool AdaptiveIsGrowableFlex(const AdaptiveColumnSpec& s)
{
	return !s.bHidden && !s.bSticky && s.nKind == AdaptiveColumnFlexible &&
	       s.nWeight > 0;
}

inline int AdaptiveInitialColumnWidth(const AdaptiveColumnSpec& s, int nScalePercent)
{
	if (s.bHidden)
		return 0;

	const int nMin = AdaptiveScalePx(s.nMin, nScalePercent);
	const int nMax = AdaptiveScaledMaxPx(s.nMax, nMin, nScalePercent);
	if (s.bSticky)
		return AdaptiveClampInt(s.nStickyWidth, nMin, nMax);

	const int nPref = AdaptiveScalePx(s.nPreferred, nScalePercent);
	return AdaptiveClampInt(nPref, nMin, nMax);
}

inline long long AdaptiveFlexRoom(const AdaptiveColumnSpec& s, int nWidth, int nScalePercent)
{
	const int nMin = AdaptiveScalePx(s.nMin, nScalePercent);
	const int nMax = AdaptiveScaledMaxPx(s.nMax, nMin, nScalePercent);
	return (long long)nMax - nWidth;
}

inline void AdaptiveSeedColumnWidths(
    int nScalePercent,
    const AdaptiveColumnSpec* pSpecs,
    int nCount,
    int* pOutWidths,
    long long& nUsed,
    long long& nFlexWeight)
{
	nUsed = 0;
	nFlexWeight = 0;
	for (int i = 0; i < nCount; ++i)
	{
		const AdaptiveColumnSpec& s = pSpecs[i];
		pOutWidths[i] = AdaptiveInitialColumnWidth(s, nScalePercent);
		nUsed += pOutWidths[i];
		if (AdaptiveIsGrowableFlex(s))
			nFlexWeight += s.nWeight;
	}
}

inline bool AdaptiveGiveFlexRemainderPass(
    int nScalePercent,
    const AdaptiveColumnSpec* pSpecs,
    int nCount,
    int* pOutWidths,
    long long& nExtra,
    long long& nUsed)
{
	bool bProgress = false;
	for (int i = 0; i < nCount; ++i)
	{
		if (nExtra <= 0)
			break;

		const AdaptiveColumnSpec& s = pSpecs[i];
		if (!AdaptiveIsGrowableFlex(s))
			continue;

		const long long nRoom = AdaptiveFlexRoom(s, pOutWidths[i], nScalePercent);
		if (nRoom <= 0)
			continue;

		long long nGive = nRoom;
		if (nGive > nExtra)
			nGive = nExtra;
		pOutWidths[i] += (int)nGive;
		nExtra -= nGive;
		nUsed += nGive;
		bProgress = true;
	}
	return bProgress;
}

inline void AdaptiveGrowFlexibleColumns(
    long long nAvail,
    int nScalePercent,
    const AdaptiveColumnSpec* pSpecs,
    int nCount,
    int* pOutWidths,
    long long& nUsed,
    long long nFlexWeight)
{
	if (nAvail <= nUsed || nFlexWeight <= 0)
		return;

	long long nExtra = nAvail - nUsed;
	long long nWeightLeft = nFlexWeight;
	for (int i = 0; i < nCount; ++i)
	{
		if (nExtra <= 0 || nWeightLeft <= 0)
			break;

		const AdaptiveColumnSpec& s = pSpecs[i];
		if (!AdaptiveIsGrowableFlex(s))
			continue;

		const long long nRoom = AdaptiveFlexRoom(s, pOutWidths[i], nScalePercent);
		if (nRoom < 0)
		{
			nWeightLeft -= s.nWeight;
			continue;
		}

		long long nShare = (nExtra * s.nWeight) / nWeightLeft;
		if (nShare < 0)
			nShare = 0;
		if (nShare > nRoom)
			nShare = nRoom;
		pOutWidths[i] += (int)nShare;
		nExtra -= nShare;
		nUsed += nShare;
		nWeightLeft -= s.nWeight;
	}

	// Remainder: keep giving to flexible columns with room until exhausted
	// (a fixed pass count can strand leftover when an earlier column saturates).
	while (nExtra > 0 && AdaptiveGiveFlexRemainderPass(
	                         nScalePercent, pSpecs, nCount, pOutWidths, nExtra, nUsed))
	{
		// Extra width remains only while at least one flex column still has room.
	}
}

inline void AdaptiveShrinkKind(
    AdaptiveColumnKind nKind,
    int nScalePercent,
    const AdaptiveColumnSpec* pSpecs,
    int nCount,
    int* pOutWidths,
    long long& nOver,
    long long& nUsed)
{
	for (int i = 0; i < nCount; ++i)
	{
		if (nOver <= 0)
			break;

		const AdaptiveColumnSpec& s = pSpecs[i];
		if (s.bHidden || s.bSticky || s.nKind != nKind)
			continue;

		const int nMin = AdaptiveScalePx(s.nMin, nScalePercent);
		const int nCan = pOutWidths[i] - nMin;
		if (nCan <= 0)
			continue;

		const int nCut = (nOver > nCan) ? nCan : (int)nOver;
		pOutWidths[i] -= nCut;
		nOver -= nCut;
		nUsed -= nCut;
	}
}

inline void AdaptiveShrinkOverflowColumns(
    long long nAvail,
    int nScalePercent,
    const AdaptiveColumnSpec* pSpecs,
    int nCount,
    int* pOutWidths,
    long long& nUsed)
{
	if (nUsed <= nAvail)
		return;

	long long nOver = nUsed - nAvail;
	AdaptiveShrinkKind(
	    AdaptiveColumnFlexible, nScalePercent, pSpecs, nCount, pOutWidths, nOver, nUsed);
	AdaptiveShrinkKind(
	    AdaptiveColumnBounded, nScalePercent, pSpecs, nCount, pOutWidths, nOver, nUsed);
	// Fixed/sticky stay at clamped widths; leftover overage keeps horizontal scroll
	// rather than producing negative widths.
}

// Allocate column widths into pOutWidths[0..nCount).
// nClientWidth is the list client width (caller subtracts scrollbar if desired).
// Returns FALSE if inputs are unusable; pOutWidths still filled with safe mins.
inline BOOL AdaptiveAllocateColumns(
    int nClientWidth,
    int nScalePercent,
    const AdaptiveColumnSpec* pSpecs,
    int nCount,
    int* pOutWidths)
{
	if (!pSpecs || !pOutWidths || nCount <= 0)
		return FALSE;

	if (nScalePercent < 100)
		nScalePercent = 100;
	if (nScalePercent > 200)
		nScalePercent = 200;

	if (nClientWidth < 0)
		nClientWidth = 0;

	long long nUsed = 0;
	long long nFlexWeight = 0;
	AdaptiveSeedColumnWidths(
	    nScalePercent, pSpecs, nCount, pOutWidths, nUsed, nFlexWeight);

	const long long nAvail = nClientWidth;
	AdaptiveGrowFlexibleColumns(
	    nAvail, nScalePercent, pSpecs, nCount, pOutWidths, nUsed, nFlexWeight);
	AdaptiveShrinkOverflowColumns(
	    nAvail, nScalePercent, pSpecs, nCount, pOutWidths, nUsed);

	for (int i = 0; i < nCount; ++i)
	{
		if (pOutWidths[i] < 0)
			pOutWidths[i] = 0;
	}

	return TRUE;
}
