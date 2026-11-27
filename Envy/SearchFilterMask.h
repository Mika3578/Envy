//
// SearchFilterMask.h
//
// Canonical codec for Settings.Search.FilterMask.
//
// CMatchList::Filter() (MatchObjects.cpp) is the only writer of this mask,
// so its positions are the persisted contract every reader must use. The
// positions do not follow Shareaza's ordering (which Envy already
// renumbered); they follow the values existing users have persisted.
// Encode/decode go through SearchFilterState so both readers and the
// writer share one code path that EnvyTests can round-trip portably.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
// This file is part of Envy (getenvy.com) (C) 2016-2026
//

#pragma once

inline constexpr unsigned int SEARCH_FILTER_REGEXP = 1u << 0;
inline constexpr unsigned int SEARCH_FILTER_PUSH = 1u << 1;
inline constexpr unsigned int SEARCH_FILTER_UNSTABLE = 1u << 2;
inline constexpr unsigned int SEARCH_FILTER_BUSY = 1u << 3;
inline constexpr unsigned int SEARCH_FILTER_LOCAL = 1u << 4;
inline constexpr unsigned int SEARCH_FILTER_REJECT = 1u << 5;
inline constexpr unsigned int SEARCH_FILTER_BOGUS = 1u << 6;
inline constexpr unsigned int SEARCH_FILTER_DRM = 1u << 7;
inline constexpr unsigned int SEARCH_FILTER_RESTRICTED = 1u << 8;
inline constexpr unsigned int SEARCH_FILTER_SUSPICIOUS = 1u << 9;
inline constexpr unsigned int SEARCH_FILTER_ADULT = 1u << 10;

// One flag per persisted filter bit, named after the CMatchList members
// it feeds; a reader maps these onto its own fields in one place.
struct SearchFilterState
{
	bool bRegExp;
	bool bFilterPush;
	bool bFilterUnstable;
	bool bFilterBusy;
	bool bFilterLocal;
	bool bFilterReject;
	bool bFilterBogus;
	bool bFilterDRM;
	bool bFilterRestricted;
	bool bFilterSuspicious;
	bool bFilterAdult;
};

inline unsigned int EncodeSearchFilterMask(const SearchFilterState& oState)
{
	unsigned int nMask = 0;

	if (oState.bRegExp) nMask |= SEARCH_FILTER_REGEXP;
	if (oState.bFilterPush) nMask |= SEARCH_FILTER_PUSH;
	if (oState.bFilterUnstable) nMask |= SEARCH_FILTER_UNSTABLE;
	if (oState.bFilterBusy) nMask |= SEARCH_FILTER_BUSY;
	if (oState.bFilterLocal) nMask |= SEARCH_FILTER_LOCAL;
	if (oState.bFilterReject) nMask |= SEARCH_FILTER_REJECT;
	if (oState.bFilterBogus) nMask |= SEARCH_FILTER_BOGUS;
	if (oState.bFilterDRM) nMask |= SEARCH_FILTER_DRM;
	if (oState.bFilterRestricted) nMask |= SEARCH_FILTER_RESTRICTED;
	if (oState.bFilterSuspicious) nMask |= SEARCH_FILTER_SUSPICIOUS;
	if (oState.bFilterAdult) nMask |= SEARCH_FILTER_ADULT;

	return nMask;
}

inline SearchFilterState DecodeSearchFilterMask(unsigned int nMask)
{
	SearchFilterState oState;

	oState.bRegExp = (nMask & SEARCH_FILTER_REGEXP) > 0;
	oState.bFilterPush = (nMask & SEARCH_FILTER_PUSH) > 0;
	oState.bFilterUnstable = (nMask & SEARCH_FILTER_UNSTABLE) > 0;
	oState.bFilterBusy = (nMask & SEARCH_FILTER_BUSY) > 0;
	oState.bFilterLocal = (nMask & SEARCH_FILTER_LOCAL) > 0;
	oState.bFilterReject = (nMask & SEARCH_FILTER_REJECT) > 0;
	oState.bFilterBogus = (nMask & SEARCH_FILTER_BOGUS) > 0;
	oState.bFilterDRM = (nMask & SEARCH_FILTER_DRM) > 0;
	oState.bFilterRestricted = (nMask & SEARCH_FILTER_RESTRICTED) > 0;
	oState.bFilterSuspicious = (nMask & SEARCH_FILTER_SUSPICIOUS) > 0;
	oState.bFilterAdult = (nMask & SEARCH_FILTER_ADULT) > 0;

	return oState;
}
