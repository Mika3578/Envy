//
// SearchFilterMask.h
//
// Canonical bit assignments for Settings.Search.FilterMask (#432).
//
// CMatchList::Filter() (MatchObjects.cpp) is the only writer of this mask,
// so its positions are the persisted contract every reader must use. The
// positions do not follow Shareaza's ordering (which Envy already
// renumbered); they follow the values existing users have persisted.
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
