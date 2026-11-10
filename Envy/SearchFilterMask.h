//
// SearchFilterMask.h
//
// Canonical bit layout of the persisted Settings.Search.FilterMask value.
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

#pragma once

#include <cstdint>

// Settings.Search.FilterMask is written by the search result list and read
// back both by that list and by the saved-filter defaults. Every reader and
// writer must go through this header: the bit positions are persisted in the
// user's settings, so they can never be renumbered or reused.
namespace SearchFilterMask
{
enum : uint32_t
{
	RegExp = 1u << 0,
	Push = 1u << 1,
	Unstable = 1u << 2,
	Busy = 1u << 3,
	Local = 1u << 4,
	Reject = 1u << 5,
	Bogus = 1u << 6,
	DRM = 1u << 7,
	Restricted = 1u << 8,
	Suspicious = 1u << 9,
	Adult = 1u << 10,

	// Every bit that currently carries a meaning.
	Known = (1u << 11) - 1,

	// First-run value: hide DRM-protected and suspicious results.
	Default = DRM | Suspicious
};

struct Flags
{
	bool bRegExp = false;
	bool bPush = false;
	bool bUnstable = false;
	bool bBusy = false;
	bool bLocal = false;
	bool bReject = false;
	bool bBogus = false;
	bool bDRM = false;
	bool bRestricted = false;
	bool bSuspicious = false;
	bool bAdult = false;
};

// Unknown high bits are ignored so a mask written by a newer build still
// decodes its known options.
inline Flags Decode(uint32_t nMask) noexcept
{
	Flags oFlags;
	oFlags.bRegExp = (nMask & RegExp) != 0;
	oFlags.bPush = (nMask & Push) != 0;
	oFlags.bUnstable = (nMask & Unstable) != 0;
	oFlags.bBusy = (nMask & Busy) != 0;
	oFlags.bLocal = (nMask & Local) != 0;
	oFlags.bReject = (nMask & Reject) != 0;
	oFlags.bBogus = (nMask & Bogus) != 0;
	oFlags.bDRM = (nMask & DRM) != 0;
	oFlags.bRestricted = (nMask & Restricted) != 0;
	oFlags.bSuspicious = (nMask & Suspicious) != 0;
	oFlags.bAdult = (nMask & Adult) != 0;
	return oFlags;
}

inline uint32_t Encode(const Flags& oFlags) noexcept
{
	uint32_t nMask = 0;
	if (oFlags.bRegExp) nMask |= RegExp;
	if (oFlags.bPush) nMask |= Push;
	if (oFlags.bUnstable) nMask |= Unstable;
	if (oFlags.bBusy) nMask |= Busy;
	if (oFlags.bLocal) nMask |= Local;
	if (oFlags.bReject) nMask |= Reject;
	if (oFlags.bBogus) nMask |= Bogus;
	if (oFlags.bDRM) nMask |= DRM;
	if (oFlags.bRestricted) nMask |= Restricted;
	if (oFlags.bSuspicious) nMask |= Suspicious;
	if (oFlags.bAdult) nMask |= Adult;
	return nMask;
}
}
