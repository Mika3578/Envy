//
// Ed2kFileRequestOutcome.h
//
// Decision policy for ED2K FILEREQUEST replies.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
// This file is part of Envy (getenvy.com) (C) 2016-2026
//

#pragma once

// A transient Library lock timeout must not become a protocol-visible
// FILENOTFOUND for a shared-only file: eMule/aMule peers re-ask, so the
// busy case defers by silence instead of reporting a missing file.
enum class Ed2kFileRequestOutcome : unsigned char
{
	AnswerShared,   // Shared and uploadable: FILEREQANSWER + comments
	AnswerDownload, // Active download source: FILEREQANSWER with its name
	DeferredBusy,   // Library lock unavailable: no reply, peer re-asks
	NotFound        // Genuinely missing or not uploadable: FILENOTFOUND
};

// Precedence: a shared file the queues can serve wins over an active
// download, a download match wins over deferral and a real miss, and
// contention defers before any negative reply is produced.
inline Ed2kFileRequestOutcome Ed2kResolveFileRequestOutcome(
    bool bLibraryLockHeld,
    bool bSharedFileAvailable,
    bool bDownloadMatch)
{
	if (bLibraryLockHeld && bSharedFileAvailable)
		return Ed2kFileRequestOutcome::AnswerShared;
	if (bDownloadMatch)
		return Ed2kFileRequestOutcome::AnswerDownload;
	if (!bLibraryLockHeld)
		return Ed2kFileRequestOutcome::DeferredBusy;
	return Ed2kFileRequestOutcome::NotFound;
}
