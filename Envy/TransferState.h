//
// TransferState.h
//
// Stable transfer-state vocabulary for the future native Remote API and
// *arr compatibility adapters. Independent of MFC, localized UI strings,
// and HTTP. Map from Envy download predicates; never from GetDownloadStatus()
// display text (those strings change with language packs).
//
// Unknown Envy combinations must not become a success/completed state in
// qBittorrent or Transmission mappings (fail closed).
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//

#pragma once

#include <cstring>

// Stable API states. Do not expose historical IDS_STATUS_* strings.
enum class TransferState
{
	Queued = 0,
	Metadata,
	Checking,
	Downloading,
	Stalled,
	Paused,
	Completed,
	Seeding,
	Error,
	Moving,
	Unknown
};

enum class TransferProtocol
{
	Unknown = 0,
	BitTorrent,
	Ed2k,
	Gnutella,
	Gnutella2,
	DirectConnect,
	Http,
	Ftp
};

// Predicate snapshot taken under the downloads lock. No MFC types.
// Value-initialized members: aggregate `{}` is defined (all false).
struct TransferStateInput
{
	bool clearing = false;
	bool paused = false;
	bool fileError = false;
	bool completed = false;
	bool seeding = false;
	bool moving = false;
	bool started = false;
	bool progressComplete = false; // GetProgress() == 100.0f
	bool trying = false;
	bool downloading = false;
	bool hasSources = false;
	bool torrent = false;
	bool allocating = false;
	bool trackerError = false;
};

inline const char* TransferStateName(TransferState nState)
{
	switch (nState)
	{
	case TransferState::Queued:
		return "queued";
	case TransferState::Metadata:
		return "metadata";
	case TransferState::Checking:
		return "checking";
	case TransferState::Downloading:
		return "downloading";
	case TransferState::Stalled:
		return "stalled";
	case TransferState::Paused:
		return "paused";
	case TransferState::Completed:
		return "completed";
	case TransferState::Seeding:
		return "seeding";
	case TransferState::Error:
		return "error";
	case TransferState::Moving:
		return "moving";
	case TransferState::Unknown:
	default:
		return "unknown";
	}
}

inline bool TransferStateIsTerminalSuccess(TransferState nState)
{
	return nState == TransferState::Completed || nState == TransferState::Seeding;
}

// Mirrors CDownload::GetDownloadStatus() branch order (Download.cpp:
// clearing, IsPaused, IsCompleted, IsMoving, started&&100%, !IsTrying,
// IsDownloading, GetEffectiveSourceCount, IsTorrent, else queued).
// paused-before-completed is required: IsPaused() is tested first there.
// Completed+seeding+trackerError stays Seeding (not Error) so *arr still
// sees a finished payload; the UI string IDS_STATUS_TRACKERDOWN is local.
inline TransferState ClassifyTransferState(const TransferStateInput& oIn)
{
	if (oIn.clearing)
		return TransferState::Unknown;

	if (oIn.paused)
	{
		// Paused seeders stay paused even when GetFileError() is set.
		if (oIn.fileError && !oIn.seeding)
			return TransferState::Error;
		return TransferState::Paused;
	}

	if (oIn.completed)
	{
		if (oIn.seeding)
			return TransferState::Seeding;
		return TransferState::Completed;
	}

	if (oIn.moving)
		return TransferState::Moving;

	if (oIn.started && oIn.progressComplete)
		return TransferState::Checking;

	if (!oIn.trying)
		return TransferState::Queued;

	if (oIn.downloading)
		return TransferState::Downloading;

	if (oIn.hasSources)
		return TransferState::Stalled;

	if (oIn.torrent)
	{
		if (oIn.allocating)
			return TransferState::Checking;
		if (oIn.trackerError)
			return TransferState::Error;
		return TransferState::Metadata;
	}

	return TransferState::Queued;
}

// qBittorrent Web API v2 `state` strings used by Radarr/Sonarr (API 2.8.x
// vocabulary: pausedDL/pausedUP, not stoppedDL/stoppedUP from 2.11+).
inline const char* MapTransferStateToQBittorrent(TransferState nState)
{
	switch (nState)
	{
	case TransferState::Queued:
		return "queuedDL";
	case TransferState::Metadata:
		return "metaDL";
	case TransferState::Checking:
		return "checkingDL";
	case TransferState::Downloading:
		return "downloading";
	case TransferState::Stalled:
		return "stalledDL";
	case TransferState::Paused:
		return "pausedDL";
	case TransferState::Completed:
		return "pausedUP";
	case TransferState::Seeding:
		return "uploading";
	case TransferState::Error:
		return "error";
	case TransferState::Moving:
		return "moving";
	case TransferState::Unknown:
	default:
		return "error";
	}
}

// When the download has finished the payload, qBit uses *UP variants.
inline const char* MapTransferStateToQBittorrentFinished(TransferState nState)
{
	switch (nState)
	{
	case TransferState::Queued:
		return "queuedUP";
	case TransferState::Checking:
		return "checkingUP";
	case TransferState::Stalled:
		return "stalledUP";
	case TransferState::Paused:
		return "pausedUP";
	case TransferState::Completed:
		return "pausedUP";
	case TransferState::Seeding:
		return "uploading";
	case TransferState::Error:
		return "error";
	case TransferState::Moving:
		return "moving";
	case TransferState::Downloading:
		return "uploading";
	case TransferState::Metadata:
		return "error";
	case TransferState::Unknown:
	default:
		return "error";
	}
}

// Transmission RPC `status` integers (rpc-spec torrent-get).
enum class TransmissionTorrentStatus
{
	Stopped = 0,
	CheckWait = 1,
	Check = 2,
	DownloadWait = 3,
	Download = 4,
	SeedWait = 5,
	Seed = 6
};

inline TransmissionTorrentStatus MapTransferStateToTransmission(TransferState nState)
{
	switch (nState)
	{
	case TransferState::Queued:
		return TransmissionTorrentStatus::DownloadWait;
	case TransferState::Metadata:
		return TransmissionTorrentStatus::DownloadWait;
	case TransferState::Checking:
		return TransmissionTorrentStatus::Check;
	case TransferState::Downloading:
		return TransmissionTorrentStatus::Download;
	case TransferState::Stalled:
		return TransmissionTorrentStatus::Download;
	case TransferState::Paused:
		return TransmissionTorrentStatus::Stopped;
	case TransferState::Completed:
		return TransmissionTorrentStatus::Stopped;
	case TransferState::Seeding:
		return TransmissionTorrentStatus::Seed;
	case TransferState::Error:
		return TransmissionTorrentStatus::Stopped;
	case TransferState::Moving:
		return TransmissionTorrentStatus::Download;
	case TransferState::Unknown:
	default:
		return TransmissionTorrentStatus::Download;
	}
}

inline bool QBittorrentStateMeansArrCompleted(const char* pszState)
{
	if (pszState == nullptr)
		return false;
	return std::strcmp(pszState, "pausedUP") == 0 ||
	       std::strcmp(pszState, "stoppedUP") == 0 ||
	       std::strcmp(pszState, "uploading") == 0 ||
	       std::strcmp(pszState, "stalledUP") == 0 ||
	       std::strcmp(pszState, "queuedUP") == 0 ||
	       std::strcmp(pszState, "forcedUP") == 0;
}

inline bool TransferUnknownNeverLooksComplete()
{
	const char* pszQbit = MapTransferStateToQBittorrent(TransferState::Unknown);
	const char* pszQbitDone = MapTransferStateToQBittorrentFinished(TransferState::Unknown);
	const TransmissionTorrentStatus nTr = MapTransferStateToTransmission(TransferState::Unknown);
	return !QBittorrentStateMeansArrCompleted(pszQbit) &&
	       !QBittorrentStateMeansArrCompleted(pszQbitDone) &&
	       nTr != TransmissionTorrentStatus::Seed &&
	       nTr != TransmissionTorrentStatus::SeedWait &&
	       nTr != TransmissionTorrentStatus::Stopped;
}
