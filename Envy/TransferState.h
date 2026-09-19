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
enum TransferState
{
	transferStateQueued = 0,
	transferStateMetadata,
	transferStateChecking,
	transferStateDownloading,
	transferStateStalled,
	transferStatePaused,
	transferStateCompleted,
	transferStateSeeding,
	transferStateError,
	transferStateMoving,
	transferStateUnknown
};

enum TransferProtocol
{
	transferProtocolUnknown = 0,
	transferProtocolBitTorrent,
	transferProtocolEd2k,
	transferProtocolGnutella,
	transferProtocolGnutella2,
	transferProtocolDirectConnect,
	transferProtocolHttp,
	transferProtocolFtp
};

// Predicate snapshot taken under the downloads lock. No MFC types.
struct TransferStateInput
{
	bool clearing;
	bool paused;
	bool fileError;
	bool completed;
	bool seeding;
	bool moving;
	bool started;
	bool progressComplete; // GetProgress() == 100.0f
	bool trying;
	bool downloading;
	bool hasSources;
	bool torrent;
	bool allocating;
	bool trackerError;
};

inline const char* TransferStateName(TransferState nState)
{
	switch (nState)
	{
	case transferStateQueued: return "queued";
	case transferStateMetadata: return "metadata";
	case transferStateChecking: return "checking";
	case transferStateDownloading: return "downloading";
	case transferStateStalled: return "stalled";
	case transferStatePaused: return "paused";
	case transferStateCompleted: return "completed";
	case transferStateSeeding: return "seeding";
	case transferStateError: return "error";
	case transferStateMoving: return "moving";
	case transferStateUnknown:
	default: return "unknown";
	}
}

inline bool TransferStateIsTerminalSuccess(TransferState nState)
{
	return nState == transferStateCompleted || nState == transferStateSeeding;
}

// Mirrors CDownload::GetDownloadStatus() branch order without localization.
inline TransferState ClassifyTransferState(const TransferStateInput& oIn)
{
	if (oIn.clearing)
		return transferStateUnknown;

	if (oIn.paused)
	{
		// CDownload::GetDownloadStatus(): paused seeders stay paused even
		// when GetFileError() is set; non-seed file errors map to error.
		if (oIn.fileError && !oIn.seeding)
			return transferStateError;
		return transferStatePaused;
	}

	if (oIn.completed)
	{
		if (oIn.seeding)
			return transferStateSeeding;
		return transferStateCompleted;
	}

	if (oIn.moving)
		return transferStateMoving;

	if (oIn.started && oIn.progressComplete)
		return transferStateChecking;

	if (!oIn.trying)
		return transferStateQueued;

	if (oIn.downloading)
		return transferStateDownloading;

	if (oIn.hasSources)
		return transferStateStalled;

	if (oIn.torrent)
	{
		if (oIn.allocating)
			return transferStateChecking;
		if (oIn.trackerError)
			return transferStateError;
		return transferStateMetadata;
	}

	return transferStateQueued;
}

// qBittorrent Web API v2 `state` strings used by Radarr/Sonarr (API 2.8.x
// vocabulary: pausedDL/pausedUP, not stoppedDL/stoppedUP from 2.11+).
inline const char* MapTransferStateToQBittorrent(TransferState nState)
{
	switch (nState)
	{
	case transferStateQueued: return "queuedDL";
	case transferStateMetadata: return "metaDL";
	case transferStateChecking: return "checkingDL";
	case transferStateDownloading: return "downloading";
	case transferStateStalled: return "stalledDL";
	case transferStatePaused: return "pausedDL";
	case transferStateCompleted: return "pausedUP";
	case transferStateSeeding: return "uploading";
	case transferStateError: return "error";
	case transferStateMoving: return "moving";
	case transferStateUnknown:
	default: return "error";
	}
}

// When the download has finished the payload, qBit uses *UP variants.
inline const char* MapTransferStateToQBittorrentFinished(TransferState nState)
{
	switch (nState)
	{
	case transferStateQueued: return "queuedUP";
	case transferStateChecking: return "checkingUP";
	case transferStateStalled: return "stalledUP";
	case transferStatePaused: return "pausedUP";
	case transferStateCompleted: return "pausedUP";
	case transferStateSeeding: return "uploading";
	case transferStateError: return "error";
	case transferStateMoving: return "moving";
	case transferStateDownloading: return "uploading";
	case transferStateMetadata: return "error";
	case transferStateUnknown:
	default: return "error";
	}
}

// Transmission RPC `status` integers (rpc-spec torrent-get).
enum TransmissionTorrentStatus
{
	transmissionStatusStopped = 0,
	transmissionStatusCheckWait = 1,
	transmissionStatusCheck = 2,
	transmissionStatusDownloadWait = 3,
	transmissionStatusDownload = 4,
	transmissionStatusSeedWait = 5,
	transmissionStatusSeed = 6
};

inline int MapTransferStateToTransmission(TransferState nState)
{
	switch (nState)
	{
	case transferStateQueued: return transmissionStatusDownloadWait;
	case transferStateMetadata: return transmissionStatusDownloadWait;
	case transferStateChecking: return transmissionStatusCheck;
	case transferStateDownloading: return transmissionStatusDownload;
	case transferStateStalled: return transmissionStatusDownload;
	case transferStatePaused: return transmissionStatusStopped;
	case transferStateCompleted: return transmissionStatusStopped;
	case transferStateSeeding: return transmissionStatusSeed;
	case transferStateError: return transmissionStatusStopped;
	case transferStateMoving: return transmissionStatusDownload;
	case transferStateUnknown:
	default: return transmissionStatusDownload;
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
	const char* pszQbit = MapTransferStateToQBittorrent(transferStateUnknown);
	const char* pszQbitDone = MapTransferStateToQBittorrentFinished(transferStateUnknown);
	const int nTr = MapTransferStateToTransmission(transferStateUnknown);
	return !QBittorrentStateMeansArrCompleted(pszQbit) &&
	       !QBittorrentStateMeansArrCompleted(pszQbitDone) &&
	       nTr != transmissionStatusSeed &&
	       nTr != transmissionStatusSeedWait &&
	       nTr != transmissionStatusStopped;
}
