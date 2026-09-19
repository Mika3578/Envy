//
// test_transfer_state_smoke.cpp
//
// Smoke tests for TransferState classification and *arr adapter mappings.
// No MFC, no HTTP, no UI.
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//

#include "test_framework.h"
#include "../Envy/TransferState.h"

#include <cstring>

static TransferStateInput EmptyInput()
{
	TransferStateInput o = {};
	return o;
}

static bool test_idle_is_queued()
{
	return ClassifyTransferState(EmptyInput()) == transferStateQueued && std::strcmp(TransferStateName(transferStateQueued), "queued") == 0;
}

static bool test_paused_without_error()
{
	TransferStateInput o = EmptyInput();
	o.paused = true;
	return ClassifyTransferState(o) == transferStatePaused;
}

static bool test_paused_file_error()
{
	TransferStateInput o = EmptyInput();
	o.paused = true;
	o.fileError = true;
	return ClassifyTransferState(o) == transferStateError;
}

static bool test_paused_seeder_keeps_paused_on_file_error()
{
	TransferStateInput o = EmptyInput();
	o.paused = true;
	o.fileError = true;
	o.seeding = true;
	o.completed = true;
	return ClassifyTransferState(o) == transferStatePaused;
}

static bool test_completed_not_seeding()
{
	TransferStateInput o = EmptyInput();
	o.completed = true;
	return ClassifyTransferState(o) == transferStateCompleted && TransferStateIsTerminalSuccess(transferStateCompleted);
}

static bool test_seeding()
{
	TransferStateInput o = EmptyInput();
	o.completed = true;
	o.seeding = true;
	return ClassifyTransferState(o) == transferStateSeeding;
}

static bool test_moving()
{
	TransferStateInput o = EmptyInput();
	o.moving = true;
	return ClassifyTransferState(o) == transferStateMoving;
}

static bool test_verifying_progress_complete()
{
	TransferStateInput o = EmptyInput();
	o.started = true;
	o.progressComplete = true;
	o.trying = true;
	return ClassifyTransferState(o) == transferStateChecking;
}

static bool test_downloading()
{
	TransferStateInput o = EmptyInput();
	o.trying = true;
	o.downloading = true;
	return ClassifyTransferState(o) == transferStateDownloading;
}

static bool test_stalled_has_sources()
{
	TransferStateInput o = EmptyInput();
	o.trying = true;
	o.hasSources = true;
	return ClassifyTransferState(o) == transferStateStalled;
}

static bool test_torrent_metadata()
{
	TransferStateInput o = EmptyInput();
	o.trying = true;
	o.torrent = true;
	return ClassifyTransferState(o) == transferStateMetadata;
}

static bool test_torrent_allocating()
{
	TransferStateInput o = EmptyInput();
	o.trying = true;
	o.torrent = true;
	o.allocating = true;
	return ClassifyTransferState(o) == transferStateChecking;
}

static bool test_torrent_tracker_error()
{
	TransferStateInput o = EmptyInput();
	o.trying = true;
	o.torrent = true;
	o.trackerError = true;
	return ClassifyTransferState(o) == transferStateError;
}

static bool test_clearing_is_unknown_not_complete()
{
	TransferStateInput o = EmptyInput();
	o.clearing = true;
	o.completed = true;
	return ClassifyTransferState(o) == transferStateUnknown && !TransferStateIsTerminalSuccess(transferStateUnknown);
}

static bool test_paused_wins_over_completed_predicates()
{
	TransferStateInput o = EmptyInput();
	o.paused = true;
	o.completed = true;
	o.seeding = true;
	return ClassifyTransferState(o) == transferStatePaused;
}

static bool test_qbit_completed_is_pausedUP()
{
	return std::strcmp(MapTransferStateToQBittorrent(transferStateCompleted), "pausedUP") == 0 && QBittorrentStateMeansArrCompleted("pausedUP") && QBittorrentStateMeansArrCompleted("stoppedUP") && QBittorrentStateMeansArrCompleted("uploading") && !QBittorrentStateMeansArrCompleted("downloading") && !QBittorrentStateMeansArrCompleted("error") && !QBittorrentStateMeansArrCompleted(nullptr);
}

static bool test_qbit_paused_incomplete()
{
	return std::strcmp(MapTransferStateToQBittorrent(transferStatePaused), "pausedDL") == 0 && std::strcmp(MapTransferStateToQBittorrentFinished(transferStatePaused), "pausedUP") == 0;
}

static bool test_unknown_never_looks_complete()
{
	return TransferUnknownNeverLooksComplete() && std::strcmp(MapTransferStateToQBittorrent(transferStateUnknown), "error") == 0 && std::strcmp(MapTransferStateToQBittorrentFinished(transferStateUnknown), "error") == 0 && MapTransferStateToTransmission(transferStateUnknown) == transmissionStatusDownload && !TransferStateIsTerminalSuccess(transferStateUnknown);
}

static bool test_transmission_seed_and_stop()
{
	return MapTransferStateToTransmission(transferStateSeeding) == transmissionStatusSeed && MapTransferStateToTransmission(transferStatePaused) == transmissionStatusStopped && MapTransferStateToTransmission(transferStateChecking) == transmissionStatusCheck && MapTransferStateToTransmission(transferStateDownloading) == transmissionStatusDownload;
}

static bool test_metadata_finished_is_error_not_importable()
{
	return std::strcmp(MapTransferStateToQBittorrentFinished(transferStateMetadata), "error") == 0 && !QBittorrentStateMeansArrCompleted(
	                                                                                                      MapTransferStateToQBittorrentFinished(transferStateMetadata));
}

void register_transfer_state_smoke_tests(TestSuite& suite)
{
	suite.add_test("transfer_state_idle_queued", test_idle_is_queued);
	suite.add_test("transfer_state_paused", test_paused_without_error);
	suite.add_test("transfer_state_paused_file_error", test_paused_file_error);
	suite.add_test("transfer_state_paused_seeder_file_error", test_paused_seeder_keeps_paused_on_file_error);
	suite.add_test("transfer_state_completed", test_completed_not_seeding);
	suite.add_test("transfer_state_seeding", test_seeding);
	suite.add_test("transfer_state_moving", test_moving);
	suite.add_test("transfer_state_verifying", test_verifying_progress_complete);
	suite.add_test("transfer_state_downloading", test_downloading);
	suite.add_test("transfer_state_stalled", test_stalled_has_sources);
	suite.add_test("transfer_state_torrent_metadata", test_torrent_metadata);
	suite.add_test("transfer_state_torrent_allocating", test_torrent_allocating);
	suite.add_test("transfer_state_torrent_tracker_error", test_torrent_tracker_error);
	suite.add_test("transfer_state_clearing_unknown", test_clearing_is_unknown_not_complete);
	suite.add_test("transfer_state_paused_wins", test_paused_wins_over_completed_predicates);
	suite.add_test("transfer_state_qbit_completed", test_qbit_completed_is_pausedUP);
	suite.add_test("transfer_state_qbit_paused", test_qbit_paused_incomplete);
	suite.add_test("transfer_state_unknown_fail_closed", test_unknown_never_looks_complete);
	suite.add_test("transfer_state_transmission_map", test_transmission_seed_and_stop);
	suite.add_test("transfer_state_metadata_not_importable", test_metadata_finished_is_error_not_importable);
}
