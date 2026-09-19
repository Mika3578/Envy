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
	return TransferStateInput{};
}

static bool test_idle_is_queued()
{
	return ClassifyTransferState(EmptyInput()) == TransferState::Queued &&
	       std::strcmp(TransferStateName(TransferState::Queued), "queued") == 0;
}

static bool test_paused_without_error()
{
	TransferStateInput o = EmptyInput();
	o.paused = true;
	return ClassifyTransferState(o) == TransferState::Paused;
}

static bool test_paused_file_error()
{
	TransferStateInput o = EmptyInput();
	o.paused = true;
	o.fileError = true;
	return ClassifyTransferState(o) == TransferState::Error;
}

static bool test_paused_seeder_keeps_paused_on_file_error()
{
	TransferStateInput o = EmptyInput();
	o.paused = true;
	o.fileError = true;
	o.seeding = true;
	o.completed = true;
	return ClassifyTransferState(o) == TransferState::Paused;
}

static bool test_completed_not_seeding()
{
	TransferStateInput o = EmptyInput();
	o.completed = true;
	return ClassifyTransferState(o) == TransferState::Completed &&
	       TransferStateIsTerminalSuccess(TransferState::Completed);
}

static bool test_seeding()
{
	TransferStateInput o = EmptyInput();
	o.completed = true;
	o.seeding = true;
	return ClassifyTransferState(o) == TransferState::Seeding;
}

static bool test_seeding_tracker_error_stays_importable()
{
	TransferStateInput o = EmptyInput();
	o.completed = true;
	o.seeding = true;
	o.trackerError = true;
	return ClassifyTransferState(o) == TransferState::Seeding &&
	       TransferStateIsTerminalSuccess(TransferState::Seeding);
}

static bool test_moving()
{
	TransferStateInput o = EmptyInput();
	o.moving = true;
	return ClassifyTransferState(o) == TransferState::Moving;
}

static bool test_verifying_progress_complete()
{
	TransferStateInput o = EmptyInput();
	o.started = true;
	o.progressComplete = true;
	o.trying = true;
	return ClassifyTransferState(o) == TransferState::Checking;
}

static bool test_downloading()
{
	TransferStateInput o = EmptyInput();
	o.trying = true;
	o.downloading = true;
	return ClassifyTransferState(o) == TransferState::Downloading;
}

static bool test_stalled_has_sources()
{
	TransferStateInput o = EmptyInput();
	o.trying = true;
	o.hasSources = true;
	return ClassifyTransferState(o) == TransferState::Stalled;
}

static bool test_torrent_metadata()
{
	TransferStateInput o = EmptyInput();
	o.trying = true;
	o.torrent = true;
	return ClassifyTransferState(o) == TransferState::Metadata;
}

static bool test_torrent_allocating()
{
	TransferStateInput o = EmptyInput();
	o.trying = true;
	o.torrent = true;
	o.allocating = true;
	return ClassifyTransferState(o) == TransferState::Checking;
}

static bool test_torrent_tracker_error()
{
	TransferStateInput o = EmptyInput();
	o.trying = true;
	o.torrent = true;
	o.trackerError = true;
	return ClassifyTransferState(o) == TransferState::Error;
}

static bool test_clearing_is_unknown_not_complete()
{
	TransferStateInput o = EmptyInput();
	o.clearing = true;
	o.completed = true;
	return ClassifyTransferState(o) == TransferState::Unknown &&
	       !TransferStateIsTerminalSuccess(TransferState::Unknown);
}

static bool test_paused_wins_over_completed_predicates()
{
	TransferStateInput o = EmptyInput();
	o.paused = true;
	o.completed = true;
	o.seeding = true;
	return ClassifyTransferState(o) == TransferState::Paused;
}

static bool test_qbit_completed_is_pausedUP()
{
	return std::strcmp(MapTransferStateToQBittorrent(TransferState::Completed), "pausedUP") == 0 &&
	       QBittorrentStateMeansArrCompleted("pausedUP") &&
	       QBittorrentStateMeansArrCompleted("stoppedUP") &&
	       QBittorrentStateMeansArrCompleted("uploading") &&
	       !QBittorrentStateMeansArrCompleted("downloading") &&
	       !QBittorrentStateMeansArrCompleted("error") &&
	       !QBittorrentStateMeansArrCompleted(nullptr);
}

static bool test_qbit_paused_incomplete()
{
	return std::strcmp(MapTransferStateToQBittorrent(TransferState::Paused), "pausedDL") == 0 &&
	       std::strcmp(MapTransferStateToQBittorrentFinished(TransferState::Paused), "pausedUP") == 0;
}

static bool test_unknown_never_looks_complete()
{
	return TransferUnknownNeverLooksComplete() &&
	       std::strcmp(MapTransferStateToQBittorrent(TransferState::Unknown), "error") == 0 &&
	       std::strcmp(MapTransferStateToQBittorrentFinished(TransferState::Unknown), "error") == 0 &&
	       MapTransferStateToTransmission(TransferState::Unknown) == TransmissionTorrentStatus::Download &&
	       !TransferStateIsTerminalSuccess(TransferState::Unknown);
}

static bool test_transmission_seed_and_stop()
{
	return MapTransferStateToTransmission(TransferState::Seeding) == TransmissionTorrentStatus::Seed &&
	       MapTransferStateToTransmission(TransferState::Paused) == TransmissionTorrentStatus::Stopped &&
	       MapTransferStateToTransmission(TransferState::Checking) == TransmissionTorrentStatus::Check &&
	       MapTransferStateToTransmission(TransferState::Downloading) == TransmissionTorrentStatus::Download;
}

static bool test_metadata_finished_is_error_not_importable()
{
	return std::strcmp(MapTransferStateToQBittorrentFinished(TransferState::Metadata), "error") == 0 &&
	       !QBittorrentStateMeansArrCompleted(MapTransferStateToQBittorrentFinished(TransferState::Metadata));
}

static bool test_downloading_finished_is_error_not_importable()
{
	// Fail-closed: Finished helper must not advertise *UP/importable for in-progress.
	return std::strcmp(MapTransferStateToQBittorrentFinished(TransferState::Downloading), "error") == 0 &&
	       !QBittorrentStateMeansArrCompleted(MapTransferStateToQBittorrentFinished(TransferState::Downloading));
}

void register_transfer_state_smoke_tests(TestSuite& suite)
{
	suite.add_test("transfer_state_idle_queued", test_idle_is_queued);
	suite.add_test("transfer_state_paused", test_paused_without_error);
	suite.add_test("transfer_state_paused_file_error", test_paused_file_error);
	suite.add_test("transfer_state_paused_seeder_file_error", test_paused_seeder_keeps_paused_on_file_error);
	suite.add_test("transfer_state_completed", test_completed_not_seeding);
	suite.add_test("transfer_state_seeding", test_seeding);
	suite.add_test("transfer_state_seeding_tracker_error", test_seeding_tracker_error_stays_importable);
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
	suite.add_test("transfer_state_downloading_finished_not_importable", test_downloading_finished_is_error_not_importable);
}
