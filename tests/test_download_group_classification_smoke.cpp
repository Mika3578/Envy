//
// test_download_group_classification_smoke.cpp
//
// Regression coverage for download-group extension and automatic-schema rules.
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
// License: GNU Affero General Public License v3.0 (AGPLv3)
//

#include "test_framework.h"
#include "../Envy/DownloadGroupClassification.h"

void register_download_group_classification_smoke_tests(TestSuite& suite)
{
	suite.add_test("download groups: case-insensitive exact extensions", [] {
		return DownloadGroupExtensionMatches( L"C:\\Downloads\\Report.PDF", L".pdf" ) &&
			! DownloadGroupExtensionMatches( L"C:\\Downloads\\Report.PDF", L".doc" );
	});

	suite.add_test("download groups: malformed and unknown names", [] {
		return ! DownloadGroupExtensionMatches( L"file", L".pdf" ) &&
			! DownloadGroupExtensionMatches( L"file.", L".pdf" ) &&
			! DownloadGroupExtensionMatches( L".pdf", L".pdf" ) &&
			! DownloadGroupExtensionMatches( L"file.pdf.", L".pdf" ) &&
			! DownloadGroupExtensionMatches( L"file.pdf", L"pdf" ) &&
			! DownloadGroupExtensionMatches( L"file.pdf", L"." );
	});

	suite.add_test("download groups: multipart extension selection", [] {
		return DownloadGroupExtensionMatches( L"archive.tar.GZ", L".gz" ) &&
			DownloadGroupExtensionMatches( L"archive.tar.GZ", L".tar.gz" ) &&
			DownloadGroupExtension( L"archive.tar.GZ" ) == L".gz";
	});

	suite.add_test("download groups: protocol precedence over overlapping file types", [] {
		const std::wstring torrent = L"http://schemas.getenvy.com/BitTorrent.xsd";
		const std::wstring archive = L"http://schemas.getenvy.com/Archive.xsd";
		return DownloadGroupExtensionMatches( L"metadata.torrent", L".torrent" ) &&
			DownloadGroupAutomaticPriority( torrent ) < DownloadGroupAutomaticPriority( archive ) &&
			DownloadGroupAutomaticPrecedes( torrent, L"torrents", archive, L"archives" );
	});

	suite.add_test("download groups: deterministic folder priority and case folding", [] {
		return DownloadGroupAutomaticPrecedes(
			L"http://schemas.getenvy.com/Audio.xsd", L"Music",
			L"http://schemas.getenvy.com/Video.xsd", L"Video") &&
			! DownloadGroupAutomaticPrecedes(
				L"http://schemas.getenvy.com/Audio.xsd", L"z",
				L"http://schemas.getenvy.com/audio.xsd", L"A");
	});
}
