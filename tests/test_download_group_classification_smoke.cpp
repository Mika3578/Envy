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

static std::wstring historical_schema_uri(std::wstring_view strSchemaFile)
{
	return std::wstring(L"http") + L"://schemas.getenvy.com/" + std::wstring(strSchemaFile);
}

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
		const std::wstring torrent = historical_schema_uri( L"BitTorrent.xsd" );
		const std::wstring archive = historical_schema_uri( L"Archive.xsd" );
		return DownloadGroupExtensionMatches( L"metadata.torrent", L".torrent" ) &&
			DownloadGroupAutomaticPriority( torrent ) < DownloadGroupAutomaticPriority( archive ) &&
			DownloadGroupAutomaticPrecedes( torrent, L"torrents", archive, L"archives" );
	});

	suite.add_test("download groups: deterministic folder priority and case folding", [] {
		return DownloadGroupAutomaticPrecedes(
			historical_schema_uri( L"Audio.xsd" ), L"Music",
			historical_schema_uri( L"Video.xsd" ), L"Video") &&
			! DownloadGroupAutomaticPrecedes(
				historical_schema_uri( L"Audio.xsd" ), L"z",
				historical_schema_uri( L"audio.xsd" ), L"A");
	});

	suite.add_test("download groups: historical schema identifiers stay local", [] {
		return DownloadGroupHistoricalSchemaFile( historical_schema_uri( L"Archive.xsd" ) ) == L"archive.xsd" &&
			DownloadGroupAutomaticPriority( std::wstring(L"https") + L"://schemas.getenvy.com/Archive.xsd" ) >= 1000 &&
			DownloadGroupAutomaticPriority( std::wstring(L"http") + L"://other.example/Archive.xsd" ) >= 1000 &&
			DownloadGroupAutomaticPriority( std::wstring(L"http") + L"://schemas.getenvy.com/folder/Archive.xsd" ) >= 1000;
	});
}
