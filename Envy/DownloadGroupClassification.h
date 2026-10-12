//
// DownloadGroupClassification.h
//
// Small, MFC-independent helpers for download-group classification.  Keep
// these rules stable so the native smoke tests cover the same extension and
// automatic-schema precedence used by the Windows application.
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
// License: GNU Affero General Public License v3.0 (AGPLv3)
//

#pragma once

#include <string>
#include <string_view>

inline std::wstring DownloadGroupLowerAscii(std::wstring_view strValue)
{
	std::wstring strResult( strValue );
	for ( wchar_t& ch : strResult )
	{
		if ( ch >= L'A' && ch <= L'Z' )
			ch = wchar_t( ch - L'A' + L'a' );
	}
	return strResult;
}

inline std::wstring DownloadGroupExtension(std::wstring_view strName)
{
	if ( strName.empty() )
		return std::wstring();

	const size_t nSlash = strName.find_last_of( L"\\/" );
	const std::wstring_view strFileName = strName.substr( nSlash == std::wstring_view::npos ? 0 : nSlash + 1 );
	if ( strFileName.empty() || strFileName.back() == L'.' )
		return std::wstring();

	const size_t nDot = strFileName.find_last_of( L'.' );
	if ( nDot == std::wstring_view::npos || nDot == 0 || nDot + 1 >= strFileName.length() )
		return std::wstring();

	return DownloadGroupLowerAscii( strFileName.substr( nDot ) );
}

inline bool DownloadGroupExtensionMatches(std::wstring_view strName, std::wstring_view strFilter)
{
	if ( strFilter.length() < 2 || strFilter.front() != L'.' || strFilter.back() == L'.' )
		return false;

	const size_t nSlash = strName.find_last_of( L"\\/" );
	const std::wstring_view strFileName = strName.substr( nSlash == std::wstring_view::npos ? 0 : nSlash + 1 );
	if ( strFileName.length() <= strFilter.length() || strFileName.front() == L'.' || strFileName.back() == L'.' )
		return false;

	const std::wstring strLowerName = DownloadGroupLowerAscii( strFileName );
	const std::wstring strLowerFilter = DownloadGroupLowerAscii( strFilter );
	return strLowerName.compare( strLowerName.length() - strLowerFilter.length(),
		strLowerFilter.length(), strLowerFilter ) == 0;
}

inline int DownloadGroupAutomaticPriority(std::wstring_view strURI)
{
	const std::wstring strLower = DownloadGroupLowerAscii( strURI );

	// Protocol classification is evaluated before file-type classification.
	if ( strLower == L"http://schemas.getenvy.com/bittorrent.xsd" ) return 0;
	if ( strLower == L"http://schemas.getenvy.com/audio.xsd" ) return 10;
	if ( strLower == L"http://schemas.getenvy.com/video.xsd" ) return 20;
	if ( strLower == L"http://schemas.getenvy.com/image.xsd" ) return 30;
	if ( strLower == L"http://schemas.getenvy.com/book.xsd" ) return 40;
	if ( strLower == L"http://schemas.getenvy.com/archive.xsd" ) return 50;
	if ( strLower == L"http://schemas.getenvy.com/application.xsd" ) return 60;
	if ( strLower == L"http://schemas.getenvy.com/rom.xsd" ) return 70;
	if ( strLower == L"http://schemas.getenvy.com/document.xsd" ) return 80;
	if ( strLower == L"http://schemas.getenvy.com/spreadsheet.xsd" ) return 90;
	if ( strLower == L"http://schemas.getenvy.com/presentation.xsd" ) return 100;
	if ( strLower == L"http://schemas.getenvy.com/sourcecode.xsd" ) return 110;
	if ( strLower == L"http://schemas.getenvy.com/collection.xsd" ) return 120;

	return 1000;
}

inline bool DownloadGroupAutomaticPrecedes(std::wstring_view strCandidateURI,
	std::wstring_view strCandidateFolder, std::wstring_view strCurrentURI,
	std::wstring_view strCurrentFolder)
{
	const int nCandidate = DownloadGroupAutomaticPriority( strCandidateURI );
	const int nCurrent = DownloadGroupAutomaticPriority( strCurrentURI );
	if ( nCandidate != nCurrent )
		return nCandidate < nCurrent;

	const std::wstring strCandidateLower = DownloadGroupLowerAscii( strCandidateURI );
	const std::wstring strCurrentLower = DownloadGroupLowerAscii( strCurrentURI );
	if ( strCandidateLower != strCurrentLower )
		return strCandidateLower < strCurrentLower;

	return DownloadGroupLowerAscii( strCandidateFolder ) < DownloadGroupLowerAscii( strCurrentFolder );
}

