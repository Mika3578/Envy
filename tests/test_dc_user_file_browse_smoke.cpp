//
// test_dc_user_file_browse_smoke.cpp
//
// Smoke tests for NMDC hub nick-list merge, hub+nick browse URLs, and
// FileListing validation (no GUI / no live hub).
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//

#include "test_framework.h"
#include "../Envy/DcNickList.h"
#include "../Envy/DcBrowse.h"
#include "../Envy/DcFileListValidate.h"

#include <set>
#include <string>
#include <vector>

static std::vector<std::string> ParseNicks(const char* psz, size_t n = 0)
{
	std::vector<std::string> o;
	if (psz == NULL)
	{
		DcParseNickList(NULL, 0, [&](const char*, size_t)
		                { return TRUE; });
		return o;
	}
	if (n == 0)
		n = strlen(psz);
	DcParseNickList(psz, n, [&](const char* p, size_t nTok)
	                {
		o.emplace_back( p, nTok );
		return TRUE; });
	return o;
}

static bool test_nicklist_nominal()
{
	const auto o = ParseNicks("alice$$bob$$carol$$");
	return o.size() == 3 && o[0] == "alice" && o[1] == "bob" && o[2] == "carol";
}

static bool test_nicklist_empty()
{
	return ParseNicks("").empty() && ParseNicks(NULL).empty() && ParseNicks("$$").empty();
}

static bool test_nicklist_one_user()
{
	const auto o = ParseNicks("alice");
	return o.size() == 1 && o[0] == "alice";
}

static bool test_nicklist_trailing_separator()
{
	const auto o = ParseNicks("alice$$");
	return o.size() == 1 && o[0] == "alice";
}

static bool test_nicklist_empty_nick_skipped()
{
	const auto o = ParseNicks("alice$$$$bob$$");
	return o.size() == 2 && o[0] == "alice" && o[1] == "bob";
}

static bool test_nicklist_truncated_ok()
{
	const auto o = ParseNicks("alice$$bo");
	return o.size() == 2 && o[1] == "bo";
}

static bool test_nicklist_illegal_nick_skipped()
{
	if (DcNickBytesOk("", 0))
		return false;
	if (DcNickBytesOk("a b", 3))
		return false;
	if (DcNickBytesOk("a$b", 3))
		return false;
	if (DcNickBytesOk("a|b", 3))
		return false;
	char szLong[82];
	memset(szLong, 'a', 81);
	szLong[81] = 0;
	if (DcNickBytesOk(szLong, 81))
		return false;
	const auto o = ParseNicks("alice$$bad nick$$bob$$");
	return o.size() == 2 && o[0] == "alice" && o[1] == "bob";
}

static bool test_nicklist_payload_cap()
{
	if (DcNickListPayloadOk(DC_NICKLIST_PAYLOAD_MAX) != TRUE)
		return false;
	if (DcNickListPayloadOk(DC_NICKLIST_PAYLOAD_MAX + 1) != FALSE)
		return false;
	std::string sOver(DC_NICKLIST_PAYLOAD_MAX + 1, 'x');
	return DcParseNickList(sOver.c_str(), sOver.size(), [](const char*, size_t)
	                       { return TRUE; }) == FALSE;
}

static bool test_nicklist_user_cap()
{
	std::string sList;
	sList.reserve(64);
	for (int i = 0; i < 8; ++i)
	{
		sList += "u";
		sList += static_cast<char>('0' + i);
		sList += "$$";
	}
	DWORD nKept = 0;
	const BOOL bOk = DcParseNickList(sList.c_str(), sList.size(), [&](const char*, size_t)
	                                 {
		if ( nKept >= 3 )
			return FALSE;
		++nKept;
		return TRUE; });
	return bOk == TRUE && nKept == 3;
}

static bool test_nicklist_duplicate_tokens()
{
	const auto o = ParseNicks("alice$$alice$$bob$$");
	return o.size() == 3 && o[0] == "alice" && o[1] == "alice" && o[2] == "bob";
}

static bool MergeNickList(std::set<std::string>& oUsers, const char* pszList)
{
	const DWORD nBefore = static_cast<DWORD>(oUsers.size());
	BOOL bOk = DcParseNickList(pszList, strlen(pszList), [&](const char* p, size_t n)
	                           {
		if ( ! DcHubUserCountOk( static_cast< DWORD >( oUsers.size() ) ) )
			return FALSE;
		oUsers.emplace( p, n );
		return TRUE; });
	(void)nBefore;
	return bOk != FALSE;
}

static bool test_myinfo_then_nicklist_no_dup()
{
	std::set<std::string> oUsers;
	oUsers.insert("alice"); // $MyINFO first
	if (!MergeNickList(oUsers, "alice$$bob$$"))
		return false;
	return oUsers.size() == 2 && oUsers.count("alice") && oUsers.count("bob");
}

static bool test_nicklist_then_myinfo_no_dup()
{
	std::set<std::string> oUsers;
	if (!MergeNickList(oUsers, "alice$$bob$$"))
		return false;
	oUsers.insert("alice"); // $MyINFO update
	oUsers.insert("carol");
	return oUsers.size() == 3 && oUsers.count("alice") && oUsers.count("bob") && oUsers.count("carol");
}

static bool test_quit_removes_user()
{
	std::set<std::string> oUsers{ "alice", "bob" };
	oUsers.erase("alice");
	return oUsers.size() == 1 && oUsers.count("bob") && !oUsers.count("alice");
}

static bool test_hub_nick_identity_distinct()
{
	if (DcBrowseTargetsEqual("Alice", "1.2.3.4", 411, "Alice", "1.2.3.4", 411) != TRUE)
		return false;
	if (DcBrowseTargetsEqual("Alice", "1.2.3.4", 411, "Alice", "5.6.7.8", 411) != FALSE)
		return false;
	if (DcBrowseTargetsEqual("Alice", "1.2.3.4", 411, "Bob", "1.2.3.4", 411) != FALSE)
		return false;
	return TRUE;
}

static bool test_browse_url_files_xml()
{
	std::string sUrl;
	if (!DcFormatFileListUrl("alice", "10.0.0.1", 411, sUrl))
		return false;
	return sUrl == "dchub://alice@10.0.0.1:411/files.xml.bz2";
}

static bool test_browse_url_special_nick()
{
	std::string sSpace, sAt;
	if (!DcFormatFileListUrl("John Doe", "10.0.0.1", 411, sSpace))
	{
		// space is illegal in NMDC nick bytes
		if (DcNickBytesOk("John Doe", 8))
			return false;
	}
	else
		return false;
	if (!DcFormatFileListUrl("a@b", "10.0.0.1", 411, sAt))
	{
		if (DcNickBytesOk("a@b", 3))
			return false; // '@' is allowed in nick bytes (not space/$/|)
	}
	// '@' is allowed by DcNickBytesOk; URL must percent-encode it
	if (!DcNickBytesOk("a@b", 3))
		return false;
	if (!DcFormatFileListUrl("a@b", "10.0.0.1", 411, sAt))
		return false;
	if (sAt != "dchub://a%40b@10.0.0.1:411/files.xml.bz2")
		return false;
	std::string sHash;
	if (!DcFormatFileListUrl("n#1", "10.0.0.1", 411, sHash))
		return false;
	return sHash == "dchub://n%231@10.0.0.1:411/files.xml.bz2";
}

static bool test_browse_rejects_bad_target()
{
	std::string sUrl;
	return DcFormatFileListUrl("", "10.0.0.1", 411, sUrl) == FALSE && DcFormatFileListUrl("alice", "bad host", 411, sUrl) == FALSE && DcFormatFileListUrl("alice", "10.0.0.1", 0, sUrl) == FALSE && DcFormatFileListUrl("alice", "10.0.0.1", 70000, sUrl) == FALSE && DcFormatFileListUrl("alice", "999.999.999.999", 411, sUrl) == FALSE && DcBrowseHubIpOk("10.0.0.1") == TRUE && DcBrowseHubIpOk("1.2.3") == FALSE;
}

static bool test_filelist_download_name()
{
	return DcIsFileListDownloadNameW(L"files.xml.bz2") == TRUE && DcIsFileListDownloadNameW(L"files.xml") == TRUE && DcIsFileListDownloadNameW(L"Files of alice.xml.bz2") == TRUE && DcIsFileListDownloadNameW(L"Files of alice 10.0.0.1_411.xml.bz2") == TRUE && DcIsFileListDownloadNameW(L"music.mp3") == FALSE && DcIsFileListDownloadNameW(L"") == FALSE;
}

static const char* kTth = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

static std::string FileTag(const char* pszName, const char* pszSize, const char* pszTth)
{
	std::string s = "<File Name=\"";
	s += pszName;
	s += "\" Size=\"";
	s += pszSize;
	s += "\" TTH=\"";
	s += pszTth;
	s += "\"/>";
	return s;
}

static bool test_filelist_minimal()
{
	const std::string sXml = std::string("<FileListing Version=\"1\">") + FileTag("a.mp3", "1", kTth) + "</FileListing>";
	std::vector<DcFileListEntry> o;
	if (DcParseFileListingXml(sXml.c_str(), sXml.size(), o) != dcFileListOk)
		return false;
	return o.size() == 1 && o[0].sName == "a.mp3" && o[0].nSize == 1 && o[0].sTth == kTth && o[0].sPath.empty();
}

static bool test_filelist_nested_dir()
{
	const std::string sXml = std::string("<FileListing Version=\"1\"><Directory Name=\"FolderA\">") + FileTag("file1.ext", "10", kTth) + "</Directory><Directory Name=\"FolderB\">" + FileTag("file3.ext", "3", kTth) + "</Directory></FileListing>";
	std::vector<DcFileListEntry> o;
	if (DcParseFileListingXml(sXml.c_str(), sXml.size(), o) != dcFileListOk)
		return false;
	return o.size() == 2 && o[0].sPath == "FolderA" && o[0].sName == "file1.ext" && o[1].sPath == "FolderB" && o[1].sName == "file3.ext";
}

static bool test_filelist_several_files()
{
	const std::string sXml = std::string("<FileListing Version=\"1\"><Directory Name=\"D\">") + FileTag("a.bin", "1", kTth) + FileTag("b.bin", "2", kTth) + "</Directory></FileListing>";
	std::vector<DcFileListEntry> o;
	return DcParseFileListingXml(sXml.c_str(), sXml.size(), o) == dcFileListOk && o.size() == 2;
}

static bool test_filelist_invalid_tth()
{
	const std::string sXml = std::string("<FileListing Version=\"1\">") + FileTag("a.mp3", "1", "NOT_A_VALID_TTH____________") + "</FileListing>";
	std::vector<DcFileListEntry> o;
	return DcParseFileListingXml(sXml.c_str(), sXml.size(), o) == dcFileListBadTth && o.empty();
}

static bool test_filelist_invalid_size()
{
	const std::string sNeg = std::string("<FileListing Version=\"1\">") + FileTag("a.mp3", "-1", kTth) + "</FileListing>";
	const std::string sJunk = std::string("<FileListing Version=\"1\">") + FileTag("a.mp3", "12x", kTth) + "</FileListing>";
	std::vector<DcFileListEntry> o;
	return DcParseFileListingXml(sNeg.c_str(), sNeg.size(), o) == dcFileListBadSize && DcParseFileListingXml(sJunk.c_str(), sJunk.size(), o) == dcFileListBadSize;
}

static bool test_filelist_truncated_xml()
{
	const std::string sXml = std::string("<FileListing Version=\"1\">") + FileTag("a.mp3", "1", kTth);
	std::vector<DcFileListEntry> o;
	const DcFileListStatus n = DcParseFileListingXml(sXml.c_str(), sXml.size(), o);
	return n == dcFileListTruncated || n == dcFileListMalformed;
}

static bool test_filelist_malformed_xml()
{
	const char* psz = "<notlisting/>";
	std::vector<DcFileListEntry> o;
	return DcParseFileListingXml(psz, strlen(psz), o) == dcFileListMalformed && DcParseFileListingXml("", 0, o) == dcFileListEmpty;
}

static bool test_filelist_missing_name()
{
	const std::string sXml = std::string("<FileListing Version=\"1\"><File Size=\"1\" TTH=\"") + kTth + "\"/></FileListing>";
	std::vector<DcFileListEntry> o;
	return DcParseFileListingXml(sXml.c_str(), sXml.size(), o) == dcFileListBadName;
}

static bool test_filelist_traversal_rejected()
{
	const std::string sXml = std::string("<FileListing Version=\"1\"><Directory Name=\"..\">") + FileTag("a.mp3", "1", kTth) + "</Directory></FileListing>";
	std::vector<DcFileListEntry> o;
	if (DcParseFileListingXml(sXml.c_str(), sXml.size(), o) != dcFileListTraversal)
		return false;
	const std::string sSlash = std::string("<FileListing Version=\"1\">") + FileTag("a/b.mp3", "1", kTth) + "</FileListing>";
	return DcParseFileListingXml(sSlash.c_str(), sSlash.size(), o) == dcFileListBadName;
}

static bool test_filelist_depth_cap()
{
	std::string sXml = "<FileListing Version=\"1\">";
	for (DWORD i = 0; i < DC_FILELIST_DEPTH_MAX + 2; ++i)
		sXml += "<Directory Name=\"d\">";
	sXml += FileTag("a.mp3", "1", kTth);
	for (DWORD i = 0; i < DC_FILELIST_DEPTH_MAX + 2; ++i)
		sXml += "</Directory>";
	sXml += "</FileListing>";
	std::vector<DcFileListEntry> o;
	return DcParseFileListingXml(sXml.c_str(), sXml.size(), o) == dcFileListTooDeep;
}

static bool test_filelist_entry_cap()
{
	if (DcFileListEntryCountOk(DC_FILELIST_ENTRIES_MAX - 1) != TRUE || DcFileListEntryCountOk(DC_FILELIST_ENTRIES_MAX) != FALSE)
		return false;
	DWORD n = 0;
	std::string sXml = "<FileListing Version=\"1\">";
	for (int i = 0; i < 3; ++i)
		sXml += FileTag("a.mp3", "1", kTth);
	sXml += "</FileListing>";
	std::vector<DcFileListEntry> o;
	if (DcParseFileListingXml(sXml.c_str(), sXml.size(), o) != dcFileListOk)
		return false;
	n = static_cast<DWORD>(o.size());
	return n == 3;
}

static bool test_filelist_uncompressed_cap()
{
	constexpr DWORD kMax = 32u * 1024u * 1024u;
	if (DC_FILELIST_BYTES_MAX != kMax)
		return false;
	return DcFileListUncompressedOk(1) == TRUE && DcFileListUncompressedOk(kMax) == TRUE && DcFileListUncompressedOk(kMax + 1) == FALSE && DcFileListCompressedOk(1) == TRUE && DcFileListCompressedOk(kMax + 1) == FALSE && DcFileListUncompressedOk(0) == FALSE;
}

static bool test_filelist_tth_predicate()
{
	return DcFileListTthOk(L"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA") == TRUE && DcFileListTthOk(L"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") == TRUE && DcFileListTthOk(L"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA") == FALSE && DcFileListTthOk(L"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=") == FALSE && DcFileListTthOk(L"") == FALSE;
}

static bool test_filelist_joined_path_cap()
{
	return DcFileListJoinedPathOk(0, 5, FALSE) == TRUE && DcFileListJoinedPathOk(DC_FILELIST_PATH_MAX, 1, TRUE) == FALSE && DcFileListJoinedPathOk(DC_FILELIST_PATH_MAX - 1, 1, FALSE) == TRUE && DcFileListJoinedPathOk(10, 5, TRUE) == TRUE;
}

static bool test_filelist_prolog_iterative()
{
	std::string sXml;
	sXml.reserve(256);
	for (int i = 0; i < 8; ++i)
		sXml += "<?x?>";
	sXml += "<FileListing Version=\"1\">";
	sXml += FileTag("a.mp3", "1", kTth);
	sXml += "</FileListing>";
	std::vector<DcFileListEntry> o;
	if (DcParseFileListingXml(sXml.c_str(), sXml.size(), o) != dcFileListOk || o.size() != 1)
		return false;
	std::string sMany;
	for (DWORD i = 0; i < DC_FILELIST_PROLOG_MAX + 2; ++i)
		sMany += "<?x?>";
	sMany += "<FileListing Version=\"1\">";
	sMany += FileTag("a.mp3", "1", kTth);
	sMany += "</FileListing>";
	o.clear();
	return DcParseFileListingXml(sMany.c_str(), sMany.size(), o) == dcFileListTooMany;
}

static bool test_filelist_dirs_only()
{
	const char* psz = "<FileListing Version=\"1\"><Directory Name=\"EmptyA\"/><Directory Name=\"EmptyB\"><Directory Name=\"Nested\"/></Directory></FileListing>";
	std::vector<DcFileListEntry> o;
	return DcParseFileListingXml(psz, strlen(psz), o) == dcFileListOk && o.empty();
}

static bool test_filelist_failure_clears_partial()
{
	const std::string sXml = std::string("<FileListing Version=\"1\">") + FileTag("ok.mp3", "1", kTth) + FileTag("bad.mp3", "1", "NOT_A_VALID_TTH____________") + "</FileListing>";
	std::vector<DcFileListEntry> o;
	return DcParseFileListingXml(sXml.c_str(), sXml.size(), o) == dcFileListBadTth && o.empty();
}

static bool test_filelist_truncated_clears_partial()
{
	const std::string sXml = std::string("<FileListing Version=\"1\">") + FileTag("a.mp3", "1", kTth);
	std::vector<DcFileListEntry> o;
	const DcFileListStatus n = DcParseFileListingXml(sXml.c_str(), sXml.size(), o);
	return (n == dcFileListTruncated || n == dcFileListMalformed) && o.empty();
}

static bool test_browse_tree_notify()
{
	static const char szHit = 0;
	return DcBrowseShareTreeNeeded(NULL, FALSE) == FALSE && DcBrowseShareTreeNeeded(NULL, TRUE) == TRUE && DcBrowseShareTreeNeeded(&szHit, FALSE) == TRUE;
}

static bool test_filelist_parent_path()
{
	const char* psz = "FolderA\\FolderB\\file.ext";
	const char* pParent = NULL;
	size_t nParent = 0;
	const char* pFile = NULL;
	size_t nFile = 0;
	if (!DcFileListSplitParentUtf8(psz, strlen(psz), pParent, nParent, pFile, nFile))
		return false;
	if (nParent != strlen("FolderA\\FolderB") || strncmp(pParent, "FolderA\\FolderB", nParent) != 0)
		return false;
	if (nFile != 8 || strncmp(pFile, "file.ext", 8) != 0)
		return false;
	const char* pszRoot = "root.mp3";
	if (!DcFileListSplitParentUtf8(pszRoot, strlen(pszRoot), pParent, nParent, pFile, nFile))
		return false;
	return nParent == 0 && nFile == 8 && strncmp(pFile, "root.mp3", 8) == 0;
}

void register_dc_user_file_browse_smoke_tests(TestSuite& suite)
{
	suite.add_test("dc_nicklist_nominal", test_nicklist_nominal);
	suite.add_test("dc_nicklist_empty", test_nicklist_empty);
	suite.add_test("dc_nicklist_one_user", test_nicklist_one_user);
	suite.add_test("dc_nicklist_trailing_separator", test_nicklist_trailing_separator);
	suite.add_test("dc_nicklist_empty_nick_skipped", test_nicklist_empty_nick_skipped);
	suite.add_test("dc_nicklist_truncated_ok", test_nicklist_truncated_ok);
	suite.add_test("dc_nicklist_illegal_nick_skipped", test_nicklist_illegal_nick_skipped);
	suite.add_test("dc_nicklist_payload_cap", test_nicklist_payload_cap);
	suite.add_test("dc_nicklist_user_cap", test_nicklist_user_cap);
	suite.add_test("dc_nicklist_duplicate_tokens", test_nicklist_duplicate_tokens);
	suite.add_test("dc_myinfo_then_nicklist_no_dup", test_myinfo_then_nicklist_no_dup);
	suite.add_test("dc_nicklist_then_myinfo_no_dup", test_nicklist_then_myinfo_no_dup);
	suite.add_test("dc_quit_removes_user", test_quit_removes_user);
	suite.add_test("dc_hub_nick_identity_distinct", test_hub_nick_identity_distinct);
	suite.add_test("dc_browse_url_files_xml", test_browse_url_files_xml);
	suite.add_test("dc_browse_url_special_nick", test_browse_url_special_nick);
	suite.add_test("dc_browse_rejects_bad_target", test_browse_rejects_bad_target);
	suite.add_test("dc_filelist_download_name", test_filelist_download_name);
	suite.add_test("dc_filelist_minimal", test_filelist_minimal);
	suite.add_test("dc_filelist_nested_dir", test_filelist_nested_dir);
	suite.add_test("dc_filelist_several_files", test_filelist_several_files);
	suite.add_test("dc_filelist_invalid_tth", test_filelist_invalid_tth);
	suite.add_test("dc_filelist_invalid_size", test_filelist_invalid_size);
	suite.add_test("dc_filelist_truncated_xml", test_filelist_truncated_xml);
	suite.add_test("dc_filelist_malformed_xml", test_filelist_malformed_xml);
	suite.add_test("dc_filelist_missing_name", test_filelist_missing_name);
	suite.add_test("dc_filelist_traversal_rejected", test_filelist_traversal_rejected);
	suite.add_test("dc_filelist_depth_cap", test_filelist_depth_cap);
	suite.add_test("dc_filelist_entry_cap", test_filelist_entry_cap);
	suite.add_test("dc_filelist_uncompressed_cap", test_filelist_uncompressed_cap);
	suite.add_test("dc_filelist_tth_predicate", test_filelist_tth_predicate);
	suite.add_test("dc_filelist_joined_path_cap", test_filelist_joined_path_cap);
	suite.add_test("dc_filelist_prolog_iterative", test_filelist_prolog_iterative);
	suite.add_test("dc_filelist_dirs_only", test_filelist_dirs_only);
	suite.add_test("dc_filelist_failure_clears_partial", test_filelist_failure_clears_partial);
	suite.add_test("dc_filelist_truncated_clears_partial", test_filelist_truncated_clears_partial);
	suite.add_test("dc_browse_tree_notify", test_browse_tree_notify);
	suite.add_test("dc_filelist_parent_path", test_filelist_parent_path);
}
