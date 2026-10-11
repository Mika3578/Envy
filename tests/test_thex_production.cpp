// SPDX-License-Identifier: AGPL-3.0-or-later
// Production THEX/DIME methods with download, connection and logging doubles.

#include "../Envy/StdAfx.h"
#include "../Envy/Buffer.h"
#include "../Envy/XML.h"
#include "../Envy/XmlParseValidate.h"
#include "test_framework.h"
#include <string_view>

constexpr char TREE_TYPE[] = "http://open-content.net/spec/thex/breadthfirst";
struct TestDownload
{
	QWORD m_nSize = SIZE_UNKNOWN;
	struct Tiger
	{
		operator bool() const { return false; }
		CString toUrn() const { return CString(); }
	} m_oTiger;
	std::vector<BYTE> tree;
	unsigned installs = 0;
	void SetTigerTree(const BYTE* p, DWORD n)
	{
		tree.assign(p, p + n);
		++installs;
	}
	void SetHashset(const BYTE*, DWORD) {}
	bool NeedTigerTree() const { return false; }
	bool GetFragment(void*) const { return true; }
	CString GetDisplayName() const { return CString(); }
};
struct TestSource
{
	BOOL m_bMetaIgnore = FALSE;
	void SetAvailableRanges(void*) {}
};
struct TestSettings
{
	struct
	{
		bool VerifyTiger = false, VerifyED2K = false;
		DWORD ChunkSize = 0;
	} Downloads;
	struct
	{
		unsigned TigerHeight = 0;
	} Library;
} Settings;
struct TestLog
{
	template<typename... Args>
	void Message(Args...) {}
} theApp;
using CLockedBuffer = CBuffer*;

// Deliberately no socket, scheduler, profile ownership or hash verification
// substitute: those integration contracts remain application/live tests.
class CDownloadTransferHTTP
{
public:
	TestDownload download;
	TestDownload* m_pDownload = &download;
	TestSource* m_pSource = NULL;
	CBuffer input;
	CString m_sContentType = L"application/dime", m_sTigerUUID;
	CString m_sAddress, m_sTigerTree, m_sMetadata;
	QWORD m_nLength = 0, m_nContentLength = 0, m_nOffset = 0, m_nPosition = 0;
	BOOL m_bKeepAlive = TRUE, m_bTigerAbandon = FALSE;
	BOOL m_bWantBackwards = FALSE, m_bRecvBackwards = FALSE;
	BOOL m_bTigerFetch = FALSE, m_bMetaFetch = FALSE, m_bTigerIgnore = FALSE;
	DWORD m_tContent = 0;
	struct
	{
		DWORD tLast = 0;
	} m_mInput;
	unsigned m_nRequests = 0, closes = 0, requests = 0;
	CBuffer* GetInput() { return &input; }
	DWORD GetInputLength() const { return input.m_nLength; }
	bool IsInputExist() const { return true; }
	bool IsOutputExist() const { return true; }
	void Close(int) { ++closes; }
	BOOL SendRequest()
	{
		++requests;
		return TRUE;
	}
	void ChunkifyRequest(QWORD*, QWORD*, DWORD, BOOL) {}
	BOOL StartNextFragment();
	BOOL ReadTiger(bool bDropped = false);
	void Begin(QWORD nLength)
	{
		m_nLength = m_nContentLength = nLength;
		download.m_nSize = 1024;
	}
};

// Only locking is replaced: all test calls run on one thread.
#undef ASSUME_LOCK
#define ASSUME_LOCK(section) ((void)0)
#define BLOCK_SIZE 1024
#define BLOCK_MASK 0xFFFFFC00
#include "thex_test_methods.inc"
#undef BLOCK_MASK
#undef BLOCK_SIZE

static void AddDescriptor(CBuffer& o, const char* id = "uuid:first", bool valid = true)
{
	const std::string xml = std::string("<hashtree><file size=\"") + (valid ? "1024" : "999") +
	                        "\"/><digest algorithm=\"http://open-content.net/spec/digest/tiger\" outputsize=\"24\"/>"
	                        "<serializedtree type=\"" +
	                        TREE_TYPE + "\" uri=\"" + id + "\"/></hashtree>";
	o.WriteDIME(1, "", 0, "text/xml", 8, xml.data(), xml.size());
}

static void AddTree(CBuffer& o, std::string_view id = "uuid:first")
{
	const BYTE tree[] = { 1, 2, 3, 4, 5 }; // Odd length exercises record padding.
	o.WriteDIME(2, id.data(), id.size(), TREE_TYPE, sizeof(TREE_TYPE) - 1, tree, sizeof(tree));
}

static bool test_thex_production_all_two_read_splits()
{
	CBuffer wire;
	AddDescriptor(wire);
	const DWORD descriptor = wire.m_nLength;
	AddTree(wire);
	CDownloadTransferHTTP whole;
	whole.Begin(wire.m_nLength);
	whole.input.Add(wire.m_pBuffer, wire.m_nLength);
	if (!whole.ReadTiger() || whole.closes || whole.download.installs != 1 || whole.m_nLength != 0) return false;
	// Includes split XML, the exact descriptor boundary, partial tree header,
	// ID/type, binary payload and padding. Observe intermediate state too.
	for (DWORD cut = 1; cut < wire.m_nLength; ++cut)
	{
		CDownloadTransferHTTP split;
		split.Begin(wire.m_nLength);
		split.input.Add(wire.m_pBuffer, cut);
		if (!split.ReadTiger() || split.closes || split.download.installs) return false;
		if (cut >= descriptor && split.m_sTigerUUID != L"uuid:first") return false;
		split.input.Add(wire.m_pBuffer + cut, wire.m_nLength - cut);
		if (!split.ReadTiger() || split.closes || split.m_nLength != 0 || split.input.m_nLength ||
		    split.download.installs != 1 || split.download.tree != whole.download.tree) return false;
	}
	return true;
}

static bool test_thex_production_identity_reset_and_mismatch()
{
	CBuffer descriptor, wrong;
	AddDescriptor(descriptor);
	AddTree(wrong, "uuid:other");
	CDownloadTransferHTTP transfer;
	transfer.Begin(descriptor.m_nLength + wrong.m_nLength);
	transfer.input.Add(descriptor.m_pBuffer, descriptor.m_nLength);
	if (!transfer.ReadTiger() || transfer.m_sTigerUUID != L"uuid:first") return false;
	transfer.input.Add(wrong.m_pBuffer, wrong.m_nLength);
	if (!transfer.ReadTiger() || transfer.download.installs || !transfer.m_sTigerUUID.IsEmpty()) return false;
	// StartNextFragment above executed the real reset. A second response must
	// accept its own nonempty identity across the same split boundary.
	CBuffer second;
	AddDescriptor(second, "uuid:second");
	const DWORD cut = second.m_nLength;
	AddTree(second, "uuid:second");
	transfer.Begin(second.m_nLength);
	transfer.input.Add(second.m_pBuffer, cut);
	if (!transfer.ReadTiger() || transfer.m_sTigerUUID != L"uuid:second") return false;
	transfer.input.Add(second.m_pBuffer + cut, second.m_nLength - cut);
	return transfer.ReadTiger() && !transfer.closes && transfer.download.installs == 1 && transfer.m_nLength == 0;
}

static bool test_thex_production_truncation_and_malformed()
{
	CBuffer wire;
	AddDescriptor(wire);
	const DWORD descriptor = wire.m_nLength;
	AddTree(wire);
	for (DWORD cut = descriptor; cut < wire.m_nLength; ++cut)
	{
		CDownloadTransferHTTP transfer;
		transfer.Begin(wire.m_nLength);
		transfer.input.Add(wire.m_pBuffer, cut);
		if (!transfer.ReadTiger() || transfer.ReadTiger(true) || transfer.closes || transfer.download.installs) return false;
	}
	const BYTE malformed[12] = {};
	for (bool dropped : { false, true })
	{
		CDownloadTransferHTTP transfer;
		transfer.Begin(sizeof(malformed));
		transfer.input.Add(malformed, sizeof(malformed));
		if (transfer.ReadTiger(dropped) || transfer.closes != (dropped ? 0u : 1u)) return false;
	}
	return true;
}

static bool test_thex_production_rejects_oversize_header_before_body()
{
	const DWORD lengths[] = { XML_PEER_PARSE_CHARS_MAX + 1u, MAXDWORD };
	for (DWORD length : lengths)
	{
		CBuffer wire;
		wire.WriteDIME(1, "", 0, "text/xml", 8, NULL, length);
		CDownloadTransferHTTP transfer;
		transfer.Begin(SIZE_UNKNOWN);
		transfer.input.Add(wire.m_pBuffer, wire.m_nLength);
		if (transfer.ReadTiger() || transfer.closes != 1 || transfer.download.installs) return false;
	}
	// Binary record padding overflow must also fail before waiting for body.
	CBuffer wire;
	wire.WriteDIME(2, "", 0, TREE_TYPE, sizeof(TREE_TYPE) - 1, NULL, MAXDWORD - 1u);
	CDownloadTransferHTTP transfer;
	transfer.Begin(SIZE_UNKNOWN);
	transfer.input.Add(wire.m_pBuffer, wire.m_nLength);
	return !transfer.ReadTiger() && transfer.closes == 1 && !transfer.download.installs;
}

static bool test_thex_production_invalid_descriptor_drains_remaining_response()
{
	CBuffer wire;
	AddDescriptor(wire, "uuid:first", false);
	const DWORD cut = wire.m_nLength;
	AddTree(wire);
	CDownloadTransferHTTP transfer;
	transfer.Begin(wire.m_nLength);
	transfer.input.Add(wire.m_pBuffer, cut);
	if (!transfer.ReadTiger() || !transfer.m_bTigerAbandon || transfer.input.m_nLength) return false;
	transfer.input.Add(wire.m_pBuffer + cut, wire.m_nLength - cut);
	return transfer.ReadTiger() && !transfer.closes && !transfer.download.installs &&
	       !transfer.m_bTigerAbandon && !transfer.input.m_nLength;
}

void RegisterThexProductionTests(TestSuite& suite)
{
	suite.add_test("thex_production_all_two_read_splits", test_thex_production_all_two_read_splits);
	suite.add_test("thex_production_identity_reset_and_mismatch", test_thex_production_identity_reset_and_mismatch);
	suite.add_test("thex_production_truncation_and_malformed", test_thex_production_truncation_and_malformed);
	suite.add_test("thex_production_rejects_oversize_header_before_body", test_thex_production_rejects_oversize_header_before_body);
	suite.add_test("thex_production_invalid_descriptor_drains_remaining_response", test_thex_production_invalid_descriptor_drains_remaining_response);
}
