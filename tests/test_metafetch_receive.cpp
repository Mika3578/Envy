// SPDX-License-Identifier: AGPL-3.0-or-later
// Run the production MetaFetch receive state machine over a scripted socket.
// Standalone harness: no MFC precompiled header (see AGENTS.md portable tests).
//
// ReadInput, ReceiveMetadataInput and ReadMetadata are extracted unchanged.
// Socket reads, response-line/header parsing and the metadata branches of
// OnHeadersComplete/OnDropped are modelled on CConnection and
// CDownloadTransferHTTP so the receive caps, phase changes and fail-closed
// paths execute exactly as the application dispatches them.

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include "../Envy/DownloadTransferHttpValidate.h"
#include "../Envy/XmlParseValidate.h"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

typedef unsigned long long QWORD;
const QWORD SIZE_UNKNOWN = ~0ull;
enum TRISTATE
{
	TRI_UNKNOWN,
	TRI_FALSE,
	TRI_TRUE
};
enum
{
	MSG_ERROR = 1
};
enum
{
	dtsNull,
	dtsConnecting,
	dtsRequesting,
	dtsHeaders,
	dtsDownloading,
	dtsFlushing,
	dtsTiger,
	dtsHashset,
	dtsMetadata
};
#define ASSUME_LOCK(section) ((void)0)

constexpr DWORD BODY_CAP = XML_PEER_PARSE_CHARS_MAX;

class CString
{
public:
	CString() = default;
	explicit CString(std::wstring s)
	    : m_s(std::move(s))
	{
	}
	operator LPCTSTR() const { return m_s.c_str(); }
	std::wstring m_s;
};

struct TestLog
{
	template<typename... Args>
	void Message(Args...) {}
} theApp;

struct CBuffer
{
	std::vector<char> m_oData;
	DWORD m_nLength = 0;
	void Add(const char* p, size_t n)
	{
		m_oData.insert(m_oData.end(), p, p + n);
		m_nLength = static_cast<DWORD>(m_oData.size());
	}
	void Remove(DWORD n)
	{
		n = std::min(n, m_nLength);
		m_oData.erase(m_oData.begin(), m_oData.begin() + n);
		m_nLength = static_cast<DWORD>(m_oData.size());
	}
	// ASCII fixtures only: widen bytes one to one.
	CString ReadString(DWORD n, unsigned) const
	{
		return CString(std::wstring(m_oData.begin(), m_oData.begin() + std::min(n, m_nLength)));
	}
};
using CLockedBuffer = CBuffer*;

// Parser double: accepts a document that looks like XML and records its size.
struct CXMLElement
{
	size_t m_nChars;
	static CXMLElement* FromPeerString(const CString& s, BOOL)
	{
		return s.m_s.empty() || s.m_s[0] != L'<' ? nullptr : new CXMLElement{ s.m_s.size() };
	}
};

struct TestDownload
{
	unsigned m_nMerges = 0;
	size_t m_nChars = 0;
	void MergeMetadata(const CXMLElement* pXML)
	{
		++m_nMerges;
		m_nChars = pXML->m_nChars;
	}
};

class CDownloadTransfer
{
public:
	unsigned m_nOtherPaths = 0;
	BOOL OnRead()
	{
		++m_nOtherPaths;
		return TRUE;
	}
};

class CDownloadTransferHTTP : public CDownloadTransfer
{
public:
	int m_nState = dtsRequesting;
	BOOL m_bMetaFetch = TRUE, m_bTigerFetch = FALSE, m_bKeepAlive = TRUE;
	QWORD m_nOffset = 0, m_nLength = SIZE_UNKNOWN, m_nContentLength = SIZE_UNKNOWN;
	CString m_sAddress;
	TestDownload m_oDownload;
	TestDownload* m_pDownload = &m_oDownload;
	CBuffer m_oInput;

	std::string m_sWire; // bytes the peer has sent and the socket has not yet delivered
	size_t m_nWirePos = 0;
	DWORD m_nMaxInput = 0, m_nMaxHeaderPhaseInput = 0, m_nPeerHttpHeaderBytes = 0;
	unsigned m_nRejects = 0, m_nCompletes = 0, m_nFragments = 0, m_nReadInputs = 0;
	bool m_bValid = true;

	static bool ParseHeaderUnsigned(const std::string& sValue, ULONGLONG& nValue)
	{
		size_t start = 0;
		while (start < sValue.size() && (sValue[start] == ' ' || sValue[start] == '\t'))
			++start;
		const std::wstring w(sValue.begin() + static_cast<std::ptrdiff_t>(start), sValue.end());
		return ParsePeerUnsignedDecimal(w.c_str(), nValue);
	}

	void ChargeHeaderLine(const std::string& sLine)
	{
		if (sLine.empty())
			return;
		const auto colon = sLine.find(':');
		if (colon != std::string::npos && colon > 0)
		{
			std::string value = sLine.substr(colon + 1);
			while (!value.empty() && (value[0] == ' ' || value[0] == '\t'))
				value.erase(value.begin());
			const DWORD nBytes = static_cast<DWORD>(colon + 1 + value.size() + 2u);
			m_nPeerHttpHeaderBytes += nBytes;
		}
		else
		{
			m_nPeerHttpHeaderBytes += static_cast<DWORD>(sLine.size()) + 2u;
		}
	}

	bool PeerHttpHeaderPhaseTooLarge() const
	{
		return PeerHttpHeaderPhaseExceeded(m_nPeerHttpHeaderBytes, GetInputLength());
	}

	BOOL ReadInput();
	BOOL ReceiveMetadataInput();
	BOOL ReadMetadata(bool bDropped = false);

	CBuffer* GetInput() { return &m_oInput; }
	DWORD GetInputLength() const { return m_oInput.m_nLength; }
	DWORD Pending() const { return m_bValid ? static_cast<DWORD>(m_sWire.size() - m_nWirePos) : 0; }
	void Deliver(const std::string& s) { m_sWire += s; }
	void Close(TRISTATE nReason)
	{
		++(nReason == TRI_TRUE ? m_nCompletes : m_nRejects);
		m_bValid = false;
	}

	// CConnection::OnReadBounded: read what is available without growing the
	// input past nMaxLength.
	BOOL OnReadBounded(DWORD nMaxLength)
	{
		if (!m_bValid) return FALSE;
		if (m_oInput.m_nLength >= nMaxLength) return TRUE;
		const size_t n = std::min<size_t>(m_sWire.size() - m_nWirePos, nMaxLength - m_oInput.m_nLength);
		m_oInput.Add(m_sWire.data() + m_nWirePos, n);
		m_nWirePos += n;
		m_nMaxInput = std::max(m_nMaxInput, m_oInput.m_nLength);
		if (m_nState != dtsMetadata)
			m_nMaxHeaderPhaseInput = std::max(m_nMaxHeaderPhaseInput, m_oInput.m_nLength);
		return TRUE;
	}

	// CDownloadTransferHTTP::OnRead: the production drain helper and probe.
	bool Pump()
	{
		return ReadHttpInputUntilBlocked(
		    [this]()
		    {
			    ++m_nReadInputs;
			    return ReadInput() != FALSE;
		    },
		    [this]()
		    { return Pending(); });
	}

	// CConnection::Read(CString&): one LF-terminated line, CR stripped.
	bool ReadLine(std::string& sLine)
	{
		const auto& d = m_oInput.m_oData;
		const auto it = std::find(d.begin(), d.end(), '\n');
		if (it == d.end()) return false;
		sLine.assign(d.begin(), it);
		if (!sLine.empty() && sLine.back() == '\r') sLine.pop_back();
		m_oInput.Remove(static_cast<DWORD>(it - d.begin() + 1));
		return true;
	}

	// Status line and keep-alive selection of ReadResponseLine (200 only).
	BOOL ReadResponseLine()
	{
		std::string sLine;
		if (!ReadLine(sLine) || sLine.empty()) return TRUE;
		ChargeHeaderLine(sLine);
		if (sLine.compare(0, 9, "HTTP/1.1 ") == 0)
			m_bKeepAlive = TRUE;
		else if (sLine.compare(0, 9, "HTTP/1.0 ") == 0)
			m_bKeepAlive = FALSE;
		else
		{
			Close(TRI_FALSE);
			return FALSE;
		}
		if (sLine.compare(9, 3, "200") != 0)
		{
			Close(TRI_FALSE);
			return FALSE;
		}
		m_nState = dtsHeaders;
		return TRUE;
	}

	// CConnection::ReadHeaders: returns TRUE while no complete line is buffered.
	BOOL ReadHeaders()
	{
		static const char szLength[] = "Content-Length:";
		std::string sLine;
		while (ReadLine(sLine))
		{
			if (sLine.empty()) return OnHeadersComplete();
			ChargeHeaderLine(sLine);
			if (sLine.compare(0, sizeof(szLength) - 1, szLength) == 0)
			{
				ULONGLONG nLength = 0;
				if (!ParseHeaderUnsigned(sLine.c_str() + sizeof(szLength) - 1, nLength))
				{
					Close(TRI_FALSE);
					return FALSE;
				}
				m_nContentLength = nLength;
			}
		}
		return TRUE;
	}

	// Metadata branch of CDownloadTransferHTTP::OnHeadersComplete.
	BOOL OnHeadersComplete()
	{
		if ((m_nContentLength != SIZE_UNKNOWN && m_nContentLength > XML_PEER_PARSE_CHARS_MAX) ||
		    (m_nContentLength == SIZE_UNKNOWN && m_bKeepAlive))
		{
			Close(TRI_FALSE);
			return FALSE;
		}
		m_nOffset = 0;
		m_nLength = m_nContentLength;
		m_nState = dtsMetadata;
		return ReadMetadata();
	}

	// Metadata branch of CDownloadTransferHTTP::OnDropped.
	void OnDropped()
	{
		if (!m_bValid) return;
		if (m_nState != dtsMetadata)
		{
			Close(TRI_FALSE);
			return;
		}
		if (m_nContentLength != SIZE_UNKNOWN)
		{
			if (GetInputLength() < m_nContentLength)
			{
				Close(TRI_FALSE);
				return;
			}
			m_nLength = m_nContentLength;
		}
		else
		{
			m_nLength = m_nContentLength = GetInputLength();
			if (m_nLength == 0 || m_nLength > XML_PEER_PARSE_CHARS_MAX)
			{
				Close(TRI_FALSE);
				return;
			}
		}
		if (!ReadMetadata(true)) return;
		Close(TRI_TRUE);
	}

	BOOL StartNextFragment()
	{
		++m_nFragments;
		m_nState = dtsNull;
		return TRUE;
	}

	// Paths outside MetaFetch must never be reached by these fixtures.
	BOOL ReceiveTigerInput() { return OnRead(); }
	BOOL ReadTiger() { return OnRead(); }
	BOOL ReadContent() { return OnRead(); }
	BOOL ReadFlush() { return OnRead(); }
};

#include "metafetch_receive_methods.inc"

namespace
{
int g_nFailures = 0;

#define CHECK(condition)                                                              \
	do                                                                                \
	{                                                                                 \
		if (!(condition))                                                             \
		{                                                                             \
			std::fprintf(stderr, "FAIL %s:%d: %s\n", __func__, __LINE__, #condition); \
			++g_nFailures;                                                            \
			return;                                                                   \
		}                                                                             \
	} while (false)

std::string Body(size_t nBody)
{
	return "<x>" + std::string(nBody - 7, 'a') + "</x>";
}

std::string Head(size_t nBody, bool bLength = true, const char* pszVersion = "HTTP/1.1")
{
	std::string s = std::string(pszVersion) + " 200 OK\r\nContent-Type: text/xml\r\n";
	if (bLength) s += "Content-Length: " + std::to_string(nBody) + "\r\n";
	return s + "\r\n";
}

std::string Response(size_t nBody, bool bLength = true, const char* pszVersion = "HTTP/1.1")
{
	return Head(nBody, bLength, pszVersion) + Body(nBody);
}

void ExpectMerged(const CDownloadTransferHTTP& t, size_t nBody)
{
	CHECK(t.m_nRejects == 0);
	CHECK(t.m_oDownload.m_nMerges == 1 && t.m_oDownload.m_nChars == nBody);
	CHECK(t.m_nMaxHeaderPhaseInput <= XML_PEER_HTTP_HEADER_PHASE_CAP
		           && t.m_nMaxInput <= BODY_CAP + 1u);
	CHECK(t.m_nOtherPaths == 0);
}

void TestSingleRead()
{
	CDownloadTransferHTTP t;
	t.Deliver(Response(1000));
	CHECK(t.Pump());
	CHECK(t.m_nFragments == 1 && t.GetInputLength() == 0);
	ExpectMerged(t, 1000);
}

void TestEveryTwoReadSplit()
{
	const std::string wire = Response(600);
	for (size_t cut = 1; cut < wire.size(); ++cut)
	{
		CDownloadTransferHTTP t;
		t.Deliver(wire.substr(0, cut));
		CHECK(t.Pump() && t.m_oDownload.m_nMerges == 0 && t.m_nRejects == 0);
		t.Deliver(wire.substr(cut));
		CHECK(t.Pump() && t.m_nFragments == 1);
		ExpectMerged(t, 600);
	}
}

void TestByteByByte()
{
	const std::string wire = Response(300);
	CDownloadTransferHTTP t;
	for (char c : wire)
	{
		t.Deliver(std::string(1, c));
		CHECK(t.Pump());
	}
	CHECK(t.m_nFragments == 1);
	ExpectMerged(t, 300);
}

// Short headers followed by a large body in one delivery: the header phase
// reads exactly 16 KiB, which must not be misread as oversized headers.
void TestHeadersWithPrefetchedBody()
{
	for (size_t nBody : { size_t(XML_PEER_HTTP_HEADER_PHASE_CAP), size_t(64u * 1024u),
	                      size_t(BODY_CAP) })
	{
		CDownloadTransferHTTP t;
		t.Deliver(Response(nBody));
		CHECK(t.Pump());
		CHECK(t.m_nMaxHeaderPhaseInput == XML_PEER_HTTP_HEADER_PHASE_CAP);
		ExpectMerged(t, nBody);
	}
}

// A header line is buffered whole, so with its CRLF it must fit in 16 KiB.
// The line that fills the cap exactly completes; one byte more fails closed
// without the header phase ever buffering past the cap.
void TestIncompleteHeaderLineBoundary()
{
	const std::string status = "HTTP/1.1 200 OK\r\n";
	const size_t kStatusBytes = status.size();
	const std::string name = "X-Pad: ";
	const std::string contentLengthLine = "Content-Length: 500\r\n";
	const std::string tail = contentLengthLine + "\r\n" + Body(500);
	const size_t kTailHeaderBytes = contentLengthLine.size() + 2u;
	const size_t nMaxPad = XML_PEER_HTTP_HEADER_PHASE_CAP - kStatusBytes - name.size() - 2u -
	                       kTailHeaderBytes - 1u;
	{
		CDownloadTransferHTTP t;
		t.Deliver(status + name + std::string(nMaxPad, 'p'));
		CHECK(t.Pump() && t.m_nRejects == 0 && t.GetInputLength() == name.size() + nMaxPad);
		t.Deliver("\r\n" + tail);
		CHECK(t.Pump());
		ExpectMerged(t, 500);
	}
	{
		CDownloadTransferHTTP t;
		const size_t nOverPad = XML_PEER_HTTP_HEADER_PHASE_CAP - kStatusBytes - name.size();
		t.Deliver(status + name + std::string(nOverPad, 'p') + "\r\n");
		CHECK(!t.Pump());
		CHECK(t.m_nRejects == 1 && t.m_oDownload.m_nMerges == 0);
		CHECK(t.m_nMaxInput <= XML_PEER_HTTP_HEADER_PHASE_CAP);
	}
	{
		CDownloadTransferHTTP t;
		t.Deliver(status + name + std::string(256u * 1024u, 'p'));
		CHECK(!t.Pump());
		CHECK(t.m_nRejects == 1 && t.m_nMaxInput <= XML_PEER_HTTP_HEADER_PHASE_CAP);
	}
}

void TestIncompleteResponseLine()
{
	CDownloadTransferHTTP t;
	t.Deliver(std::string(64u * 1024u, 'H'));
	CHECK(!t.Pump());
	CHECK(t.m_nRejects == 1 && t.m_nMaxInput <= XML_PEER_HTTP_HEADER_PHASE_CAP);
}

// The XML body limit is independent from the header cap and inclusive.
void TestBodyCap()
{
	{
		CDownloadTransferHTTP t;
		t.Deliver(Response(BODY_CAP));
		CHECK(t.Pump());
		ExpectMerged(t, BODY_CAP);
	}
	{
		CDownloadTransferHTTP t;
		t.Deliver(Response(BODY_CAP, false, "HTTP/1.0"));
		CHECK(t.Pump() && t.m_nRejects == 0 && t.GetInputLength() == BODY_CAP);
		t.OnDropped();
		CHECK(t.m_nCompletes == 1);
		ExpectMerged(t, BODY_CAP);
	}
	{
		CDownloadTransferHTTP t;
		t.Deliver(Response(BODY_CAP + 1u, false, "HTTP/1.0") + std::string(4096, 'a'));
		CHECK(!t.Pump());
		CHECK(t.m_nRejects == 1 && t.m_oDownload.m_nMerges == 0);
		CHECK(t.m_nMaxInput == BODY_CAP + 1u);
	}
}

// A stalled body neither spins nor completes; a drop then fails it closed.
// Many short complete header lines must not evade the aggregate header cap.
void TestManySmallHeaderLinesExceedCap()
{
	const std::string status = "HTTP/1.1 200 OK";
	const std::string line = "X-H: 0";
	size_t nLines = 0;
	for (;;)
	{
		CDownloadTransferHTTP acc;
		acc.ChargeHeaderLine(status);
		for (size_t i = 0; i < nLines; ++i)
			acc.ChargeHeaderLine(line);
		if (acc.m_nPeerHttpHeaderBytes >= XML_PEER_HTTP_HEADER_PHASE_CAP)
			break;
		++nLines;
	}
	std::string wire = status + "\r\n";
	for (size_t i = 0; i <= nLines; ++i)
		wire += line + "\r\n";
	CDownloadTransferHTTP t;
	t.Deliver(wire);
	CHECK(!t.Pump());
	CHECK(t.m_nRejects == 1 && t.m_oDownload.m_nMerges == 0);
}

void TestStalledBodyAndDrop()
{
	const std::string wire = Response(1000);
	CDownloadTransferHTTP t;
	t.Deliver(wire.substr(0, wire.size() - 500));
	CHECK(t.Pump());
	CHECK(t.m_nReadInputs == 1 && t.m_nState == dtsMetadata && t.m_oDownload.m_nMerges == 0);
	CHECK(t.Pump() && t.m_nReadInputs == 2);
	t.OnDropped();
	CHECK(t.m_nRejects == 1 && t.m_oDownload.m_nMerges == 0);
}
}

int main()
{
	TestSingleRead();
	TestEveryTwoReadSplit();
	TestByteByByte();
	TestHeadersWithPrefetchedBody();
	TestIncompleteHeaderLineBoundary();
	TestIncompleteResponseLine();
	TestManySmallHeaderLinesExceedCap();
	TestBodyCap();
	TestStalledBodyAndDrop();
	if (g_nFailures)
	{
		std::fprintf(stderr, "%d MetaFetch receive check(s) failed\n", g_nFailures);
		return 1;
	}
	std::puts("PASS: MetaFetch splits, header cap boundary, prefetched body, body cap, stall/drop");
	return 0;
}
