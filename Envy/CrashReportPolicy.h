//
// CrashReportPolicy.h
//
// Pure crash-report naming, metadata, privacy, and retention helpers (#90).
// Shared by CrashReporter.cpp and EnvyTests. No MFC. Crash-path callers must
// use the bounded wchar buffers; these helpers do not allocate.
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//

#pragma once

#include <windows.h>
#include <cwchar>

// Local minidumps live under %LOCALAPPDATA%\Envy\CrashReports\.
constexpr wchar_t CRASH_REPORTS_APP_DIR[] = L"Envy";
constexpr wchar_t CRASH_REPORTS_SUBDIR[] = L"CrashReports";

constexpr size_t CRASH_REPORT_NAME_MAX = 160u;
constexpr size_t CRASH_REPORT_FIELD_MAX = 256u;
constexpr size_t CRASH_REPORT_METADATA_MAX = 8192u;
constexpr size_t CRASH_REPORT_KEEP_COUNT = 8u;
constexpr unsigned long long CRASH_REPORT_KEEP_BYTES = 50ull * 1024ull * 1024ull;
constexpr size_t CRASH_REPORT_GITHUB_URL_MAX = 1024u;
constexpr size_t CRASH_REPORT_SUFFIX_ATTEMPTS = 16u;

constexpr wchar_t CRASH_REPORT_GITHUB_NEW_ISSUE[] =
    L"https://github.com/Mika3578/Envy/issues/new";

struct CrashReportMetadata
{
	wchar_t version[64];
	wchar_t revision[32];
	wchar_t buildType[16];
	wchar_t arch[8];
	wchar_t windowsVersion[32];
	wchar_t exceptionCode[20];
	wchar_t exceptionAddress[24];
	wchar_t exceptionModule[64];
	wchar_t crashUtc[32];
	wchar_t dumpFile[CRASH_REPORT_NAME_MAX + 1];
	wchar_t symbolsNote[96];
};

struct CrashReportRetentionItem
{
	wchar_t baseName[CRASH_REPORT_NAME_MAX + 1];
	unsigned long long sizeBytes;
	unsigned long long mtimeUtc;
};

inline void CrashReportZero(wchar_t* dest, size_t cch)
{
	if (dest == nullptr || cch == 0)
		return;
	dest[0] = 0;
}

inline BOOL CrashReportCopyTrunc(wchar_t* dest, size_t cch, const wchar_t* src)
{
	if (dest == nullptr || cch == 0)
		return FALSE;
	dest[0] = 0;
	if (src == nullptr)
		return TRUE;
	size_t n = 0;
	while (src[n] != 0 && n + 1 < cch)
	{
		dest[n] = src[n];
		++n;
	}
	dest[n] = 0;
	return TRUE;
}

inline BOOL CrashReportEquals(const wchar_t* a, const wchar_t* b)
{
	if (a == nullptr || b == nullptr)
		return FALSE;
	return wcscmp(a, b) == 0;
}

inline BOOL CrashReportStartsWith(const wchar_t* text, const wchar_t* prefix)
{
	if (text == nullptr || prefix == nullptr)
		return FALSE;
	while (*prefix != 0)
	{
		if (*text != *prefix)
			return FALSE;
		++text;
		++prefix;
	}
	return TRUE;
}

inline BOOL CrashReportIsNameChar(wchar_t ch)
{
	return (ch >= L'A' && ch <= L'Z') ||
	       (ch >= L'a' && ch <= L'z') ||
	       (ch >= L'0' && ch <= L'9') ||
	       ch == L'.' || ch == L'_' || ch == L'-';
}

// Filename token: letters, digits, dot, underscore, hyphen. Others become '-'.
inline BOOL CrashReportSanitizeToken(const wchar_t* src, wchar_t* dest, size_t cch)
{
	if (dest == nullptr || cch < 2)
		return FALSE;
	dest[0] = 0;
	if (src == nullptr || src[0] == 0)
		return CrashReportCopyTrunc(dest, cch, L"unknown");

	size_t o = 0;
	BOOL lastDash = FALSE;
	for (size_t i = 0; src[i] != 0 && o + 1 < cch; ++i)
	{
		wchar_t ch = src[i];
		if (CrashReportIsNameChar(ch))
		{
			if (ch == L'-' || ch == L'.' || ch == L'_')
			{
				if (o == 0 || lastDash)
					continue;
				lastDash = TRUE;
			}
			else
			{
				lastDash = FALSE;
			}
			dest[o++] = ch;
		}
		else
		{
			if (o == 0 || lastDash)
				continue;
			dest[o++] = L'-';
			lastDash = TRUE;
		}
	}
	while (o > 0 && (dest[o - 1] == L'-' || dest[o - 1] == L'.' || dest[o - 1] == L'_'))
		--o;
	dest[o] = 0;
	if (o == 0)
		return CrashReportCopyTrunc(dest, cch, L"unknown");
	return TRUE;
}

inline BOOL CrashReportIsSafeFileName(const wchar_t* name)
{
	if (name == nullptr || name[0] == 0)
		return FALSE;
	if (name[0] == L'.')
		return FALSE;
	const size_t nLen = wcslen(name);
	if (name[nLen - 1] == L'.')
		return FALSE;
	size_t n = 0;
	for (; name[n] != 0; ++n)
	{
		if (n >= CRASH_REPORT_NAME_MAX)
			return FALSE;
		if (!CrashReportIsNameChar(name[n]))
			return FALSE;
		if (name[n] == L'.' && name[n + 1] == L'.')
			return FALSE;
	}
	return n > 0;
}

inline BOOL CrashReportHasPathSeparator(const wchar_t* text)
{
	if (text == nullptr)
		return FALSE;
	for (size_t i = 0; text[i] != 0; ++i)
	{
		if (text[i] == L'\\' || text[i] == L'/')
			return TRUE;
	}
	return FALSE;
}

inline BOOL CrashReportJoinPath(const wchar_t* dir, const wchar_t* name, wchar_t* dest, size_t cch)
{
	if (dest == nullptr || cch == 0)
		return FALSE;
	dest[0] = 0;
	if (dir == nullptr || dir[0] == 0)
		return FALSE;
	if (!CrashReportIsSafeFileName(name))
		return FALSE;
	if (CrashReportHasPathSeparator(name))
		return FALSE;

	const size_t nd = wcslen(dir);
	const size_t nn = wcslen(name);
	if (nd == 0 || nd + 1 + nn + 1 > cch)
		return FALSE;

	CrashReportCopyTrunc(dest, cch, dir);
	if (dest[nd - 1] != L'\\' && dest[nd - 1] != L'/')
	{
		if (nd + 2 + nn > cch)
			return FALSE;
		dest[nd] = L'\\';
		dest[nd + 1] = 0;
		CrashReportCopyTrunc(dest + nd + 1, cch - nd - 1, name);
	}
	else
	{
		CrashReportCopyTrunc(dest + nd, cch - nd, name);
	}
	return TRUE;
}

// UTC timestamp used in filenames: YYYYMMDDTHHMMSSZ
inline BOOL CrashReportFormatUtcFileStamp(
    int year, int month, int day, int hour, int minute, int second,
    wchar_t* dest, size_t cch)
{
	if (dest == nullptr || cch < 17)
		return FALSE;
	if (year < 1970 || year > 9999 ||
	    month < 1 || month > 12 ||
	    day < 1 || day > 31 ||
	    hour < 0 || hour > 23 ||
	    minute < 0 || minute > 59 ||
	    second < 0 || second > 59)
	{
		dest[0] = 0;
		return FALSE;
	}
	swprintf_s(dest, cch, L"%04d%02d%02dT%02d%02d%02dZ",
	           year, month, day, hour, minute, second);
	return TRUE;
}

inline BOOL CrashReportFormatUtcIso(
    int year, int month, int day, int hour, int minute, int second,
    wchar_t* dest, size_t cch)
{
	if (dest == nullptr || cch < 21)
		return FALSE;
	if (year < 1970 || year > 9999 ||
	    month < 1 || month > 12 ||
	    day < 1 || day > 31 ||
	    hour < 0 || hour > 23 ||
	    minute < 0 || minute > 59 ||
	    second < 0 || second > 59)
	{
		dest[0] = 0;
		return FALSE;
	}
	swprintf_s(dest, cch, L"%04d-%02d-%02dT%02d:%02d:%02dZ",
	           year, month, day, hour, minute, second);
	return TRUE;
}

inline BOOL CrashReportFormatExceptionCode(DWORD code, wchar_t* dest, size_t cch)
{
	if (dest == nullptr || cch < 11)
		return FALSE;
	swprintf_s(dest, cch, L"0x%08X", code);
	return TRUE;
}

inline BOOL CrashReportFormatAddress(DWORD64 address, wchar_t* dest, size_t cch)
{
	if (dest == nullptr || cch < 19)
		return FALSE;
	swprintf_s(dest, cch, L"0x%llX", static_cast<unsigned long long>(address));
	return TRUE;
}

inline const wchar_t* CrashReportArchitectureToken()
{
#ifdef _WIN64
	return L"x64";
#else
	return L"Win32";
#endif
}

// Envy-<version>-<arch>-<utc>-p<pid>-<suffix>
inline BOOL CrashReportBuildBaseName(
    const wchar_t* version,
    const wchar_t* arch,
    const wchar_t* utcStamp,
    DWORD processId,
    unsigned suffix,
    wchar_t* dest,
    size_t cch)
{
	if (dest == nullptr || cch < 24)
		return FALSE;
	dest[0] = 0;

	wchar_t verTok[48];
	wchar_t archTok[12];
	wchar_t stampTok[20];
	if (!CrashReportSanitizeToken(version, verTok, _countof(verTok)))
		return FALSE;
	if (!CrashReportSanitizeToken(arch && arch[0] ? arch : CrashReportArchitectureToken(),
	                              archTok, _countof(archTok)))
		return FALSE;
	if (utcStamp == nullptr || utcStamp[0] == 0)
		return FALSE;
	if (!CrashReportSanitizeToken(utcStamp, stampTok, _countof(stampTok)))
		return FALSE;
	if (wcslen(stampTok) != 16) // YYYYMMDDTHHMMSSZ with Z kept as letter
		return FALSE;

	const int n = swprintf_s(dest, cch, L"Envy-%s-%s-%s-p%lu-%04x",
	                         verTok, archTok, stampTok, processId, suffix & 0xFFFFu);
	if (n <= 0)
		return FALSE;
	return CrashReportIsSafeFileName(dest);
}

inline void CrashReportMetadataClear(CrashReportMetadata* meta)
{
	if (meta == nullptr)
		return;
	ZeroMemory(meta, sizeof(*meta));
}

// Metadata fields: strip controls, reject path-like values for dump names.
inline BOOL CrashReportSanitizeField(const wchar_t* src, wchar_t* dest, size_t cch)
{
	if (dest == nullptr || cch == 0)
		return FALSE;
	dest[0] = 0;
	if (src == nullptr)
		return TRUE;

	size_t o = 0;
	for (size_t i = 0; src[i] != 0 && o + 1 < cch && o + 1 < CRASH_REPORT_FIELD_MAX; ++i)
	{
		const wchar_t ch = src[i];
		if (ch < 32 || ch == 127 || ch == L'%')
			continue;
		dest[o++] = ch;
	}
	dest[o] = 0;
	return TRUE;
}

inline BOOL CrashReportLooksLikeWindowsPath(const wchar_t* text)
{
	if (text == nullptr)
		return FALSE;
	for (size_t i = 0; text[i] != 0; ++i)
	{
		if (((text[i] >= L'A' && text[i] <= L'Z') ||
		     (text[i] >= L'a' && text[i] <= L'z')) &&
		    text[i + 1] == L':' &&
		    (text[i + 2] == L'\\' || text[i + 2] == L'/'))
		{
			return TRUE;
		}
		if (text[i] == L'\\' && text[i + 1] == L'\\')
			return TRUE;
	}
	return FALSE;
}

inline BOOL CrashReportLooksLikeCredentialUrl(const wchar_t* text)
{
	if (text == nullptr)
		return FALSE;
	const wchar_t* scheme = wcsstr(text, L"://");
	if (scheme == nullptr)
		return FALSE;
	const wchar_t* at = wcschr(scheme + 3, L'@');
	if (at == nullptr)
		return FALSE;
	const wchar_t* slash = wcschr(scheme + 3, L'/');
	if (slash != nullptr && slash < at)
		return FALSE;
	return TRUE;
}

inline BOOL CrashReportContainsInsensitive(const wchar_t* text, const wchar_t* token)
{
	if (text == nullptr || token == nullptr || token[0] == 0)
		return FALSE;
	const size_t nTok = wcslen(token);
	for (size_t i = 0; text[i] != 0; ++i)
	{
		size_t j = 0;
		while (j < nTok)
		{
			const wchar_t a0 = text[i + j];
			if (a0 == 0)
				return FALSE;
			wchar_t a = a0;
			wchar_t b = token[j];
			if (a >= L'A' && a <= L'Z')
				a = static_cast<wchar_t>(a - L'A' + L'a');
			if (b >= L'A' && b <= L'Z')
				b = static_cast<wchar_t>(b - L'A' + L'a');
			if (a != b)
				break;
			++j;
		}
		if (j == nTok)
			return TRUE;
	}
	return FALSE;
}

inline BOOL CrashReportLooksLikeIPv4(const wchar_t* text)
{
	if (text == nullptr)
		return FALSE;
	for (size_t i = 0; text[i] != 0; ++i)
	{
		if (text[i] < L'0' || text[i] > L'9')
			continue;
		if (i > 0)
		{
			const wchar_t prev = text[i - 1];
			if ((prev >= L'0' && prev <= L'9') || prev == L'.')
				continue;
		}
		unsigned octet = 0;
		unsigned parts = 0;
		size_t k = i;
		BOOL ok = TRUE;
		while (parts < 4 && ok)
		{
			if (text[k] < L'0' || text[k] > L'9')
			{
				ok = FALSE;
				break;
			}
			unsigned value = 0;
			size_t digits = 0;
			while (text[k] >= L'0' && text[k] <= L'9')
			{
				value = value * 10u + static_cast<unsigned>(text[k] - L'0');
				++k;
				++digits;
				if (digits > 3 || value > 255)
				{
					ok = FALSE;
					break;
				}
			}
			++parts;
			if (parts < 4)
			{
				if (text[k] != L'.')
				{
					ok = FALSE;
					break;
				}
				++k;
			}
			octet = value;
			(void)octet;
		}
		if (ok && parts == 4)
		{
			const wchar_t next = text[k];
			if (next == 0 || next == L' ' || next == L'\t' || next == L':' ||
			    next == L',' || next == L')' || next == L']')
			{
				return TRUE;
			}
		}
	}
	return FALSE;
}

// Used to refuse log-tail inclusion. Log tails are omitted from this PR.
inline BOOL CrashReportLooksPrivate(const wchar_t* text)
{
	if (text == nullptr || text[0] == 0)
		return FALSE;
	if (CrashReportLooksLikeWindowsPath(text))
		return TRUE;
	if (CrashReportLooksLikeCredentialUrl(text))
		return TRUE;
	if (CrashReportLooksLikeIPv4(text))
		return TRUE;
	if (CrashReportContainsInsensitive(text, L"passkey="))
		return TRUE;
	if (CrashReportContainsInsensitive(text, L"password="))
		return TRUE;
	if (CrashReportContainsInsensitive(text, L"cookie="))
		return TRUE;
	if (CrashReportContainsInsensitive(text, L"authorization:"))
		return TRUE;
	if (wcsstr(text, L"/home/") != nullptr || wcsstr(text, L"/Users/") != nullptr)
		return TRUE;
	return FALSE;
}

inline BOOL CrashReportFormatMetadataText(const CrashReportMetadata* meta, wchar_t* dest, size_t cch)
{
	if (dest == nullptr || cch == 0)
		return FALSE;
	dest[0] = 0;
	if (meta == nullptr)
		return FALSE;

	CrashReportMetadata clean;
	CrashReportMetadataClear(&clean);
	CrashReportSanitizeField(meta->version, clean.version, _countof(clean.version));
	CrashReportSanitizeField(meta->revision, clean.revision, _countof(clean.revision));
	CrashReportSanitizeField(meta->buildType, clean.buildType, _countof(clean.buildType));
	CrashReportSanitizeField(meta->arch, clean.arch, _countof(clean.arch));
	CrashReportSanitizeField(meta->windowsVersion, clean.windowsVersion, _countof(clean.windowsVersion));
	CrashReportSanitizeField(meta->exceptionCode, clean.exceptionCode, _countof(clean.exceptionCode));
	CrashReportSanitizeField(meta->exceptionAddress, clean.exceptionAddress, _countof(clean.exceptionAddress));
	CrashReportSanitizeField(meta->exceptionModule, clean.exceptionModule, _countof(clean.exceptionModule));
	CrashReportSanitizeField(meta->crashUtc, clean.crashUtc, _countof(clean.crashUtc));
	CrashReportSanitizeField(meta->dumpFile, clean.dumpFile, _countof(clean.dumpFile));
	CrashReportSanitizeField(meta->symbolsNote, clean.symbolsNote, _countof(clean.symbolsNote));

	if (clean.dumpFile[0] != 0 && !CrashReportIsSafeFileName(clean.dumpFile))
		clean.dumpFile[0] = 0;
	if (CrashReportHasPathSeparator(clean.exceptionModule))
		clean.exceptionModule[0] = 0;
	if (CrashReportLooksLikeWindowsPath(clean.exceptionModule))
		clean.exceptionModule[0] = 0;

	const int n = swprintf_s(dest, cch,
	                         L"envy_crash_report=1\r\n"
	                         L"envy_version=%s\r\n"
	                         L"revision=%s\r\n"
	                         L"build_type=%s\r\n"
	                         L"arch=%s\r\n"
	                         L"windows_version=%s\r\n"
	                         L"exception_code=%s\r\n"
	                         L"exception_address=%s\r\n"
	                         L"exception_module=%s\r\n"
	                         L"crash_utc=%s\r\n"
	                         L"dump_file=%s\r\n"
	                         L"symbols=%s\r\n"
	                         L"privacy=Minidumps can contain fragments of process memory and are not anonymous. "
	                         L"ENVY does not upload dumps. Attach a .dmp only if you choose to.\r\n"
	                         L"log_tail=omitted\r\n",
	                         clean.version,
	                         clean.revision,
	                         clean.buildType,
	                         clean.arch,
	                         clean.windowsVersion,
	                         clean.exceptionCode,
	                         clean.exceptionAddress,
	                         clean.exceptionModule,
	                         clean.crashUtc,
	                         clean.dumpFile,
	                         clean.symbolsNote[0] ? clean.symbolsNote : L"PDB not shipped in the installer");
	return n > 0;
}

inline BOOL CrashReportParseKey(const wchar_t* line, const wchar_t* key, wchar_t* dest, size_t cch)
{
	if (line == nullptr || key == nullptr)
		return FALSE;
	const size_t nKey = wcsnlen(key, CRASH_REPORT_FIELD_MAX);
	if (nKey == 0 || nKey >= CRASH_REPORT_FIELD_MAX)
		return FALSE;
	const size_t nLine = wcsnlen(line, CRASH_REPORT_FIELD_MAX + 64);
	if (nLine <= nKey)
		return FALSE;
	if (wcsncmp(line, key, nKey) != 0)
		return FALSE;
	if (line[nKey] != L'=')
		return FALSE;
	return CrashReportSanitizeField(line + nKey + 1, dest, cch);
}

// Untrusted metadata. Bounds every field; ignores unknown keys and junk.
inline BOOL CrashReportParseMetadataText(const wchar_t* text, size_t chars, CrashReportMetadata* meta)
{
	CrashReportMetadataClear(meta);
	if (text == nullptr || meta == nullptr || chars == 0)
		return FALSE;
	if (chars > CRASH_REPORT_METADATA_MAX)
		chars = CRASH_REPORT_METADATA_MAX;

	BOOL sawHeader = FALSE;
	size_t i = 0;
	while (i < chars && text[i] != 0)
	{
		wchar_t line[CRASH_REPORT_FIELD_MAX + 64];
		size_t o = 0;
		while (i < chars && text[i] != 0 && text[i] != L'\n' && text[i] != L'\r')
		{
			if (o + 1 < _countof(line))
				line[o++] = text[i];
			++i;
		}
		line[o] = 0;
		while (i < chars && (text[i] == L'\n' || text[i] == L'\r'))
			++i;
		if (line[0] == 0)
			continue;
		if (wcsncmp(line, L"envy_crash_report=", 18) == 0)
		{
			sawHeader = TRUE;
			continue;
		}
		CrashReportParseKey(line, L"envy_version", meta->version, _countof(meta->version));
		CrashReportParseKey(line, L"revision", meta->revision, _countof(meta->revision));
		CrashReportParseKey(line, L"build_type", meta->buildType, _countof(meta->buildType));
		CrashReportParseKey(line, L"arch", meta->arch, _countof(meta->arch));
		CrashReportParseKey(line, L"windows_version", meta->windowsVersion, _countof(meta->windowsVersion));
		CrashReportParseKey(line, L"exception_code", meta->exceptionCode, _countof(meta->exceptionCode));
		CrashReportParseKey(line, L"exception_address", meta->exceptionAddress, _countof(meta->exceptionAddress));
		CrashReportParseKey(line, L"exception_module", meta->exceptionModule, _countof(meta->exceptionModule));
		CrashReportParseKey(line, L"crash_utc", meta->crashUtc, _countof(meta->crashUtc));
		CrashReportParseKey(line, L"dump_file", meta->dumpFile, _countof(meta->dumpFile));
		CrashReportParseKey(line, L"symbols", meta->symbolsNote, _countof(meta->symbolsNote));
	}

	if (meta->dumpFile[0] != 0 && !CrashReportIsSafeFileName(meta->dumpFile))
		meta->dumpFile[0] = 0;
	if (CrashReportHasPathSeparator(meta->exceptionModule) ||
	    CrashReportLooksLikeWindowsPath(meta->exceptionModule))
	{
		meta->exceptionModule[0] = 0;
	}
	return sawHeader || meta->dumpFile[0] != 0 || meta->exceptionCode[0] != 0;
}

inline BOOL CrashReportPercentEncodeUtf8(const wchar_t* src, wchar_t* dest, size_t cch)
{
	if (dest == nullptr || cch == 0)
		return FALSE;
	dest[0] = 0;
	if (src == nullptr)
		return TRUE;

	char utf8[512];
	const int nUtf8 = WideCharToMultiByte(CP_UTF8, 0, src, -1, utf8, sizeof(utf8), nullptr, nullptr);
	if (nUtf8 <= 1)
		return FALSE;

	size_t o = 0;
	for (int i = 0; i < nUtf8 - 1; ++i)
	{
		const unsigned char b = static_cast<unsigned char>(utf8[i]);
		const BOOL unreserved =
		    (b >= 'A' && b <= 'Z') ||
		    (b >= 'a' && b <= 'z') ||
		    (b >= '0' && b <= '9') ||
		    b == '-' || b == '_' || b == '.' || b == '~';
		if (unreserved)
		{
			if (o + 1 >= cch)
				return FALSE;
			dest[o++] = static_cast<wchar_t>(b);
		}
		else
		{
			if (o + 3 >= cch)
				return FALSE;
			static const wchar_t hex[] = L"0123456789ABCDEF";
			dest[o++] = L'%';
			dest[o++] = hex[b >> 4];
			dest[o++] = hex[b & 0x0F];
		}
	}
	dest[o] = 0;
	return TRUE;
}

// Title only. Never put dump bytes or log bodies in a URL.
inline BOOL CrashReportBuildGitHubIssueUrl(
    const wchar_t* version,
    const wchar_t* arch,
    const wchar_t* exceptionCode,
    wchar_t* dest,
    size_t cch)
{
	if (dest == nullptr || cch < 48)
		return FALSE;
	dest[0] = 0;

	wchar_t verTok[48];
	wchar_t archTok[12];
	wchar_t codeTok[20];
	CrashReportSanitizeToken(version, verTok, _countof(verTok));
	CrashReportSanitizeToken(arch, archTok, _countof(archTok));
	CrashReportSanitizeField(exceptionCode, codeTok, _countof(codeTok));
	if (codeTok[0] == 0)
		CrashReportCopyTrunc(codeTok, _countof(codeTok), L"unknown");

	wchar_t title[128];
	swprintf_s(title, _countof(title), L"crash: Envy %s %s %s", verTok, archTok, codeTok);

	wchar_t encoded[384];
	if (!CrashReportPercentEncodeUtf8(title, encoded, _countof(encoded)))
		return FALSE;

	const int n = swprintf_s(dest, cch, L"%s?title=%s",
	                         CRASH_REPORT_GITHUB_NEW_ISSUE, encoded);
	if (n <= 0)
		return FALSE;
	return CrashReportStartsWith(dest, CRASH_REPORT_GITHUB_NEW_ISSUE);
}

inline BOOL CrashReportIsTrustedGitHubNewIssueUrl(const wchar_t* url)
{
	if (url == nullptr)
		return FALSE;
	if (!CrashReportStartsWith(url, CRASH_REPORT_GITHUB_NEW_ISSUE))
		return FALSE;
	const size_t n = wcslen(url);
	if (n >= CRASH_REPORT_GITHUB_URL_MAX)
		return FALSE;
	for (size_t i = 0; i < n; ++i)
	{
		const wchar_t ch = url[i];
		if (ch < 32 || ch == 127 || ch == L'\'' || ch == L'\"' || ch == L'\\')
			return FALSE;
	}
	return TRUE;
}

// Newest-first items[0]. Never marks the newest for prune. Prefer count then size.
inline size_t CrashReportSelectPrune(
    const CrashReportRetentionItem* items,
    size_t count,
    BOOL* prune,
    size_t keepCount,
    unsigned long long keepBytes)
{
	if (prune == nullptr)
		return 0;
	for (size_t i = 0; i < count; ++i)
		prune[i] = FALSE;
	if (items == nullptr || count == 0)
		return 0;

	size_t marked = 0;
	unsigned long long used = 0;
	size_t kept = 0;
	for (size_t i = 0; i < count; ++i)
	{
		const BOOL overCount = kept >= keepCount;
		const BOOL overSize = (used + items[i].sizeBytes) > keepBytes && kept > 0;
		if (i == 0)
		{
			used += items[i].sizeBytes;
			++kept;
			continue;
		}
		if (overCount || overSize)
		{
			prune[i] = TRUE;
			++marked;
		}
		else
		{
			used += items[i].sizeBytes;
			++kept;
		}
	}
	return marked;
}

inline BOOL CrashReportBaseNameFromDumpFile(const wchar_t* dumpFile, wchar_t* dest, size_t cch)
{
	if (dest == nullptr || cch == 0)
		return FALSE;
	dest[0] = 0;
	if (!CrashReportIsSafeFileName(dumpFile))
		return FALSE;
	const size_t n = wcslen(dumpFile);
	if (n < 5)
		return FALSE;
	if (dumpFile[n - 4] != L'.')
		return FALSE;
	if (dumpFile[n - 3] != L'd' && dumpFile[n - 3] != L'D')
		return FALSE;
	if (dumpFile[n - 2] != L'm' && dumpFile[n - 2] != L'M')
		return FALSE;
	if (dumpFile[n - 1] != L'p' && dumpFile[n - 1] != L'P')
		return FALSE;
	if (n - 4 + 1 > cch)
		return FALSE;
	for (size_t i = 0; i < n - 4; ++i)
		dest[i] = dumpFile[i];
	dest[n - 4] = 0;
	return CrashReportIsSafeFileName(dest);
}
