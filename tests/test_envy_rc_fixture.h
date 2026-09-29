//
// test_envy_rc_fixture.h
//
// Shared helpers for offline Envy.rc STRINGTABLE checks in EnvyTests.
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//

#pragma once

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

inline bool TestReadTextFile(const char* path, std::string& out)
{
	FILE* fp = nullptr;
#if defined(_MSC_VER)
	if (fopen_s(&fp, path, "rb") != 0 || !fp)
		return false;
#else
	fp = fopen(path, "rb");
	if (!fp)
		return false;
#endif
	if (fseek(fp, 0, SEEK_END) != 0)
	{
		fclose(fp);
		return false;
	}
	const long nSize = ftell(fp);
	if (nSize < 0 || nSize > 1024 * 1024)
	{
		fclose(fp);
		return false;
	}
	if (fseek(fp, 0, SEEK_SET) != 0)
	{
		fclose(fp);
		return false;
	}
	std::vector<char> buf(static_cast<size_t>(nSize) + 1u, '\0');
	const size_t nRead = fread(buf.data(), 1, static_cast<size_t>(nSize), fp);
	fclose(fp);
	if (nRead != static_cast<size_t>(nSize))
		return false;
	out.assign(buf.data(), nRead);
	return true;
}

inline bool TestReadEnvyRc(std::string& out, const char* pszMissingLog)
{
	const char* paths[] = {
		"Envy/Envy.rc",
		"../Envy/Envy.rc",
		"../../Envy/Envy.rc",
		"../../../Envy/Envy.rc",
		"../../../../Envy/Envy.rc"
	};
	for (const char* path : paths)
	{
		if (TestReadTextFile(path, out))
			return true;
	}
	if (pszMissingLog != nullptr)
		std::fputs(pszMissingLog, stderr);
	return false;
}

// Extract an RC STRINGTABLE value; treats doubled quotes ("") as a literal quote.
inline bool TestExtractRcQuotedString(const std::string& text, const char* id, std::string& value)
{
	const std::string key = std::string(id);
	size_t pos = 0;
	while ((pos = text.find(key, pos)) != std::string::npos)
	{
		if (pos > 0)
		{
			const char prev = text[pos - 1];
			if ((prev >= 'A' && prev <= 'Z') || (prev >= 'a' && prev <= 'z') ||
			    (prev >= '0' && prev <= '9') || prev == '_')
			{
				pos += key.size();
				continue;
			}
		}
		size_t i = pos + key.size();
		while (i < text.size() && (text[i] == ' ' || text[i] == '\t'))
			++i;
		if (i >= text.size() || text[i] != '"')
		{
			pos += key.size();
			continue;
		}
		++i;
		std::string out;
		while (i < text.size())
		{
			const char c = text[i++];
			if (c == '"')
			{
				if (i < text.size() && text[i] == '"')
				{
					out.push_back('"');
					++i;
					continue;
				}
				value.swap(out);
				return true;
			}
			if (c == '\\' && i < text.size())
			{
				const char esc = text[i++];
				if (esc == 'n')
					out.push_back('\n');
				else if (esc == 't')
					out.push_back('\t');
				else if (esc == 'r')
					out.push_back('\r');
				else
					out.push_back(esc);
				continue;
			}
			out.push_back(c);
		}
		return false;
	}
	return false;
}
