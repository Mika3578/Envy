#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Exercise production Load/RemoveNodesDatContacts with isolated archive services.

Run with: python3 tests/test_hostcache_load.py
The archive adapter supplies mixed legacy contacts; the import adapter uses the
production nodes.dat parser. No MFC, disk cache, or network service is needed.
"""

import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest

from extract_thex_test_methods import extract


HARNESS = r'''
#undef NDEBUG  // the checks below call the code under test
#include "KadNodesDat.h"
#include <algorithm>
#include <array>
#include <cassert>
#include <iostream>
#include <map>
#include <string>

using BOOL = int;
using LPCTSTR = const wchar_t*;
struct CString : std::wstring {
    using std::wstring::wstring;
    CString(const std::wstring& s) : std::wstring(s) {}
    operator LPCTSTR() const { return c_str(); }
};
constexpr BOOL TRUE = 1, FALSE = 0;
enum { PROTOCOL_G2, PROTOCOL_G1, PROTOCOL_ED2K, PROTOCOL_BT, PROTOCOL_KAD, PROTOCOL_DC };
enum { MSG_ERROR };
struct { struct { CString DataPath = L"fixture/"; } General; } Settings;
struct {
    template<class... T> void Message(T...) {}
    CString GetProgramFilesFolder() { return L"programs"; }
    CString GetProgramFilesFolder64() { return L"programs64"; }
    CString GetLocalAppDataFolder() { return L"local"; }
    CString GetAppDataFolder() { return L"roaming"; }
} theApp;
template<class T, size_t N> constexpr int _countof(const T (&)[N]) { return N; }
struct CException { void Delete() {} };
int archiveVersion = 2;
bool lanMode = false, archiveAvailable = true, archiveOpen = false, fileOpen = false, closeFails = false;
int lockDepth = 0;
struct CQuickLock {
    explicit CQuickLock(int&) { ++lockDepth; }
    ~CQuickLock() { --lockDepth; }
};
struct CFile {
    enum { modeRead = 1, shareDenyWrite = 2, osSequentialScan = 4 };
    bool Open(const CString&, int) { return fileOpen = archiveAvailable; }
    void Close() { fileOpen = false; }
    void Abort() { Close(); }
};
struct CArchive {
    enum { load };
    CArchive(CFile*, int, int) { archiveOpen = true; }
    void Close() {
        archiveOpen = false;
        if (closeFails)
            throw new CException;
    }
    void Abort() { archiveOpen = false; }
};
struct Host {
    std::array<uint8_t, 16> m_oGUID{};
    std::array<uint8_t, 4> ip{};
};
using CHostCacheHostPtr = Host*;
using CHostCacheMapItr = std::map<unsigned, Host*>::iterator;
struct CHostCacheList {
    int m_pSection = 0;
    std::map<unsigned, Host*> m_Hosts;
    ~CHostCacheList() { Clear(); }
    void Clear() { for (auto& h : m_Hosts) delete h.second; m_Hosts.clear(); }
    bool IsEmpty() const { return m_Hosts.empty(); }
    void Add(std::array<uint8_t, 4> ip, uint8_t id) {
        auto* h = new Host;
        h->ip = ip;
        h->m_oGUID[0] = id;
        m_Hosts.emplace(m_Hosts.empty() ? 0 : m_Hosts.rbegin()->first + 1, h);
    }
    CHostCacheMapItr Remove(Host* h) {
        auto it = std::find_if(m_Hosts.begin(), m_Hosts.end(),
                               [h](const auto& entry) { return entry.second == h; });
        delete h;
        return m_Hosts.erase(it);
    }
    int RemoveNodesDatContacts();
};
struct CHostCache {
    CHostCacheList Gnutella2, Gnutella1, eDonkey, BitTorrent, Kademlia, DC;
    int m_pSection = 0, m_nKadDropped = 0, imports = 0, fallbacks = 0, minimumChecks = 0;
    BOOL Load();
    void ImportKadNodes();
    void Clear() { Kademlia.Clear(); }
    void Serialize(CArchive&) {
        // Archive boundary: two old imports and a manually added ID-less host.
        Kademlia.Add({77, 2, 0, 192}, 1);
        Kademlia.Add({245, 113, 0, 203}, 2);
        Kademlia.Add({192, 0, 2, 99}, 0);
        m_nKadDropped = KadNodesDatHostCacheNeedsReimport(archiveVersion)
                            ? Kademlia.RemoveNodesDatContacts() : 0;
    }
    int Import(const CString& path, BOOL freshOnly = FALSE) {
        assert(!archiveOpen && !fileOpen && lockDepth == 0);
        if (path != Settings.General.DataPath + L"nodes.dat") {
            assert(freshOnly);
            ++fallbacks;
            return 0;
        }
        assert(!freshOnly);
        ++imports;
        const uint8_t nodes[] = {
            0,0,0,0, 1,0,0,0, 2,0,0,0,
            1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
            77,2,0,192, 0x40,0x12, 0x36,0x12, 8,
            2,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
            245,113,0,203, 0x41,0x12, 0x36,0x12, 8
        };
        KadNodesDatContact parsed[2]{};
        const auto result = KadNodesDatParse(nodes, sizeof(nodes), parsed, 2, nullptr);
        assert(result.status == KadNodesDatStatus::Ok && result.acceptedCount == 2);
        for (const auto& c : parsed)
            Kademlia.Add({c.ip[0], c.ip[1], c.ip[2], c.ip[3]}, c.id[0]);
        return 2;
    }
    bool CheckMinimumServers(int protocol, bool force = false) {
        if (protocol == PROTOCOL_KAD) {
            ++minimumChecks;
            if (!lanMode && (force || Kademlia.IsEmpty()))
                Import(Settings.General.DataPath + L"nodes.dat", FALSE);
        }
        return true;
    }
};
'''

MAIN = r'''
int main(int argc, char** argv) {
    assert(argc == 3);
    archiveVersion = std::stoi(argv[1]);
    lanMode = std::stoi(argv[2]) != 0;
    CHostCache cache;
    assert(cache.Load());
    assert(cache.Kademlia.m_Hosts.size() == 3);
    if (KadNodesDatHostCacheNeedsReimport(archiveVersion)) {
        assert(cache.imports == 1 && cache.fallbacks == 16 && cache.minimumChecks == 0);
        bool first = false, second = false, idless = false;
        for (const auto& entry : cache.Kademlia.m_Hosts) {
            const auto& h = *entry.second;
            first |= h.m_oGUID[0] == 1 && h.ip == (std::array<uint8_t, 4>{192,0,2,77});
            second |= h.m_oGUID[0] == 2 && h.ip == (std::array<uint8_t, 4>{203,0,113,245});
            idless |= KadNodesDatIdIsZero(h.m_oGUID.data()) &&
                      h.ip == (std::array<uint8_t, 4>{192,0,2,99});
        }
        assert(first && second && idless);
    } else {
        assert(cache.imports == 0 && cache.minimumChecks == 0);
    }
    const int imported = cache.imports;
    archiveAvailable = false;
    assert(!cache.Load());
    assert(cache.imports == imported); // A failed reload must not reuse the drop count.

    // Serialize succeeds but closing the archive throws: Load fails and must not
    // import or persist anything, even though contacts were dropped in memory.
    archiveAvailable = true;
    closeFails = true;
    CHostCache failing;
    assert(!failing.Load());
    assert(failing.imports == 0 && failing.minimumChecks == 0);
    closeFails = false;
    std::cout << "PASS archive=" << archiveVersion << " LAN=" << lanMode << '\n';
}
'''


class HostCacheLoadTests(unittest.TestCase):
    def test_reimport_with_idless_host(self):
        root = Path(__file__).resolve().parent.parent
        source = (root / "Envy/HostCache.cpp").read_bytes().decode("latin1").replace("\r\n", "\n")
        methods = [extract(source, signature)[0] for signature in (
            "BOOL CHostCache::Load()",
            "int CHostCacheList::RemoveNodesDatContacts()",
            "void CHostCache::ImportKadNodes()",
        )]
        with tempfile.TemporaryDirectory(prefix="envy-hostcache-") as tmp:
            cpp = Path(tmp) / "hostcache_load.cpp"
            executable = Path(tmp) / "hostcache_load"
            cpp.write_text(HARNESS + "\n".join(methods) + MAIN, encoding="utf-8")
            compiler = shlex.split(os.environ.get("CXX", "g++"))
            subprocess.run(compiler + ["-std=c++17", "-Wall", "-Wextra", "-Werror",
                                      "-pedantic", "-I", str(root / "Envy"),
                                      str(cpp), "-o", str(executable)], check=True)
            for version in (1, 2, 1000, 3):
                for lan in (0, 1):
                    with self.subTest(archive_version=version, lan_mode=lan):
                        subprocess.run([str(executable), str(version), str(lan)],
                                       check=True, cwd=tmp)


if __name__ == "__main__":
    unittest.main()
