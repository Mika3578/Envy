// SPDX-License-Identifier: AGPL-3.0-or-later
// Execute extracted production methods with deterministic allocation failures.

#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <new>
#include <cstddef>

using DWORD = std::uint32_t;
using WORD = std::uint16_t;
using BYTE = unsigned char;
using LPBYTE = BYTE*;
using BOOL = int;
constexpr BOOL TRUE = 1, FALSE = 0;
constexpr DWORD MAXDWORD = UINT32_MAX;
#undef assert
#define assert(condition)                                                        \
	do {                                                                         \
		if (!(condition))                                                        \
		{                                                                        \
			std::fprintf(stderr, "FAIL at line %d: %s\n", __LINE__, #condition); \
			std::abort();                                                        \
		}                                                                        \
	} while (false)
#define ASSERT assert
#define CopyMemory std::memcpy

namespace
{
bool failAllocation = false;
unsigned allocations = 0;
void* watched = nullptr;
unsigned watchedFrees = 0;
struct AllocationTag
{
};
}

// Only production allocations use this overload. Fixtures use ordinary new[].
void* operator new[](std::size_t size, AllocationTag)
#ifndef TEST_THROW_ALLOCATION
    noexcept
#endif
{
	++allocations;
	if (failAllocation)
	{
		failAllocation = false;
#ifdef TEST_THROW_ALLOCATION
		throw std::bad_alloc();
#else
		return nullptr;
#endif
	}
	return std::malloc(size);
}

void* operator new[](std::size_t size)
{
	if (void* p = std::malloc(size)) return p;
	throw std::bad_alloc();
}

void operator delete[](void* p) noexcept
{
	if (p && p == watched) ++watchedFrees;
	std::free(p);
}

void operator delete[](void* p, std::size_t) noexcept { operator delete[](p); }
void operator delete[](void* p, AllocationTag) noexcept { operator delete[](p); }

struct HASHDB_INDEX
{
	DWORD nIndex, nType, nOffset, nLength;
};
struct CHashDatabase
{
	BOOL m_bOpen = TRUE;
	HASHDB_INDEX* m_pIndex = nullptr;
	DWORD m_nIndex = 0, m_nBuffer = 0, m_nOffset = 0;
	HASHDB_INDEX* Lookup(DWORD, DWORD) const;
	HASHDB_INDEX* PrepareToStore(DWORD, DWORD, DWORD);
	~CHashDatabase() { delete[] m_pIndex; }
};

struct IN_ADDR
{
	struct
	{
		DWORD S_addr;
	} S_un;
};
struct CHubHorizonHub
{
	IN_ADDR m_pAddress{};
	WORD m_nPort = 0;
	DWORD m_nReference = 0;
	CHubHorizonHub* m_pNext = nullptr;
};
struct CHubHorizonPool
{
	CHubHorizonHub* m_pFree = nullptr;
	CHubHorizonHub* m_pActive = nullptr;
	DWORD m_nActive = 0, m_nBuffer = 0;
	BOOL CanAdd(IN_ADDR*);
	CHubHorizonHub* Add(IN_ADDR*, WORD);
	void Remove(CHubHorizonHub*);
	CHubHorizonHub* Find(IN_ADDR*);
} HubHorizonPool;
struct CHubHorizonGroup
{
	CHubHorizonHub** m_pList = nullptr;
	DWORD m_nCount = 0, m_nBuffer = 0;
	void Add(IN_ADDR*, WORD);
	void Clear();
	~CHubHorizonGroup()
	{
		Clear();
		delete[] m_pList;
	}
};

namespace Hashes
{
struct Sha1Hash
{
};
}
struct PreviewFile
{
	LPBYTE m_pPreview;
	DWORD m_nPreview;
};
struct Matches
{
	int m_pSection = 0;
	DWORD result = 0;
	DWORD FileToItem(PreviewFile*) { return result; }
};
struct CSingleLock
{
	CSingleLock(int*, BOOL) {}
};
struct CSearchDetailPanel
{
	Matches* m_pMatches;
	PreviewFile* m_pFile;
	BOOL CachePreviewImage(const Hashes::Sha1Hash&, LPBYTE, DWORD);
};
struct CBrowseTreeItem
{
	DWORD* m_pFiles = nullptr;
	DWORD m_nFiles = 0, m_nFileBuffer = 0;
	void AddFileIndex(DWORD);
	~CBrowseTreeItem() { delete[] m_pFiles; }
};

#define new new (AllocationTag{})
#include "buffer_growth_methods.inc"
#undef new

namespace
{
void Watch(void* p)
{
	watched = p;
	watchedFrees = 0;
}

template<class F>
void Fail(F action)
{
	failAllocation = true;
	bool threw = false;
	try
	{
		action();
	}
	catch (const std::bad_alloc&)
	{
		threw = true;
	}
	assert(!failAllocation);
#ifdef TEST_THROW_ALLOCATION
	assert(threw);
#else
	assert(!threw);
#endif
}

void TestHash()
{
	CHashDatabase db;
	db.m_nIndex = db.m_nBuffer = 1;
	db.m_nOffset = 104;
	db.m_pIndex = new HASHDB_INDEX[1]{ { 7, 2, 100, 4 } };
	Watch(db.m_pIndex);
	Fail([&]
	     { assert(db.PrepareToStore(7, 2, 8) == nullptr); });
	assert(db.Lookup(7, 2) == db.m_pIndex);
	assert(db.m_nIndex == 1 && db.m_nBuffer == 1 && db.m_nOffset == 104);
	assert(db.m_pIndex[0].nLength == 4 && watchedFrees == 0);
	assert(db.PrepareToStore(7, 2, 8) == db.m_pIndex + 1);
	assert(watchedFrees == 1 && db.m_nIndex == 2 && db.m_nOffset == 112);
	assert(db.m_pIndex[0].nIndex == 0 && db.Lookup(7, 2)->nLength == 8);
	const unsigned before = allocations;
	assert(db.PrepareToStore(7, 2, 2) == db.m_pIndex);
	assert(db.m_pIndex[1].nIndex == 0 && db.Lookup(7, 2) == db.m_pIndex);
	assert(allocations == before && db.m_nIndex == 2);
}

void TestHub()
{
	CHubHorizonHub hubs[2];
	hubs[0].m_pNext = &hubs[1];
	HubHorizonPool = {};
	HubHorizonPool.m_pFree = hubs;
	HubHorizonPool.m_nBuffer = 2;
	IN_ADDR address{ { 1 } }, second{ { 2 } }, third{ { 3 } };
	{
		CHubHorizonGroup group;
		Fail([&]
		     { group.Add(&address, 10); });
		assert(group.m_pList == nullptr && group.m_nBuffer == 0 && group.m_nCount == 0);
		assert(HubHorizonPool.m_nActive == 0 && hubs[0].m_nReference == 0);
		group.Add(&address, 10);
		assert(group.m_nCount == 1 && hubs[0].m_nReference == 1);
		const unsigned before = allocations;
		group.Add(&address, 11);
		assert(group.m_nCount == 1 && hubs[0].m_nReference == 1 && allocations == before);
		group.m_nBuffer = 1;
		Watch(group.m_pList);
		Fail([&]
		     { group.Add(&second, 20); });
		assert(group.m_pList == watched && watchedFrees == 0 && group.m_nCount == 1);
		assert(group.m_nBuffer == 1 && HubHorizonPool.m_nActive == 1);
		group.Add(&second, 20);
		assert(watchedFrees == 1 && group.m_nCount == 2);
		const unsigned fullAllocations = allocations;
		CHubHorizonGroup other;
		other.Add(&third, 30);
		assert(other.m_nCount == 0 && allocations == fullAllocations);
		Fail([&]
		     { other.Add(&address, 12); });
		assert(other.m_nCount == 0 && hubs[0].m_nReference == 1);
		// Pool exhaustion must not prevent sharing an existing hub.
		other.Add(&address, 12);
		assert(other.m_nCount == 1 && hubs[0].m_nReference == 2);
	}
	assert(HubHorizonPool.m_nActive == 0 && hubs[0].m_nReference == 0);
	HubHorizonPool = {};
}

void TestPreview()
{
	PreviewFile file{ new BYTE[3]{ 1, 2, 3 }, 3 };
	Matches matches;
	CSearchDetailPanel panel{ &matches, &file };
	Watch(file.m_pPreview);
	Fail([&]
	     { assert(!panel.CachePreviewImage({}, file.m_pPreview, 3)); });
	assert(file.m_pPreview == watched && file.m_nPreview == 3 && watchedFrees == 0);
	// Alias the old buffer to verify that copying precedes its deletion.
	assert(panel.CachePreviewImage({}, file.m_pPreview, 3));
	assert(file.m_pPreview[2] == 3 && watchedFrees == 1);
	matches.result = MAXDWORD;
	const unsigned before = allocations;
	assert(!panel.CachePreviewImage({}, file.m_pPreview, 3) && allocations == before);
	delete[] file.m_pPreview;
}

void TestBrowse()
{
	CBrowseTreeItem item;
	item.m_pFiles = new DWORD[1]{ 7 };
	item.m_nFiles = item.m_nFileBuffer = 1;
	Watch(item.m_pFiles);
	Fail([&]
	     { item.AddFileIndex(8); });
	assert(item.m_pFiles == watched && item.m_nFiles == 1 && item.m_nFileBuffer == 1);
	assert(item.m_pFiles[0] == 7 && watchedFrees == 0);
	item.AddFileIndex(8);
	assert(item.m_nFiles == 2 && item.m_pFiles[0] == 7 && item.m_pFiles[1] == 8 && watchedFrees == 1);
	const unsigned before = allocations;
	item.m_nFiles = item.m_nFileBuffer = 0x40000000u;
	item.AddFileIndex(9);
	assert(allocations == before && item.m_nFiles == 0x40000000u);
	item.m_nFiles = item.m_nFileBuffer = 0x80000000u;
	item.AddFileIndex(9);
	assert(allocations == before && item.m_nFiles == 0x80000000u);
	item.m_nFiles = 2;
}
}

int main()
{
	TestHash();
	TestHub();
	TestPreview();
	TestBrowse();
	std::puts("PASS: hash rollback/reuse, hub ownership/exhaustion, preview aliasing, browse growth/wrap");
}
