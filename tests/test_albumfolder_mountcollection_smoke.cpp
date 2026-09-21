//
// test_albumfolder_mountcollection_smoke.cpp
//
// Portable stand-in for the CAlbumFolder::MountCollection child-visit
// policy (#300). CAlbumFolder itself is MFC/Library-locked and cannot
// be constructed in EnvyTests.
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//

#include "test_framework.h"

#include <array>
#include <cstddef>

// Mirrors the Release-safe MountCollection loops: skip a null child
// instead of calling a method with this == nullptr.
template<std::size_t N>
static bool VisitMountChildren(const std::array<int*, N>& children, int& nVisited)
{
	bool bResult = false;
	nVisited = 0;

	for (const int* pSubFolder : children)
	{
		if (pSubFolder == nullptr)
			continue;

		++nVisited;
		bResult = true;
	}

	return bResult;
}

static bool test_empty_tree()
{
	int nVisited = -1;
	const std::array<int*, 0> children{};
	const bool bResult = VisitMountChildren(children, nVisited);
	return !bResult && nVisited == 0;
}

static bool test_valid_children()
{
	int a = 1;
	int b = 2;
	const std::array<int*, 2> children{ &a, &b };
	int nVisited = 0;
	const bool bResult = VisitMountChildren(children, nVisited);
	return bResult && nVisited == 2;
}

static bool test_null_child_skipped()
{
	int a = 1;
	int b = 2;
	const std::array<int*, 3> children{ &a, nullptr, &b };
	int nVisited = 0;
	const bool bResult = VisitMountChildren(children, nVisited);
	return bResult && nVisited == 2;
}

static bool test_all_null_children()
{
	const std::array<int*, 2> children{ nullptr, nullptr };
	int nVisited = -1;
	const bool bResult = VisitMountChildren(children, nVisited);
	return !bResult && nVisited == 0;
}

static bool test_nested_valid_then_null()
{
	int rootChild = 1;
	int nested = 2;
	const std::array<int*, 2> outer{ &rootChild, nullptr };
	const std::array<int*, 1> inner{ &nested };
	int nOuter = 0;
	int nInner = 0;
	if (!VisitMountChildren(outer, nOuter))
		return false;
	if (!VisitMountChildren(inner, nInner))
		return false;
	return nOuter == 1 && nInner == 1;
}

void register_albumfolder_mountcollection_smoke_tests(TestSuite& suite)
{
	suite.add_test("albumfolder_mount_empty_tree", test_empty_tree);
	suite.add_test("albumfolder_mount_valid_children", test_valid_children);
	suite.add_test("albumfolder_mount_null_child_skipped", test_null_child_skipped);
	suite.add_test("albumfolder_mount_all_null_children", test_all_null_children);
	suite.add_test("albumfolder_mount_nested_visit", test_nested_valid_then_null);
}
