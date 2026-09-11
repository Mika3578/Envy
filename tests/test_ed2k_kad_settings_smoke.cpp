//
// test_ed2k_kad_settings_smoke.cpp
//
// Smoke tests for ED2K EnableKad settings policy (#124).
// Does not load MFC CSettings — verifies the shared default/key contract used
// by Settings.Add so InitKademlia is reachable when Kad is intended on.
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//

#include "test_framework.h"
#include "../Envy/Ed2kKadSettingsPolicy.h"

#include <cwchar>

static bool test_enablekad_default_true()
{
	return Ed2kEnableKadDefault() == true;
}

static bool test_enablekad_section_edonkey()
{
	return wcscmp(Ed2kEnableKadSection(), L"eDonkey") == 0;
}

static bool test_enablekad_name()
{
	return wcscmp(Ed2kEnableKadName(), L"EnableKad") == 0;
}

static bool test_enablekad_distinct_from_hello_name()
{
	// EnableKadHello is a different setting (protocol hello only).
	return wcscmp(Ed2kEnableKadName(), L"EnableKadHello") != 0;
}

void register_ed2k_kad_settings_smoke_tests(TestSuite& suite)
{
	suite.add_test("enablekad_default_true", test_enablekad_default_true);
	suite.add_test("enablekad_section_edonkey", test_enablekad_section_edonkey);
	suite.add_test("enablekad_name", test_enablekad_name);
	suite.add_test("enablekad_distinct_from_hello_name", test_enablekad_distinct_from_hello_name);
}
