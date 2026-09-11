//
// test_ed2k_kad_settings_smoke.cpp
//
// Smoke tests for ED2K EnableKad settings policy (#124).
// Covers absent-key default, save/reload, and name collisions with sibling
// Kad settings — without loading MFC CSettings.
//
// Missing-key / save semantics mirror CSettings::Item::Load/Save →
// CRegistry::GetBool/SetBool (absent key returns bDefault).
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//

#include "test_framework.h"
#include "../Envy/Ed2kKadSettingsPolicy.h"

#include <cwchar>
#include <map>
#include <string>

namespace {

// In-memory mirror of CRegistry bool Get/Set used by Settings::Item Load/Save.
class BoolSettingStore
{
public:
	void SetBool(LPCTSTR pszSection, LPCTSTR pszName, bool bValue)
	{
		m_oValues[ Key( pszSection, pszName ) ] = bValue ? 1u : 0u;
	}

	bool Has(LPCTSTR pszSection, LPCTSTR pszName) const
	{
		return m_oValues.find( Key( pszSection, pszName ) ) != m_oValues.end();
	}

	void Delete(LPCTSTR pszSection, LPCTSTR pszName)
	{
		m_oValues.erase( Key( pszSection, pszName ) );
	}

	bool GetBool(LPCTSTR pszSection, LPCTSTR pszName, bool bDefault) const
	{
		const auto it = m_oValues.find( Key( pszSection, pszName ) );
		if ( it == m_oValues.end() )
			return bDefault;
		return it->second != 0;
	}

private:
	static std::wstring Key(LPCTSTR pszSection, LPCTSTR pszName)
	{
		std::wstring s( pszSection ? pszSection : L"" );
		s.push_back( L'\\' );
		s.append( pszName ? pszName : L"" );
		return s;
	}

	std::map<std::wstring, DWORD> m_oValues;
};

bool LoadEnableKad(const BoolSettingStore& store)
{
	return store.GetBool(
		Ed2kEnableKadSection(),
		Ed2kEnableKadName(),
		Ed2kEnableKadDefault() );
}

void SaveEnableKad(BoolSettingStore& store, bool bValue)
{
	store.SetBool( Ed2kEnableKadSection(), Ed2kEnableKadName(), bValue );
}

} // namespace

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

static bool test_enablekad_no_sibling_name_collision()
{
	return Ed2kEnableKadNameCollidesWithSiblings() == false;
}

static bool test_enablekad_absent_key_loads_default_true()
{
	BoolSettingStore store;
	return store.Has(Ed2kEnableKadSection(), Ed2kEnableKadName()) == false
		&& LoadEnableKad(store) == true;
}

static bool test_enablekad_save_reload_false()
{
	BoolSettingStore store;
	SaveEnableKad(store, false);
	return store.Has(Ed2kEnableKadSection(), Ed2kEnableKadName())
		&& LoadEnableKad(store) == false;
}

static bool test_enablekad_save_reload_true()
{
	BoolSettingStore store;
	SaveEnableKad(store, false);
	SaveEnableKad(store, true);
	return LoadEnableKad(store) == true;
}

static bool test_enablekad_delete_restores_default()
{
	BoolSettingStore store;
	SaveEnableKad(store, false);
	store.Delete(Ed2kEnableKadSection(), Ed2kEnableKadName());
	return LoadEnableKad(store) == Ed2kEnableKadDefault();
}

static bool test_enablekad_independent_of_enablekadhello()
{
	BoolSettingStore store;
	store.SetBool(Ed2kEnableKadSection(), L"EnableKadHello", false);
	SaveEnableKad(store, true);
	return store.GetBool(Ed2kEnableKadSection(), L"EnableKadHello", true) == false
		&& LoadEnableKad(store) == true;
}

void register_ed2k_kad_settings_smoke_tests(TestSuite& suite)
{
	suite.add_test("enablekad_default_true", test_enablekad_default_true);
	suite.add_test("enablekad_section_edonkey", test_enablekad_section_edonkey);
	suite.add_test("enablekad_name", test_enablekad_name);
	suite.add_test("enablekad_no_sibling_name_collision", test_enablekad_no_sibling_name_collision);
	suite.add_test("enablekad_absent_key_loads_default_true", test_enablekad_absent_key_loads_default_true);
	suite.add_test("enablekad_save_reload_false", test_enablekad_save_reload_false);
	suite.add_test("enablekad_save_reload_true", test_enablekad_save_reload_true);
	suite.add_test("enablekad_delete_restores_default", test_enablekad_delete_restores_default);
	suite.add_test("enablekad_independent_of_enablekadhello", test_enablekad_independent_of_enablekadhello);
}
