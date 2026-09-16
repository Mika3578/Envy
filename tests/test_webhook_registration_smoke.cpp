//
// test_webhook_registration_smoke.cpp
//
// Smoke tests for legacy IE WebHook plugin registration filtering.
// Verifies both architectures are skipped when WebHookEnable is false,
// and that enabling the setting allows registration to be attempted.
//
// Shipped names: WebHook32.dll / WebHook64.dll. WebHook.dll is historical.
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//

#include "test_framework.h"
#include "../Envy/WebHookRegistrationPolicy.h"

static bool test_skip_both_when_disabled()
{
	if ( ! ShouldSkipWebHookPluginRegistration( L"WebHook.dll", false ) )
		return false;
	if ( ! ShouldSkipWebHookPluginRegistration( L"WebHook32.dll", false ) )
		return false;
	if ( ! ShouldSkipWebHookPluginRegistration( L"WebHook64.dll", false ) )
		return false;
	return true;
}

static bool test_attempt_both_when_enabled()
{
	if ( ShouldSkipWebHookPluginRegistration( L"WebHook.dll", true ) )
		return false;
	if ( ShouldSkipWebHookPluginRegistration( L"WebHook32.dll", true ) )
		return false;
	if ( ShouldSkipWebHookPluginRegistration( L"WebHook64.dll", true ) )
		return false;
	return true;
}

static bool test_case_insensitive_names()
{
	if ( ! ShouldSkipWebHookPluginRegistration( L"webhook.dll", false ) )
		return false;
	if ( ! ShouldSkipWebHookPluginRegistration( L"WEBHOOK32.DLL", false ) )
		return false;
	if ( ! ShouldSkipWebHookPluginRegistration( L"WEBHOOK64.DLL", false ) )
		return false;
	return true;
}

static bool test_does_not_match_other_plugins()
{
	if ( ShouldSkipWebHookPluginRegistration( L"ImageViewer.dll", false ) )
		return false;
	if ( ShouldSkipWebHookPluginRegistration( L"WebHookExtra.dll", false ) )
		return false;
	if ( ShouldSkipWebHookPluginRegistration( L"WebHook.dll.bak", false ) )
		return false;
	if ( IsWebHookPluginFileName( L"WebHookX.dll" ) )
		return false;
	return true;
}

static bool test_bho_root_per_user_vs_machine()
{
	if ( WebHookBhoRegistryRoot( true ) != HKEY_CURRENT_USER )
		return false;
	if ( WebHookBhoRegistryRoot( false ) != HKEY_LOCAL_MACHINE )
		return false;
	return true;
}

static bool test_shared_clsid_unchanged()
{
	return _wcsicmp( WebHookBhoClsidString(),
		L"{C0283C00-AA11-43E4-8C1D-8D28A0C86042}" ) == 0;
}

void register_webhook_registration_smoke_tests(TestSuite& suite)
{
	suite.add_test( "webhook_skip_both_when_disabled", test_skip_both_when_disabled );
	suite.add_test( "webhook_attempt_both_when_enabled", test_attempt_both_when_enabled );
	suite.add_test( "webhook_case_insensitive_names", test_case_insensitive_names );
	suite.add_test( "webhook_does_not_match_other_plugins", test_does_not_match_other_plugins );
	suite.add_test( "webhook_bho_root_per_user_vs_machine", test_bho_root_per_user_vs_machine );
	suite.add_test( "webhook_shared_clsid_unchanged", test_shared_clsid_unchanged );
}
