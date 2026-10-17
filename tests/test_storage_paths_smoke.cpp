// SPDX-License-Identifier: AGPL-3.0-or-later
// Tests for fresh-install storage defaults and preservation of configured paths.

#include "test_framework.h"
#include "../Envy/StoragePaths.h"
#include "../Envy/StorageProbe.h"

#include <sddl.h>

namespace
{

bool test_storage_defaults_use_per_user_locations()
{
	const StoragePathDefaults paths = BuildStoragePathDefaults(
	    L"C:\\Users\\User\\AppData\\Roaming",
	    L"C:\\Users\\User\\AppData\\Local",
	    L"D:\\Users\\User\\Downloads\\Envy");

	return paths.userData == L"C:\\Users\\User\\AppData\\Roaming\\Envy" &&
	       paths.incomplete == L"C:\\Users\\User\\AppData\\Local\\Envy\\Incomplete" &&
	       paths.complete == L"D:\\Users\\User\\Downloads\\Envy" &&
	       paths.collections == L"D:\\Users\\User\\Downloads\\Envy\\Collections" &&
	       paths.torrents == L"D:\\Users\\User\\Downloads\\Envy\\Torrents";
}

bool test_storage_defaults_follow_custom_complete_root()
{
	const StoragePathDefaults paths = BuildStoragePathDefaults(
	    L"C:\\Users\\User\\AppData\\Roaming",
	    L"C:\\Users\\User\\AppData\\Local",
	    L"E:\\Custom Downloads");

	return paths.collections == L"E:\\Custom Downloads\\Collections" &&
	       paths.torrents == L"E:\\Custom Downloads\\Torrents";
}

bool test_portable_storage_defaults_stay_with_package()
{
	const StoragePathDefaults paths = BuildPortableStoragePathDefaults(
	    L"E:\\Envy-Portable",
	    L"D:\\Users\\User\\Downloads\\Envy");

	return paths.userData == L"E:\\Envy-Portable" &&
	       paths.incomplete == L"E:\\Envy-Portable\\Incomplete" &&
	       paths.collections == L"E:\\Envy-Portable\\Collections" &&
	       paths.torrents == L"D:\\Users\\User\\Downloads\\Envy\\Torrents";
}

bool test_storage_mode_uses_installer_registration()
{
	return !IsPortableStorageMode(true, false) && !IsPortableStorageMode(false, true) &&
	       IsPortableStorageMode(false, false);
}

bool test_storage_path_join_preserves_drive_root()
{
	return JoinStoragePath(L"C:\\", L"Envy") == L"C:\\Envy" &&
	       JoinStoragePath(L"C:\\Users\\User\\", L"Envy") == L"C:\\Users\\User\\Envy";
}

bool test_storage_paths_preserve_nonempty_configuration()
{
	return ResolveStoragePath(L"F:\\Existing Incomplete", L"C:\\Users\\User\\AppData\\Local\\Envy\\Incomplete") ==
	           L"F:\\Existing Incomplete" &&
	       ResolveStoragePath(L"", L"C:\\Users\\User\\AppData\\Local\\Envy\\Incomplete") ==
	           L"C:\\Users\\User\\AppData\\Local\\Envy\\Incomplete" &&
	       ResolveStoragePath(L"", L"C:\\Users\\User\\AppData\\Local\\Envy\\Incomplete", L"C:\\Program Files\\Envy\\Incomplete") ==
	           L"C:\\Program Files\\Envy\\Incomplete";
}

bool test_storage_path_reparse_point_detection()
{
	return !StoragePathIsReparsePoint(0x10) &&
	       StoragePathIsReparsePoint(0x410) &&
	       !StoragePathIsReparsePoint(0xFFFFFFFF);
}

bool test_storage_recovery_offers_default_only_when_customised()
{
	return ChooseStorageRecovery(L"F:\\Incomplete", L"C:\\Users\\User\\AppData\\Local\\Envy\\Incomplete") ==
	           StorageRecovery::RetryUseDefaultOrExit &&
	       ChooseStorageRecovery(L"c:\\users\\user\\appdata\\local\\envy\\incomplete\\",
	                             L"C:\\Users\\User\\AppData\\Local\\Envy\\Incomplete") == StorageRecovery::RetryOrExit &&
	       ChooseStorageRecovery(L"F:\\Incomplete", L"") == StorageRecovery::RetryOrExit &&
	       StoragePathsEqual(L"C:\\", L"c:\\") && !StoragePathsEqual(L"C:\\Envy", L"C:\\Envy2");
}

// A read-only ACL reproduces a protected install dir or locked redirected folder:
// the directory exists, so only the write probe can reject it.
bool test_storage_probe_rejects_access_denied_directory()
{
	wchar_t szTemp[MAX_PATH] = {};
	if (!GetTempPathW(MAX_PATH, szTemp))
		return false;
	const std::wstring strRoot = std::wstring(szTemp) + L"envy-storage-probe-" + std::to_wstring(GetCurrentProcessId());
	const std::wstring strDenied = strRoot + L"\\Denied";
	const std::wstring strChild = strDenied + L"\\Data";

	PSECURITY_DESCRIPTOR pDescriptor = nullptr;
	if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(A;OICI;FRFX;;;WD)", SDDL_REVISION_1, &pDescriptor, nullptr))
		return false;
	SECURITY_ATTRIBUTES security = { sizeof(security), pDescriptor, FALSE };

	bool bOk = CreateDirectoryW(strRoot.c_str(), nullptr) && CreateDirectoryW(strDenied.c_str(), &security);
	DWORD nError = ERROR_SUCCESS;
	bOk = bOk && ProbeStorageDirectory(strRoot) == StorageProbeResult::Ready;
	bOk = bOk && ProbeStorageDirectory(strDenied, &nError) == StorageProbeResult::NotWritable && nError == ERROR_ACCESS_DENIED;
	bOk = bOk && ProbeStorageDirectory(strChild) == StorageProbeResult::CreateFailed;
	bOk = bOk && ProbeStorageDirectory(L"") == StorageProbeResult::CreateFailed;

	RemoveDirectoryW(strChild.c_str());
	RemoveDirectoryW(strDenied.c_str());
	// Retry after access is restored (here: the locked folder is replaced) must succeed.
	const bool bFresh = ProbeStorageDirectory(strDenied) == StorageProbeResult::Ready;
	RemoveDirectoryW(strDenied.c_str());
	RemoveDirectoryW(strRoot.c_str());
	LocalFree(pDescriptor);
	return bOk && bFresh;
}

} // namespace

void register_storage_paths_smoke_tests(TestSuite& suite)
{
	suite.add_test("storage_paths_user_defaults", test_storage_defaults_use_per_user_locations);
	suite.add_test("storage_paths_custom_complete_root", test_storage_defaults_follow_custom_complete_root);
	suite.add_test("storage_paths_portable_defaults", test_portable_storage_defaults_stay_with_package);
	suite.add_test("storage_paths_installer_registration", test_storage_mode_uses_installer_registration);
	suite.add_test("storage_paths_join_roots", test_storage_path_join_preserves_drive_root);
	suite.add_test("storage_paths_preserve_configuration", test_storage_paths_preserve_nonempty_configuration);
	suite.add_test("storage_paths_reparse_detection", test_storage_path_reparse_point_detection);
	suite.add_test("storage_paths_recovery_choice", test_storage_recovery_offers_default_only_when_customised);
	suite.add_test("storage_paths_probe_access_denied", test_storage_probe_rejects_access_denied_directory);
}
