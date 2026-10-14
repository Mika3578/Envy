// SPDX-License-Identifier: AGPL-3.0-or-later
// Tests for fresh-install storage defaults and preservation of configured paths.

#include "test_framework.h"
#include "../Envy/StoragePaths.h"

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

} // namespace

void register_storage_paths_smoke_tests(TestSuite& suite)
{
	suite.add_test("storage_paths_user_defaults", test_storage_defaults_use_per_user_locations);
	suite.add_test("storage_paths_custom_complete_root", test_storage_defaults_follow_custom_complete_root);
	suite.add_test("storage_paths_portable_defaults", test_portable_storage_defaults_stay_with_package);
	suite.add_test("storage_paths_join_roots", test_storage_path_join_preserves_drive_root);
	suite.add_test("storage_paths_preserve_configuration", test_storage_paths_preserve_nonempty_configuration);
	suite.add_test("storage_paths_reparse_detection", test_storage_path_reparse_point_detection);
}
