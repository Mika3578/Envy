// Regression coverage for Windows path preparation used by library scanning.

#include "test_framework.h"
#include "LibraryFileSystem.h"

static bool test_local_long_path()
{
	const std::wstring input = L"C:\\TestShare\\Media\\" + std::wstring(240, L'x');
	const std::wstring output = EnvyFileSystem::ApiPath(input);
	return output.compare(0, 4, L"\\\\?\\") == 0 && output.substr(4) == input;
}

static bool test_unc_long_path()
{
	const std::wstring input = L"\\\\test-server\\test-share\\Media\\" + std::wstring(240, L'x');
	const std::wstring output = EnvyFileSystem::ApiPath(input);
	return output.compare(0, 8, L"\\\\?\\UNC\\") == 0 && output.substr(8) == input.substr(2);
}

static bool test_mapped_drive_long_path()
{
	const std::wstring input = L"X:\\TestShare\\Media\\" + std::wstring(240, L'x');
	const std::wstring output = EnvyFileSystem::ApiPath(input);
	return output.compare(0, 4, L"\\\\?\\") == 0 && output.substr(4) == input;
}

static bool test_existing_extended_path()
{
	const std::wstring input = L"\\\\?\\UNC\\test-server\\test-share\\Media";
	return EnvyFileSystem::ApiPath(input) == input;
}

static bool test_enumeration_errors()
{
	return EnvyFileSystem::EnumerationComplete(ERROR_NO_MORE_FILES) &&
	       EnvyFileSystem::EnumerationComplete(ERROR_FILE_NOT_FOUND) &&
	       !EnvyFileSystem::EnumerationComplete(ERROR_ACCESS_DENIED) &&
	       !EnvyFileSystem::EnumerationComplete(ERROR_OPERATION_ABORTED);
}

void register_library_filesystem_smoke_tests(TestSuite& suite)
{
	suite.add_test("library_filesystem_local_long_path", test_local_long_path);
	suite.add_test("library_filesystem_unc_long_path", test_unc_long_path);
	suite.add_test("library_filesystem_mapped_drive_long_path", test_mapped_drive_long_path);
	suite.add_test("library_filesystem_existing_extended_path", test_existing_extended_path);
	suite.add_test("library_filesystem_enumeration_errors", test_enumeration_errors);
}
