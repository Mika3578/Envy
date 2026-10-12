//
// test_schema_icon_resources.cpp
//
// Regression coverage for schema descriptor icon references.
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
// License: GNU Affero General Public License v3.0 (AGPLv3)
//

#include "test_framework.h"

#include <filesystem>
#include <fstream>
#include <regex>
#include <string>

static std::filesystem::path find_schema_directory()
{
	std::filesystem::path path = std::filesystem::current_path();
	for ( int nLevel = 0; nLevel < 5; ++nLevel )
	{
		const std::filesystem::path schemas = path / L"Schemas";
		if ( std::filesystem::is_directory( schemas ) )
			return schemas;
		path = path.parent_path();
	}

	return std::filesystem::path();
}

static bool test_schema_descriptor_icons_exist()
{
	const std::filesystem::path schemas = find_schema_directory();
	if ( schemas.empty() )
		return false;

	const std::regex iconPattern( R"REGEX(<icon\s+path="([^"]+)")REGEX" );
	bool bFoundIcon = false;

	for ( const std::filesystem::directory_entry& entry : std::filesystem::directory_iterator( schemas ) )
	{
		if ( entry.path().extension() != L".xml" )
			continue;

		std::ifstream file( entry.path(), std::ios::binary );
		if ( ! file )
			return false;

		const std::string xml( ( std::istreambuf_iterator< char >( file ) ), std::istreambuf_iterator< char >() );
		for ( std::sregex_iterator it( xml.begin(), xml.end(), iconPattern ), end; it != end; ++it )
		{
			bFoundIcon = true;
			if ( ! std::filesystem::is_regular_file( schemas / ( *it )[ 1 ].str() ) )
				return false;
		}
	}

	return bFoundIcon;
}

void register_schema_icon_resource_tests( TestSuite& suite )
{
	suite.add_test( "Schema icons: every descriptor reference has a resource",
		test_schema_descriptor_icons_exist );
}
