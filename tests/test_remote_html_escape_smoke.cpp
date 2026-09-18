//
// test_remote_html_escape_smoke.cpp
//
// Smoke tests for Remote HTML-entity escape contract (#76 XSS).
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//

#include "test_framework.h"
#include "../Envy/RemoteHtmlEscape.h"

static bool test_remote_html_escape_null_empty()
{
	return RemoteHtmlEscape( nullptr ).empty()
		&& RemoteHtmlEscape( L"" ).empty();
}

static bool test_remote_html_escape_specials()
{
	return RemoteHtmlEscape( L"a&b<c>d\"e'f" )
		== L"a&amp;b&lt;c&gt;d&quot;e&apos;f";
}

static bool test_remote_html_escape_script_payload()
{
	return RemoteHtmlEscapeNeutralizesXssPayload(
			L"<img src=x onerror=alert(1)>" ) != FALSE
		&& RemoteHtmlEscapeNeutralizesXssPayload(
			L"\" onmouseover=\"alert(1)" ) != FALSE
		&& RemoteHtmlEscapeNeutralizesXssPayload(
			L"';><script>alert(1)</script>" ) != FALSE;
}

static bool test_remote_html_escape_safe_passthrough()
{
	return RemoteHtmlEscape( L"file.txt" ) == L"file.txt"
		&& RemoteHtmlEscape( L"eMule 0.50a" ) == L"eMule 0.50a";
}

void register_remote_html_escape_smoke_tests( TestSuite& suite )
{
	suite.add_test( "remote_html_escape_null_empty", test_remote_html_escape_null_empty );
	suite.add_test( "remote_html_escape_specials", test_remote_html_escape_specials );
	suite.add_test( "remote_html_escape_script_payload", test_remote_html_escape_script_payload );
	suite.add_test( "remote_html_escape_safe_passthrough", test_remote_html_escape_safe_passthrough );
}
