//
// RemotePasswordPolicy.h
//
// Pure predicates for Remote password-hash formats (no CNG / MFC).
// Shared by RemoteSecurity and EnvyTests.
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//

#pragma once

#include <windows.h>
#include <cctype>
#include <cstdint>
#include <cstring>

// PBKDF2-HMAC-SHA256 parameters for new Remote password hashes (#79).
constexpr ULONG REMOTE_PBKDF2_ITERATIONS = 100000ul;
constexpr size_t REMOTE_PBKDF2_SALT_BYTES = 16u;
constexpr size_t REMOTE_PBKDF2_KEY_BYTES = 32u;

inline BOOL RemoteLegacySha1HashLooksValid(const char* pszHash, size_t nLen)
{
	if ( pszHash == nullptr || nLen != 40 )
		return FALSE;
	for ( size_t i = 0; i < nLen; ++i )
	{
		if ( ! isxdigit( static_cast< unsigned char >( pszHash[ i ] ) ) )
			return FALSE;
	}
	return TRUE;
}

inline BOOL RemotePasswordNeedsRehash(const char* pszHash)
{
	if ( pszHash == nullptr || pszHash[ 0 ] == '\0' )
		return TRUE;
	// Current format: pbkdf2-sha256:<iters>:<salt>:<dk>
	return strncmp( pszHash, "pbkdf2-sha256:", 14 ) != 0;
}
