//
// RemoteBase64.h
//
// Shared Base64 encode helper for RemoteSecurity (#92 empty-input safety).
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//

#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

// Encode raw bytes to Base64. Empty or null input yields an empty string
// (never writes padding into an empty buffer).
inline std::string RemoteBase64Encode( const uint8_t* data, size_t length )
{
	if ( data == nullptr || length == 0 )
		return std::string();

	static const char* const base64Chars =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

	std::string encoded;
	encoded.reserve( ( ( length + 2 ) / 3 ) * 4 );

	for ( size_t i = 0; i < length; i += 3 )
	{
		const uint32_t octet_a = data[ i ];
		const uint32_t octet_b = ( i + 1 < length ) ? data[ i + 1 ] : 0u;
		const uint32_t octet_c = ( i + 2 < length ) ? data[ i + 2 ] : 0u;
		const uint32_t triple = ( octet_a << 16 ) + ( octet_b << 8 ) + octet_c;

		encoded += base64Chars[ ( triple >> 18 ) & 0x3F ];
		encoded += base64Chars[ ( triple >> 12 ) & 0x3F ];
		encoded += base64Chars[ ( triple >> 6 ) & 0x3F ];
		encoded += base64Chars[ triple & 0x3F ];
	}

	const size_t padding = ( 3 - ( length % 3 ) ) % 3;
	if ( padding > 0 && encoded.size() >= padding )
	{
		for ( size_t i = 0; i < padding; ++i )
			encoded[ encoded.size() - 1 - i ] = '=';
	}

	return encoded;
}
