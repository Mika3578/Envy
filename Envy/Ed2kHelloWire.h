//
// Ed2kHelloWire.h
//
// Pure ED2K C2C Hello / HelloAnswer body + TCP framing helpers (no MFC).
// Layout MUST stay aligned with CEDClient::SendHello:
//   - Hello prepends legacy hash-size byte 0x10; HelloAnswer does not
//   - classic tags (bSmallTags = FALSE): type, WORD key-len=1, key, value
//   - nickname via Unicode ED-string (WORD UTF-8 length + UTF-8 bytes)
//   - six fixed tags in order: Name, Version, UdpPorts, FeatureVersions,
//     MoreFeatureVersions, SoftwareVersion
//   - trailing server IPv4 + port (LE), zeros when no server
//   - GUID bytes [5]=14 and [14]=111 applied like SendHello
//
// Shared by EnvyTests golden vectors. Do not treat packed bytes as an
// eMule/aMule capture unless SOURCE says so.
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//

#pragma once

#include <windows.h>
#include <string.h>

#include "Ed2kHelloCapabilities.h"

#ifndef ED2K_PROTOCOL_EDONKEY
#define ED2K_PROTOCOL_EDONKEY			0xE3
#endif
#ifndef ED2K_C2C_HELLO
#define ED2K_C2C_HELLO					0x01
#endif
#ifndef ED2K_C2C_HELLOANSWER
#define ED2K_C2C_HELLOANSWER			0x4C
#endif
#ifndef ED2K_CT_NAME
#define ED2K_CT_NAME					0x01
#endif
#ifndef ED2K_CT_VERSION
#define ED2K_CT_VERSION					0x11
#endif
#ifndef ED2K_CT_UDPPORTS
#define ED2K_CT_UDPPORTS				0xF9
#endif
#ifndef ED2K_CT_FEATUREVERSIONS
#define ED2K_CT_FEATUREVERSIONS			0xFA
#endif
#ifndef ED2K_CT_SOFTWAREVERSION
#define ED2K_CT_SOFTWAREVERSION			0xFB
#endif
#ifndef ED2K_CT_MOREFEATUREVERSIONS
#define ED2K_CT_MOREFEATUREVERSIONS		0xFE
#endif
#ifndef ED2K_TAG_STRING
#define ED2K_TAG_STRING					0x02
#endif
#ifndef ED2K_TAG_INT
#define ED2K_TAG_INT					0x03
#endif
#ifndef ED2K_VERSION
#define ED2K_VERSION					0x3D
#endif

// Deterministic Hello / HelloAnswer inputs (host-order ports, LE integer fields).
struct Ed2kHelloWireInput
{
	BYTE	userHash[16];			// raw GUID before SendHello mutation
	DWORD	clientId;				// written little-endian
	WORD	tcpPort;				// host-order TCP port (e.g. 4662)
	WORD	udpPort;				// host-order UDP port for CT_UDPPORTS
	const BYTE* nickUtf8;			// UTF-8 nickname bytes (not null-terminated required)
	WORD	nickUtf8Len;
	DWORD	ed2kVersion;			// ED2K_CT_VERSION (typically ED2K_VERSION)
	DWORD	miscOptions1;			// CT_FEATUREVERSIONS
	DWORD	miscOptions2;			// CT_MOREFEATUREVERSIONS
	DWORD	softwareVersion;		// CT_SOFTWAREVERSION
	DWORD	serverIp;				// trailing server IPv4 (0 if none)
	WORD	serverPort;				// host-order server TCP port
	BOOL	bHello;					// TRUE = Hello (0x01 + 0x10), FALSE = HelloAnswer (0x4C)
};

inline void Ed2kHelloApplyGuidMutation(BYTE hash[16])
{
	// Matches CEDClient::SendHello: oGUID[5] = 14; oGUID[14] = 111;
	hash[5] = 14;
	hash[14] = 111;
}

inline BOOL Ed2kHelloWireAppendByte(BYTE* pOut, size_t nCap, size_t* pLen, BYTE nValue)
{
	if ( *pLen >= nCap )
		return FALSE;
	pOut[(*pLen)++] = nValue;
	return TRUE;
}

inline BOOL Ed2kHelloWireAppendBytes(BYTE* pOut, size_t nCap, size_t* pLen, const void* pData, size_t nBytes)
{
	if ( *pLen + nBytes > nCap )
		return FALSE;
	CopyMemory( pOut + *pLen, pData, nBytes );
	*pLen += nBytes;
	return TRUE;
}

inline BOOL Ed2kHelloWireAppendU16LE(BYTE* pOut, size_t nCap, size_t* pLen, WORD nValue)
{
	BYTE b[2] = { (BYTE)( nValue & 0xFF ), (BYTE)( ( nValue >> 8 ) & 0xFF ) };
	return Ed2kHelloWireAppendBytes( pOut, nCap, pLen, b, 2 );
}

inline BOOL Ed2kHelloWireAppendU32LE(BYTE* pOut, size_t nCap, size_t* pLen, DWORD nValue)
{
	BYTE b[4] = {
		(BYTE)( nValue & 0xFF ),
		(BYTE)( ( nValue >> 8 ) & 0xFF ),
		(BYTE)( ( nValue >> 16 ) & 0xFF ),
		(BYTE)( ( nValue >> 24 ) & 0xFF ) };
	return Ed2kHelloWireAppendBytes( pOut, nCap, pLen, b, 4 );
}

// Classic ED2K int tag (bSmallTags = FALSE).
inline BOOL Ed2kHelloWireAppendIntTag(BYTE* pOut, size_t nCap, size_t* pLen, BYTE nKey, DWORD nValue)
{
	return Ed2kHelloWireAppendByte( pOut, nCap, pLen, ED2K_TAG_INT )
		&& Ed2kHelloWireAppendU16LE( pOut, nCap, pLen, 1 )
		&& Ed2kHelloWireAppendByte( pOut, nCap, pLen, nKey )
		&& Ed2kHelloWireAppendU32LE( pOut, nCap, pLen, nValue );
}

// Classic ED2K Unicode string tag (WORD UTF-8 length + UTF-8 payload).
inline BOOL Ed2kHelloWireAppendUtf8StringTag(
	BYTE* pOut, size_t nCap, size_t* pLen,
	BYTE nKey, const BYTE* pUtf8, WORD nUtf8Len)
{
	return Ed2kHelloWireAppendByte( pOut, nCap, pLen, ED2K_TAG_STRING )
		&& Ed2kHelloWireAppendU16LE( pOut, nCap, pLen, 1 )
		&& Ed2kHelloWireAppendByte( pOut, nCap, pLen, nKey )
		&& Ed2kHelloWireAppendU16LE( pOut, nCap, pLen, nUtf8Len )
		&& Ed2kHelloWireAppendBytes( pOut, nCap, pLen, pUtf8, nUtf8Len );
}

// Pack packet body only (no TCP header / opcode). Returns FALSE on overflow.
inline BOOL Ed2kPackHelloBody(const Ed2kHelloWireInput* pIn, BYTE* pOut, size_t nCap, size_t* pLen)
{
	if ( ! pIn || ! pOut || ! pLen )
		return FALSE;

	*pLen = 0;

	BYTE hash[16];
	CopyMemory( hash, pIn->userHash, 16 );
	Ed2kHelloApplyGuidMutation( hash );

	if ( pIn->bHello )
	{
		if ( ! Ed2kHelloWireAppendByte( pOut, nCap, pLen, 0x10 ) )
			return FALSE;
	}

	if ( ! Ed2kHelloWireAppendBytes( pOut, nCap, pLen, hash, 16 )
		|| ! Ed2kHelloWireAppendU32LE( pOut, nCap, pLen, pIn->clientId )
		|| ! Ed2kHelloWireAppendU16LE( pOut, nCap, pLen, pIn->tcpPort )
		|| ! Ed2kHelloWireAppendU32LE( pOut, nCap, pLen, 6 )	// tag count
		|| ! Ed2kHelloWireAppendUtf8StringTag( pOut, nCap, pLen, ED2K_CT_NAME, pIn->nickUtf8, pIn->nickUtf8Len )
		|| ! Ed2kHelloWireAppendIntTag( pOut, nCap, pLen, ED2K_CT_VERSION, pIn->ed2kVersion )
		|| ! Ed2kHelloWireAppendIntTag( pOut, nCap, pLen, ED2K_CT_UDPPORTS, (DWORD)pIn->udpPort )
		|| ! Ed2kHelloWireAppendIntTag( pOut, nCap, pLen, ED2K_CT_FEATUREVERSIONS, pIn->miscOptions1 )
		|| ! Ed2kHelloWireAppendIntTag( pOut, nCap, pLen, ED2K_CT_MOREFEATUREVERSIONS, pIn->miscOptions2 )
		|| ! Ed2kHelloWireAppendIntTag( pOut, nCap, pLen, ED2K_CT_SOFTWAREVERSION, pIn->softwareVersion )
		|| ! Ed2kHelloWireAppendU32LE( pOut, nCap, pLen, pIn->serverIp )
		|| ! Ed2kHelloWireAppendU16LE( pOut, nCap, pLen, pIn->serverPort ) )
	{
		return FALSE;
	}

	return TRUE;
}

// Full TCP frame: protocol 0xE3 | length(LE)=body+1 | opcode | body.
inline BOOL Ed2kPackHelloTcpPacket(const Ed2kHelloWireInput* pIn, BYTE* pOut, size_t nCap, size_t* pLen)
{
	if ( ! pIn || ! pOut || ! pLen || nCap < 6 )
		return FALSE;

	BYTE body[512];
	size_t nBody = 0;
	if ( ! Ed2kPackHelloBody( pIn, body, sizeof( body ), &nBody ) )
		return FALSE;

	const BYTE nOpcode = pIn->bHello ? (BYTE)ED2K_C2C_HELLO : (BYTE)ED2K_C2C_HELLOANSWER;
	const DWORD nLength = (DWORD)( nBody + 1 );	// includes type byte

	*pLen = 0;
	if ( ! Ed2kHelloWireAppendByte( pOut, nCap, pLen, ED2K_PROTOCOL_EDONKEY )
		|| ! Ed2kHelloWireAppendU32LE( pOut, nCap, pLen, nLength )
		|| ! Ed2kHelloWireAppendByte( pOut, nCap, pLen, nOpcode )
		|| ! Ed2kHelloWireAppendBytes( pOut, nCap, pLen, body, nBody ) )
	{
		return FALSE;
	}

	return TRUE;
}

// SoftwareVersion packing used by CEDClient::SendHello (major/minor only).
inline DWORD Ed2kPackSoftwareVersion(BYTE nClientId, WORD nMajor, WORD nMinor)
{
	return ( ( (DWORD)( nClientId & 0xFF ) << 24 ) |
			 ( (DWORD)( nMajor & 0x7F ) << 17 ) |
			 ( (DWORD)( nMinor & 0x7F ) << 10 ) );
}

// Scan classic Hello/HelloAnswer body for a numeric tag by key.
// pBody points at the first body byte (0x10 for Hello, or hash[0] for HelloAnswer).
inline BOOL Ed2kHelloBodyFindIntTag(
	const BYTE* pBody, size_t nBody, BOOL bHello, BYTE nKey, DWORD* pValue)
{
	if ( ! pBody || ! pValue || nBody < 1 )
		return FALSE;

	size_t n = 0;
	if ( bHello )
	{
		if ( pBody[0] != 0x10 )
			return FALSE;
		n = 1;
	}

	if ( n + 16 + 4 + 2 + 4 > nBody )
		return FALSE;
	n += 16 + 4 + 2;	// hash + clientId + port

	const DWORD nTags =
		(DWORD)pBody[n]
		| ( (DWORD)pBody[n + 1] << 8 )
		| ( (DWORD)pBody[n + 2] << 16 )
		| ( (DWORD)pBody[n + 3] << 24 );
	n += 4;

	for ( DWORD i = 0; i < nTags; ++i )
	{
		if ( n + 1 + 2 + 1 > nBody )
			return FALSE;

		const BYTE nType = pBody[n++];
		const WORD nKeyLen = (WORD)( pBody[n] | ( pBody[n + 1] << 8 ) );
		n += 2;
		if ( nKeyLen != 1 || n + 1 > nBody )
			return FALSE;

		const BYTE nTagKey = pBody[n++];

		if ( nType == ED2K_TAG_INT )
		{
			if ( n + 4 > nBody )
				return FALSE;
			const DWORD nVal =
				(DWORD)pBody[n]
				| ( (DWORD)pBody[n + 1] << 8 )
				| ( (DWORD)pBody[n + 2] << 16 )
				| ( (DWORD)pBody[n + 3] << 24 );
			n += 4;
			if ( nTagKey == nKey )
			{
				*pValue = nVal;
				return TRUE;
			}
		}
		else if ( nType == ED2K_TAG_STRING )
		{
			if ( n + 2 > nBody )
				return FALSE;
			const WORD nStrLen = (WORD)( pBody[n] | ( pBody[n + 1] << 8 ) );
			n += 2;
			if ( n + nStrLen > nBody )
				return FALSE;
			n += nStrLen;
		}
		else
		{
			return FALSE;	// unexpected classic-tag type in Envy Hello
		}
	}

	return FALSE;
}

// TCP packet → body pointer/length (skips 0xE3 + length + opcode).
inline BOOL Ed2kHelloTcpStripHeader(
	const BYTE* pPacket, size_t nPacket, BYTE* pOpcode, const BYTE** ppBody, size_t* pBodyLen)
{
	if ( ! pPacket || ! pOpcode || ! ppBody || ! pBodyLen || nPacket < 6 )
		return FALSE;
	if ( pPacket[0] != ED2K_PROTOCOL_EDONKEY )
		return FALSE;

	const DWORD nLength =
		(DWORD)pPacket[1]
		| ( (DWORD)pPacket[2] << 8 )
		| ( (DWORD)pPacket[3] << 16 )
		| ( (DWORD)pPacket[4] << 24 );
	if ( nLength < 1 || nPacket < 5 + nLength )
		return FALSE;

	*pOpcode = pPacket[5];
	*ppBody = pPacket + 6;
	*pBodyLen = (size_t)( nLength - 1 );
	return TRUE;
}
