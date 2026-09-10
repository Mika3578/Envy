//
// SecureIdentPolicy.h
//
// Pure ED2K/eMule SecureIdent policy helpers (no network / MFC).
// Shared by CEDClient and EnvyTests smoke tests.
//
// Issue #75: Envy's historical MD5/non-zero SecureIdent path was not eMule-
// compatible RSA verification. Until real RSA SecureIdent exists, Envy must
// not advertise SecureIdent support and must never treat a peer as verified.
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//

#pragma once

#include <windows.h>

// Local SecureIdent session states used by CEDClient.
// State 3 historically meant both "response sent" and "verified"; that
// overload is retired. Verified is reserved for a future RSA success path.
enum
{
	ED2K_SECUREIDENT_STATE_NONE = 0,
	ED2K_SECUREIDENT_STATE_CHALLENGING = 1,	// legacy / unused until RSA
	ED2K_SECUREIDENT_STATE_RESPONDING = 2,	// legacy / unused until RSA
	ED2K_SECUREIDENT_STATE_VERIFIED = 3		// only after real RSA verify
};

// Hello FeatureVersions SecureIdent nibble. Must stay 0 while RSA verification
// is unimplemented — Envy must not claim a capability it cannot enforce.
inline BYTE Ed2kSecureIdentAdvertisedVersion()
{
	return 0;
}

// Real eMule SecureIdent (RSA signature over challenge with peer public key)
// is not implemented yet.
inline BOOL Ed2kSecureIdentIsImplemented()
{
	return FALSE;
}

// Reject every SecureIdent response until RSA verification exists.
// Length, null, zero-fill, non-zero bytes, and legacy MD5-shaped payloads
// are all refused — none prove peer identity.
inline BOOL Ed2kSecureIdentAcceptResponse(const BYTE* pResponse, DWORD nLength)
{
	(void)pResponse;
	(void)nLength;
	return FALSE;
}

// A peer is never SecureIdent-verified without Ed2kSecureIdentAcceptResponse
// succeeding under a future RSA implementation.
inline BOOL Ed2kSecureIdentIsVerifiedState(DWORD nState)
{
	return Ed2kSecureIdentIsImplemented()
		&& nState == ED2K_SECUREIDENT_STATE_VERIFIED;
}

// After rejecting/ignoring an inbound SecureIdent packet, clear to none.
inline DWORD Ed2kSecureIdentStateAfterRejectedResponse()
{
	return ED2K_SECUREIDENT_STATE_NONE;
}

// SecureIdent is authentication/trust only — never a prerequisite for ED2K
// Hello, source use, or file transfer.
inline BOOL Ed2kRequiresSecureIdentForTransfer()
{
	return FALSE;
}
