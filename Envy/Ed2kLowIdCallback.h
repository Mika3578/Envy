//
// Ed2kLowIdCallback.h
//
// Pure ED2K/eMule LowID callback + PUBLICIP packet/state helpers (no MFC / network).
// Phase-1 baseline for #87 — not Buddy/firewall completion.
//
// Protocol evidence (aMule / eMule Community):
//   OP_PUBLICIP_REQ (0x97): empty body; answer with peer's observed IPv4.
//   OP_PUBLICIP_ANSWER (0x98): exactly 4 bytes (raw sockaddr-style DWORD / LE on wire).
//   OP_CALLBACK (0x99): <KadCheck 16><FileHash 16><IP 4><TCPPort 2> = 38 bytes
//     (header comments that say <HASH><HASH><uint16> are incomplete).
//   OP_REASKCALLBACKTCP (0x9A): Buddy-only; deferred to phase 2.
//
// Shared by CEDClient handlers and EnvyTests smoke tests.
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//

#pragma once

#include <windows.h>
#include <string.h>

// ---- Wire sizes ----

inline constexpr DWORD Ed2kPublicIpReqExactBytes()
{
	return 0u;
}

inline constexpr DWORD Ed2kPublicIpAnswerExactBytes()
{
	return 4u;
}

// aMule ClientTCPSocket.cpp OP_CALLBACK / eMule ListenSocket.cpp OP_CALLBACK
inline constexpr DWORD Ed2kC2cCallbackExactBytes()
{
	return 16u + 16u + 4u + 2u; // 38
}

// Buddy-forwarded reask: <IP 4><UDPPort 2><FileHash 16> minimum (extended info may follow)
inline constexpr DWORD Ed2kReaskCallbackTcpMinBytes()
{
	return 4u + 2u + 16u;
}

// Classic server S2C_CALLBACKREQUESTED: <IP 4><PORT 2>
inline constexpr DWORD Ed2kServerCallbackRequestedExactBytes()
{
	return 4u + 2u;
}

// Public-IP query / C2C callback pending lifetime (ms)
inline constexpr DWORD Ed2kPublicIpQueryTimeoutMs()
{
	return 60u * 1000u;
}

inline constexpr DWORD Ed2kC2cCallbackPendingTimeoutMs()
{
	return 60u * 1000u;
}

// ED2K LowID threshold (same as CEDPacket::IsLowID)
inline BOOL Ed2kIsLowIdValue(DWORD nId)
{
	return nId > 0 && nId < 16777216u;
}

// ---- PUBLICIP ----

inline BOOL Ed2kPublicIpReqPayloadOk(DWORD nRemaining)
{
	return nRemaining == Ed2kPublicIpReqExactBytes();
}

// Exact 4-byte answer; truncated / empty / oversize rejected (eMule throws on != 4).
inline BOOL Ed2kPublicIpAnswerPayloadOk(DWORD nRemaining)
{
	return nRemaining == Ed2kPublicIpAnswerExactBytes();
}

// Decode IPv4 from PUBLICIP_ANSWER body (little-endian DWORD = sockaddr s_addr form).
inline BOOL Ed2kPublicIpAnswerDecode(const BYTE* pData, DWORD nLen, DWORD* pnIpOut)
{
	if (!pData || !pnIpOut || !Ed2kPublicIpAnswerPayloadOk(nLen))
		return FALSE;

	DWORD nIp = (DWORD)pData[0] | ((DWORD)pData[1] << 8) | ((DWORD)pData[2] << 16) | ((DWORD)pData[3] << 24);
	*pnIpOut = nIp;
	return TRUE;
}

// Encode observed peer IPv4 into PUBLICIP_ANSWER body (LE dword).
inline BOOL Ed2kPublicIpAnswerEncode(DWORD nPeerIp, BYTE* pOut4)
{
	if (!pOut4)
		return FALSE;

	pOut4[0] = (BYTE)(nPeerIp & 0xFF);
	pOut4[1] = (BYTE)((nPeerIp >> 8) & 0xFF);
	pOut4[2] = (BYTE)((nPeerIp >> 16) & 0xFF);
	pOut4[3] = (BYTE)((nPeerIp >> 24) & 0xFF);
	return TRUE;
}

// eMule/aMule: only apply answer when we asked, public IP still unknown, and value is not LowID-shaped.
inline BOOL Ed2kPublicIpAnswerMayApply(BOOL bNeedOurPublicIp, DWORD nCurrentPublicIp, DWORD nAnswerIp)
{
	if (!bNeedOurPublicIp)
		return FALSE;
	if (nCurrentPublicIp != 0)
		return FALSE;
	if (Ed2kIsLowIdValue(nAnswerIp))
		return FALSE;
	return TRUE;
}

// Bounded public-IP query state (per peer session).
struct Ed2kPublicIpQueryState
{
	BOOL bOutstanding;
	BOOL bConsumed;
	DWORD tCreatedMs;

	Ed2kPublicIpQueryState()
	    : bOutstanding(FALSE)
	    , bConsumed(FALSE)
	    , tCreatedMs(0)
	{
	}

	void Clear()
	{
		bOutstanding = FALSE;
		bConsumed = FALSE;
		tCreatedMs = 0;
	}

	void MarkRequested(DWORD tNowMs)
	{
		bOutstanding = TRUE;
		bConsumed = FALSE;
		tCreatedMs = tNowMs;
	}

	BOOL IsExpired(DWORD tNowMs, DWORD nTimeoutMs = Ed2kPublicIpQueryTimeoutMs()) const
	{
		if (!bOutstanding)
			return FALSE;
		return (tNowMs - tCreatedMs) >= nTimeoutMs;
	}

	// Accept one answer while outstanding and not yet consumed.
	BOOL TryConsumeAnswer(DWORD tNowMs, DWORD nTimeoutMs = Ed2kPublicIpQueryTimeoutMs())
	{
		if (!bOutstanding || bConsumed)
			return FALSE;
		if (IsExpired(tNowMs, nTimeoutMs))
		{
			Clear();
			return FALSE;
		}
		bOutstanding = FALSE;
		bConsumed = TRUE;
		return TRUE;
	}

	void OnDisconnect()
	{
		Clear();
	}
};

// ---- C2C CALLBACK (0x99) ----

struct Ed2kC2cCallbackFields
{
	BYTE kadCheck[16]; // ownKadId XOR 0xFF…FF when valid for us
	BYTE fileHash[16];
	DWORD nIp;     // LE dword / sockaddr s_addr form (Kad host IP storage)
	WORD nTcpPort; // host-order port after LE decode
};

inline void Ed2kXorKadIdWithOnes(BYTE* pId16)
{
	if (!pId16)
		return;
	for (int i = 0; i < 16; ++i)
		pId16[i] = (BYTE)(pId16[i] ^ 0xFF);
}

// packetCheck XOR all-ones must equal our Kad ID (aMule/eMule OP_CALLBACK).
inline BOOL Ed2kCallbackKadIdMatches(const BYTE* pPacketCheck16, const BYTE* pOwnKadId16)
{
	if (!pPacketCheck16 || !pOwnKadId16)
		return FALSE;

	BYTE tmp[16];
	memcpy(tmp, pPacketCheck16, 16);
	Ed2kXorKadIdWithOnes(tmp);
	return memcmp(tmp, pOwnKadId16, 16) == 0;
}

inline BOOL Ed2kC2cCallbackPayloadOk(DWORD nRemaining)
{
	return nRemaining == Ed2kC2cCallbackExactBytes();
}

inline BOOL Ed2kC2cCallbackParse(const BYTE* pData, DWORD nLen, Ed2kC2cCallbackFields* pOut)
{
	if (!pData || !pOut || !Ed2kC2cCallbackPayloadOk(nLen))
		return FALSE;

	memcpy(pOut->kadCheck, pData, 16);
	memcpy(pOut->fileHash, pData + 16, 16);
	pOut->nIp = (DWORD)pData[32] | ((DWORD)pData[33] << 8) | ((DWORD)pData[34] << 16) | ((DWORD)pData[35] << 24);
	pOut->nTcpPort = (WORD)((DWORD)pData[36] | ((DWORD)pData[37] << 8));
	return TRUE;
}

// Endpoint checks before initiating a callback-derived HighID connect.
inline BOOL Ed2kCallbackEndpointOk(DWORD nIp, WORD nPort)
{
	if (nPort == 0)
		return FALSE;
	if (nIp == 0 || nIp == 0xFFFFFFFFu)
		return FALSE;
	// Reject LowID-shaped values used as an IP (cannot dial a LowID as HighID).
	if (Ed2kIsLowIdValue(nIp))
		return FALSE;
	return TRUE;
}

// Zero / empty file hash is not a usable callback target identity.
inline BOOL Ed2kCallbackFileHashNonEmpty(const BYTE* pHash16)
{
	if (!pHash16)
		return FALSE;
	static const BYTE zeros[16] = {};
	return memcmp(pHash16, zeros, 16) != 0;
}

// One-shot consume guard for inbound OP_CALLBACK (eMule connects immediately).
// Duplicate identical (ip,port,file) within the window must not reconnect;
// a different peer/file target is a separate event and is allowed.
struct Ed2kC2cCallbackConsumeGuard
{
	BOOL bArmed;
	BOOL bConsumed;
	DWORD tCreatedMs;
	DWORD nIp;
	WORD nPort;
	BYTE fileHash[16];

	Ed2kC2cCallbackConsumeGuard()
	    : bArmed(FALSE)
	    , bConsumed(FALSE)
	    , tCreatedMs(0)
	    , nIp(0)
	    , nPort(0)
	{
		memset(fileHash, 0, sizeof(fileHash));
	}

	void Clear()
	{
		bArmed = FALSE;
		bConsumed = FALSE;
		tCreatedMs = 0;
		nIp = 0;
		nPort = 0;
		memset(fileHash, 0, sizeof(fileHash));
	}

	BOOL IsExpired(DWORD tNowMs, DWORD nTimeoutMs = Ed2kC2cCallbackPendingTimeoutMs()) const
	{
		if (!bArmed)
			return FALSE;
		return (tNowMs - tCreatedMs) >= nTimeoutMs;
	}

	// True when this exact callback was already consumed and is still within the window.
	BOOL IsDuplicate(DWORD tNowMs, DWORD nIpIn, WORD nPortIn, const BYTE* pFileHash16,
	                 DWORD nTimeoutMs = Ed2kC2cCallbackPendingTimeoutMs()) const
	{
		if (!bConsumed || !bArmed || !pFileHash16)
			return FALSE;
		if (IsExpired(tNowMs, nTimeoutMs))
			return FALSE;
		if (nIpIn != nIp || nPortIn != nPort)
			return FALSE;
		return memcmp(pFileHash16, fileHash, 16) == 0;
	}

	// Arm + consume in one step after validation (cannot be reused).
	BOOL TryConsumeOnce(DWORD tNowMs, DWORD nIpIn, WORD nPortIn, const BYTE* pFileHash16,
	                    DWORD nTimeoutMs = Ed2kC2cCallbackPendingTimeoutMs())
	{
		if (!pFileHash16)
			return FALSE;
		if (IsExpired(tNowMs, nTimeoutMs))
			Clear();
		if (IsDuplicate(tNowMs, nIpIn, nPortIn, pFileHash16, nTimeoutMs))
			return FALSE;

		bArmed = TRUE;
		bConsumed = TRUE;
		tCreatedMs = tNowMs;
		nIp = nIpIn;
		nPort = nPortIn;
		memcpy(fileHash, pFileHash16, 16);
		return TRUE;
	}

	void OnDisconnect()
	{
		Clear();
	}
};

// ---- Classic server callback (regression seam) ----

inline BOOL Ed2kServerCallbackRequestedPayloadOk(DWORD nRemaining)
{
	return nRemaining >= Ed2kServerCallbackRequestedExactBytes();
}

inline BOOL Ed2kServerCallbackRequestedParse(const BYTE* pData, DWORD nLen, DWORD* pnIp, WORD* pnPort)
{
	if (!pData || !pnIp || !pnPort || !Ed2kServerCallbackRequestedPayloadOk(nLen))
		return FALSE;

	*pnIp = (DWORD)pData[0] | ((DWORD)pData[1] << 8) | ((DWORD)pData[2] << 16) | ((DWORD)pData[3] << 24);
	*pnPort = (WORD)((DWORD)pData[4] | ((DWORD)pData[5] << 8));
	return TRUE;
}

// LowID identity: ClientID alone is insufficient — server endpoint must match (CEDClient::Equals).
inline BOOL Ed2kLowIdPeersEqual(DWORD nIdA, DWORD nServerIpA, DWORD nIdB, DWORD nServerIpB)
{
	if (!Ed2kIsLowIdValue(nIdA) || !Ed2kIsLowIdValue(nIdB))
		return FALSE;
	return nIdA == nIdB && nServerIpA == nServerIpB;
}

inline BOOL Ed2kLowIdSameIdDifferentServerCollide(DWORD nIdA, DWORD nServerIpA, DWORD nIdB, DWORD nServerIpB)
{
	if (!Ed2kIsLowIdValue(nIdA) || !Ed2kIsLowIdValue(nIdB))
		return FALSE;
	if (nIdA != nIdB)
		return FALSE;
	return nServerIpA != nServerIpB;
}

// Conceptual classic path: LowID Connect uses server push (not direct TCP).
inline BOOL Ed2kLowIdConnectUsesServerPush(DWORD nClientId)
{
	return Ed2kIsLowIdValue(nClientId);
}
