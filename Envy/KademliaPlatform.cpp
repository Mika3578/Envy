//
// KademliaPlatform.cpp
//
// Platform-specific functions for Kademlia DHT
// Windows/Visual Studio implementation
//
// This file is part of Envy (getenvy.com) © 2016-2026
//
// Envy is free software. You may redistribute and/or modify it
// under the terms of the GNU Affero General Public License
// as published by the Free Software Foundation (fsf.org);
// version 3 or later at your option. (AGPLv3)
//

#include "StdAfx.h"
#include "Kademlia.h"
#include "Security.h"
#include "Network.h"
#include "../HashLib/SHA.h"

#ifdef _DEBUG
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#define new DEBUG_NEW
#endif	// Debug

// Check if an IP address is blacklisted
int kad_blacklisted(const struct sockaddr *addr, int addr_len)
{
    if (!addr || addr->sa_family != AF_INET) {
        return 1; // Blacklist unknown address families
    }

    const struct sockaddr_in *addr_in = (const struct sockaddr_in *)addr;
    const IN_ADDR *ip_addr = &addr_in->sin_addr;

    // Use Envy's security system to check if IP is blocked
    if (Security.IsDenied(ip_addr)) {
        return 1; // Blacklisted
    }

    // Check if it's a firewalled address
    if (Network.IsFirewalledAddress(ip_addr, FALSE)) {
        return 1; // Don't communicate with firewalled addresses
    }

    // Check if it's a reserved/private address that we shouldn't contact
    if (Network.IsReserved(ip_addr)) {
        return 1; // Reserved addresses
    }

    return 0; // Not blacklisted
}

// Hash function - uses SHA-1 for cryptographic security (eMule-compatible)
void kad_hash(void *hash_return, int hash_size,
             const void *v1, int len1,
             const void *v2, int len2,
             const void *v3, int len3)
{
    // Use SHA-1 for Kademlia hashing (compatible with eMule)
    // SHA-1 provides cryptographic security against collision and preimage attacks
    
    CSHA sha1;
    
    // Add all input data to the hash
    if (v1 && len1 > 0) {
        sha1.Add(v1, len1);
    }
    if (v2 && len2 > 0) {
        sha1.Add(v2, len2);
    }
    if (v3 && len3 > 0) {
        sha1.Add(v3, len3);
    }
    
    // Finalize the hash computation
    sha1.Finish();
    
    // Get the SHA-1 hash (20 bytes)
    unsigned char sha1_result[20];
    sha1.GetHash(sha1_result);
    
    // Copy the requested number of bytes to output buffer
    // Zero out the buffer first, then copy what we need
    memset(hash_return, 0, hash_size);
    int copy_size = (hash_size < 20) ? hash_size : 20;
    memcpy(hash_return, sha1_result, copy_size);
}

// Generate random bytes
int kad_random_bytes(void *buf, size_t size)
{
    if (!buf || size == 0) {
        return -1;
    }

    // Use Windows CryptGenRandom for cryptographic randomness
    // Priority: Use theApp.m_hCryptProv if available, otherwise create temporary context
    if (theApp.m_hCryptProv != 0) {
        // Use existing crypto provider from the application
        if (CryptGenRandom(theApp.m_hCryptProv, (DWORD)size, (BYTE *)buf)) {
            return 0; // Success
        }
        // Fall through to try creating a temporary context
    }

    // Try to create a temporary cryptographic context
    HCRYPTPROV hProvider = 0;
    if (!CryptAcquireContext(&hProvider, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        // CRITICAL: Cryptographic RNG failed - this is a security-critical operation
        // DO NOT fallback to insecure rand() - return error instead
        ASSERT(FALSE); // Alert in debug builds
        return -1; // Failure - caller must handle this
    }

    BOOL success = CryptGenRandom(hProvider, (DWORD)size, (BYTE *)buf);
    CryptReleaseContext(hProvider, 0);

    return success ? 0 : -1;
}

// Send UDP packet
int kad_sendto(int socket_fd, const void *buf, int len, int flags,
              const struct sockaddr *to, int tolen)
{
    if (socket_fd < 0 || !buf || !to) {
        return -1;
    }

    // Use Windows sendto
    int result = sendto(socket_fd, (const char *)buf, len, flags, to, tolen);

    if (result == SOCKET_ERROR) {
        int error = WSAGetLastError();
        TRACE("kad_sendto failed: %d\n", error);
        return -1;
    }

    return result;
}