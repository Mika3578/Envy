//
// Kademlia.h
//
// Kad2 (Kademlia2) DHT implementation for eDonkey2000 network
// eMule-compatible Kademlia protocol implementation
//
// This file is part of Envy (getenvy.com) © 2016-2026
//
// Envy is free software. You may redistribute and/or modify it
// under the terms of the GNU Affero General Public License
// as published by the Free Software Foundation (fsf.org);
// version 3 or later at your option. (AGPLv3)
//

#pragma once

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <array>
#include <vector>
#include <list>
#include <map>
#include <unordered_map>
#include "KadRoutingTable.h"
#include "KadSearchResDelivery.h"
#include "KadFirewallCheck.h"

// Kad2 protocol constants
#define KAD2_UDP_PORT 4672               // Default Kad UDP port
#define KAD2_BOOTSTRAP_TIMEOUT 10000     // Bootstrap timeout in ms
#define KAD2_PING_TIMEOUT 5000           // Ping timeout in ms
#define KAD2_FIND_NODE_TIMEOUT 5000      // Find node timeout in ms
#define KAD2_REQUEST_TIMEOUT 30000       // Request timeout in ms (30 seconds)
#define KAD2_MAX_OUTSTANDING_REQUESTS 10 // Maximum outstanding requests
#define KADEMLIA_VERSION 8               // Kad protocol version (eMule compatible)

inline void KadContactGetSockAddr(const KadContact& contact, sockaddr_in& addr)
{
	memset(&addr, 0, sizeof(sockaddr_in));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(contact.ip);
	addr.sin_port = htons(contact.udpPort);
}

// Kad2 request tracking
enum KadRequestType {
    KAD_REQUEST_BOOTSTRAP = 0,
    KAD_REQUEST_FIND_NODE = 1,
    KAD_REQUEST_SEARCH_KEY = 2,
    KAD_REQUEST_SEARCH_SOURCE = 3,
    KAD_REQUEST_PUBLISH_KEY = 4,
	KAD_REQUEST_PUBLISH_SOURCE = 5,
	KAD_REQUEST_FIREWALL_CHECK = 6
};

// DHT stored entry (published keyword or source)
struct KadStoredEntry {
    KadId       sourceId;       // Publisher node ID
    DWORD       ip;             // Publisher IP
    WORD        tcpPort;        // Publisher TCP port
    WORD        udpPort;        // Publisher UDP port
    DWORD       lifetime;       // Expiry tick count
    std::vector<std::pair<BYTE, std::vector<BYTE>>> tags;   // Tag list (tagId, value)
};

// Hash functor for KadId in unordered_map
struct KadIdHash {
    size_t operator()(const std::array<unsigned char, KAD_ID_SIZE>& id) const {
        size_t h = 0;
        for (int i = 0; i < KAD_ID_SIZE; i++)
            h = h * 31 + id[i];
        return h;
    }
};

// DHT value storage: target hash -> list of entries
typedef std::array<unsigned char, KAD_ID_SIZE> KadIdKey;
typedef std::unordered_map<KadIdKey, std::vector<KadStoredEntry>, KadIdHash> KadStore;

#define KAD_STORE_MAX_ENTRIES_PER_KEY 50
#define KAD_STORE_ENTRY_LIFETIME (2 * 60 * 60 * 1000)  // 2 hours
#define KAD_STORE_MAX_TOTAL 5000

struct KadOutstandingRequest {
    KadRequestType type;
    DWORD sentTime;
    SOCKADDR_IN targetAddr;

    KadOutstandingRequest() : type(KAD_REQUEST_BOOTSTRAP), sentTime(0) {
        memset(&targetAddr, 0, sizeof(targetAddr));
    }

    KadOutstandingRequest(KadRequestType t, const SOCKADDR_IN& addr) :
        type(t), sentTime(GetTickCount()), targetAddr(addr) {}
};

// CKademlia Kad2 implementation class
class CKademlia {
public:
    CKademlia();
    ~CKademlia();

    // Initialize Kad2
    bool Init();

    // Shutdown Kad2
    void Stop();

    // Check if initialized
    bool IsInitialized() const { return m_bInitialized; }

    // Process incoming Kad2 packet
    BOOL OnPacket(const SOCKADDR_IN* pHost, class CEDPacket* pPacket);

    // Timer callback (~5 seconds)
    void OnTimer();

    // Bootstrap from host cache
    void Bootstrap();

    // Security and rate limiting
    bool CheckRateLimit(const SOCKADDR_IN* pHost, KadRequestType type);
    void CleanupRateLimitMap();

    // Send bootstrap request to specific contact
    void SendBootstrapRequest(const KadContact& contact);

    // Send find node request to specific contact (random target, or an explicit zone target)
    void SendFindNodeRequest(const KadContact& contact);
    void SendFindNodeRequest(const KadContact& contact, const KadId& targetId);

    // Send hello request to specific host
    void SendHelloRequest(const SOCKADDR_IN* pTarget);

    // Send hello response to specific host
    void SendHelloResponse(const SOCKADDR_IN* pTarget);

    // Mark contact as verified
    void MarkContactVerified(const KadId& id);

	// Kad TCP firewall-check ACK from ED2K C2C (0xA8). UDP state is separate.
	void OnTcpFirewallCheckAck(const SOCKADDR_IN* pHost);

	KadTcpFirewallState GetTcpFirewallState() const { return m_firewall.TcpState(); }
	KadUdpFirewallState GetUdpFirewallState() const { return m_firewall.UdpState(); }
	DWORD GetObservedPublicIp() const { return m_firewall.PublicIpHost(); }

	// Search for keyword results in DHT
	void SearchKeyword(const KadId& keywordHash);

	// Search for file sources in DHT
	void SearchSource(const KadId& fileHash);

	// Publish a keyword entry to DHT
	void PublishKeyword(const KadId& keywordHash, const KadStoredEntry& entry);

	// Publish a source entry to DHT
	void PublishSource(const KadId& fileHash, const KadStoredEntry& entry);

	// Get total stored DHT entries
	size_t GetStoredEntryCount() const;

	// Copy own Kad ID (16 bytes). Returns false when not initialized.
	bool GetOwnKadId(KadId& outId) const
	{
		if (!m_bInitialized)
			return false;
		memcpy(outId, m_ownId, KAD_ID_SIZE);
		return true;
	}

private:
    // Packet handlers
    void OnBootstrapRequest(const SOCKADDR_IN* pHost, CEDPacket* pPacket);
    void OnBootstrapResponse(const SOCKADDR_IN* pHost, CEDPacket* pPacket);
    void OnPing(const SOCKADDR_IN* pHost, CEDPacket* pPacket);
    void OnPong(const SOCKADDR_IN* pHost, CEDPacket* pPacket);
    void OnFindNodeRequest(const SOCKADDR_IN* pHost, CEDPacket* pPacket);
    void OnFindNodeResponse(const SOCKADDR_IN* pHost, CEDPacket* pPacket);
    void OnHelloRequest(const SOCKADDR_IN* pHost, CEDPacket* pPacket);
    void OnHelloResponse(const SOCKADDR_IN* pHost, CEDPacket* pPacket);

    // Search and publish handlers
    void OnSearchKeyRequest(const SOCKADDR_IN* pHost, CEDPacket* pPacket);
    void OnSearchSourceRequest(const SOCKADDR_IN* pHost, CEDPacket* pPacket);
    void OnSearchResponse(const SOCKADDR_IN* pHost, CEDPacket* pPacket);
    void OnPublishKeyRequest(const SOCKADDR_IN* pHost, CEDPacket* pPacket);
    void OnPublishSourceRequest(const SOCKADDR_IN* pHost, CEDPacket* pPacket);
    void OnPublishResponse(const SOCKADDR_IN* pHost, CEDPacket* pPacket);

    // Send search/publish packets to a contact
    void SendSearchKeyRequest(const KadContact& contact, const KadId& targetId);
    void SendSearchSourceRequest(const KadContact& contact, const KadId& targetId);
    void SendPublishKeyRequest(const KadContact& contact, const KadId& targetId, const KadStoredEntry& entry);
    void SendPublishSourceRequest(const KadContact& contact, const KadId& targetId, const KadStoredEntry& entry);

    // Store management
    bool StoreEntry(const KadIdKey& key, const KadStoredEntry& entry);
    void CleanupExpiredEntries();
    void WriteEntryTags(CEDPacket* pPacket, const KadStoredEntry& entry);
    bool ReadEntryTags(CEDPacket* pPacket, KadStoredEntry& entry);

    // Utility methods
    void SendPacket(const SOCKADDR_IN* pHost, CEDPacket* pPacket);
    bool UpdateContact(const KadContact& contact, KadContactSource source = KadContactSource::Candidate, bool markVerified = false);
    void GenerateOwnKadId();
    void LogKadStatus();

    // Request tracking methods
    DWORD AddOutstandingRequest(KadRequestType type, const SOCKADDR_IN& targetAddr);
    bool IsRequestOutstanding(DWORD requestId, KadRequestType expectedType, const SOCKADDR_IN& fromAddr);
    void RemoveOutstandingRequest(DWORD requestId);
    void CleanupExpiredRequests();

    // Member variables
    bool m_bInitialized;
    KadId m_ownId;
    Kad2RoutingTable m_routingTable;
    CCriticalSection m_pKadSection;
    DWORD m_lastBootstrapTime;
    DWORD m_lastTimerCall;

    // Request tracking
    std::map<DWORD, KadOutstandingRequest> m_outstandingRequests; // Key is request ID

    // Security and rate limiting
    std::map<DWORD, DWORD> m_rateLimitMap; // IP -> last request time
    DWORD m_lastRateLimitCleanup;

    // DHT value storage
    KadStore m_keywordStore;     // Keyword hash -> published keyword entries
    KadStore m_sourceStore;      // File hash -> published source entries
    DWORD m_lastStoreCleanup;

	// SEARCH_RES → ED2K source delivery (impl at EOF of Kademlia.cpp).
	void DeliverSourceCandidate(const BYTE* pFileHash, const KadSourceCandidate& cand);
	void ProcessSearchResponseDelivery(const SOCKADDR_IN* pHost, CEDPacket* pPacket);
	// Outstanding searches: target hash + kind + expiry; no CDownload*.
	KadOutstandingSearchMap m_outstandingSearches;

	// TCP firewall-detection baseline (UDP tester / Buddy / callback deferred).
	void OnFirewalledRequest(const SOCKADDR_IN* pHost, CEDPacket* pPacket, bool firewalled2);
	void OnFirewalledResponse(const SOCKADDR_IN* pHost, CEDPacket* pPacket);
	void OnFirewalledAck(const SOCKADDR_IN* pHost, CEDPacket* pPacket);
	void SendFirewalledResponse(const SOCKADDR_IN* pHost, DWORD observedIpHost);
	void SendFirewalledRequest(const KadContact& contact);
	void MaybeStartFirewallChecks();
	void CollectFirewallCheckCandidates(KadFwPeerCandidate* out, size_t outMax, size_t& outCount) const;
	KadFirewallCheck m_firewall;
	WORD m_lastFirewallTcpPort;
};

// Kademlia packet structures
#pragma pack(push, 1)

// PUBLISH request packet
typedef struct {
    unsigned char targetId[KAD_ID_SIZE];  // Target ID (file hash or keyword hash)
    unsigned char load;                   // Load factor (not used in basic impl)
} KadPublishRequest;

// PUBLISH response packet
typedef struct {
    unsigned char targetId[KAD_ID_SIZE];  // Target ID echoed back
    unsigned char load;                   // Load factor (0=success, 1=failed)
} KadPublishResponse;

#pragma pack(pop)

// Global Kademlia instance
extern CKademlia Kademlia;
