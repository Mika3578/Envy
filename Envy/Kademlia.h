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
#include <vector>
#include <list>
#include <map>

// Kademlia node ID is 128-bit (16 bytes) for eDonkey2000
#define KAD_ID_SIZE 16
typedef unsigned char KadId[KAD_ID_SIZE];

// Kademlia routing table constants
#define KAD_K 10                         // Bucket size (number of nodes per bucket) - eMule uses 10
#define KAD_ID_BITS 128                  // ID size in bits
#define KAD_BUCKET_COUNT (KAD_ID_BITS)   // Number of buckets
#define KAD_MAX_CONTACTS 500             // Maximum contacts in routing table

// Kad2 protocol constants
#define KAD2_UDP_PORT 4672               // Default Kad UDP port
#define KAD2_BOOTSTRAP_TIMEOUT 10000     // Bootstrap timeout in ms
#define KAD2_PING_TIMEOUT 5000           // Ping timeout in ms
#define KAD2_FIND_NODE_TIMEOUT 5000      // Find node timeout in ms
#define KAD2_REQUEST_TIMEOUT 30000       // Request timeout in ms (30 seconds)
#define KAD2_MAX_OUTSTANDING_REQUESTS 10 // Maximum outstanding requests

// Kad2 node contact information
#pragma pack(push, 1)
struct KadContact {
    KadId id;                    // Node ID (16 bytes)
    DWORD ip;                    // IPv4 address
    WORD udpPort;                // UDP port
    WORD tcpPort;                // TCP port (usually same as UDP)
    DWORD lastSeen;              // Last contact time (tick count)
    BYTE version;                // Kad version
    BOOL verified;               // Contact verified via ping/pong

    KadContact() {
        memset(this, 0, sizeof(KadContact));
    }

    KadContact(const KadId& nodeId, DWORD nodeIp, WORD nodeUdpPort, WORD nodeTcpPort = 0) {
        memcpy(id, nodeId, KAD_ID_SIZE);
        ip = nodeIp;
        udpPort = nodeUdpPort;
        tcpPort = nodeTcpPort ? nodeTcpPort : nodeUdpPort;
        lastSeen = GetTickCount();
        version = 0;
        verified = FALSE;
    }

    // Get sockaddr_in for network operations
    void GetSockAddr(sockaddr_in& addr) const {
        memset(&addr, 0, sizeof(sockaddr_in));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(ip);  // Convert host order to network order
        addr.sin_port = htons(udpPort);
    }
};
#pragma pack(pop)

// Kad2 request tracking
enum KadRequestType {
    KAD_REQUEST_BOOTSTRAP = 0,
    KAD_REQUEST_FIND_NODE = 1,
    KAD_REQUEST_PING = 2,
    KAD_REQUEST_PUBLISH = 3
};

struct KadOutstandingRequest {
    KadRequestType type;
    DWORD sentTime;
    SOCKADDR_IN targetAddr;
    int retryCount;  // Number of retries attempted
    DWORD timeout;   // Timeout in milliseconds (specific to request type)

    KadOutstandingRequest() : type(KAD_REQUEST_BOOTSTRAP), sentTime(0), retryCount(0), timeout(KAD2_BOOTSTRAP_TIMEOUT) {
        memset(&targetAddr, 0, sizeof(targetAddr));
    }

    KadOutstandingRequest(KadRequestType t, const SOCKADDR_IN& addr) :
        type(t), sentTime(GetTickCount()), targetAddr(addr), retryCount(0) {
        // Set timeout based on request type (per eMule standard)
        switch (t) {
            case KAD_REQUEST_BOOTSTRAP:
                timeout = KAD2_BOOTSTRAP_TIMEOUT;  // 10s
                break;
            case KAD_REQUEST_PING:
                timeout = KAD2_PING_TIMEOUT;       // 5s
                break;
            case KAD_REQUEST_FIND_NODE:
                timeout = KAD2_FIND_NODE_TIMEOUT;  // 5s
                break;
            case KAD_REQUEST_PUBLISH:
                timeout = 10000;                    // 10s for publish
                break;
            default:
                timeout = KAD2_REQUEST_TIMEOUT;    // 30s default
                break;
        }
    }
    
    // Check if request has timed out
    bool IsExpired() const {
        return (GetTickCount() - sentTime) > timeout;
    }
    
    // Check if we should retry (max 3 retries per eMule standard)
    bool ShouldRetry() const {
        return retryCount < 3 && IsExpired();
    }
};

// Kad2 routing table bucket
class KadBucket {
public:
    std::list<KadContact> contacts;
    DWORD lastRefresh;

    KadBucket() : lastRefresh(0) {}

    bool AddContact(const KadContact& contact);
    bool RemoveContact(const KadId& id);
    const KadContact* FindContact(const KadId& id) const;
    size_t GetContactCount() const { return contacts.size(); }
    bool IsFull() const { return contacts.size() >= KAD_K; }
};

// Kad2 routing table (eMule-compatible)
class Kad2RoutingTable {
public:
    KadBucket buckets[KAD_BUCKET_COUNT];
    KadId ownId;

    Kad2RoutingTable();
    ~Kad2RoutingTable();

    bool Initialize(const KadId& nodeId);
    bool AddContact(const KadContact& contact);
    bool RemoveContact(const KadId& id);
    const KadContact* FindContact(const KadId& id) const;
    void FindClosestContacts(const KadId& targetId, std::vector<KadContact>& results, int maxCount = KAD_K);
    size_t GetTotalContacts() const;
    void GetContactsForBootstrap(std::vector<KadContact>& results, int maxCount = 20);
    size_t GetContactCount() const { return buckets[0].GetContactCount(); } // For compatibility
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

    // Send bootstrap request to specific contact
    void SendBootstrapRequest(const KadContact& contact);

    // Send find node request to specific contact
    void SendFindNodeRequest(const KadContact& contact);

private:
    // Packet handlers
    void OnBootstrapRequest(const SOCKADDR_IN* pHost, CEDPacket* pPacket);
    void OnBootstrapResponse(const SOCKADDR_IN* pHost, CEDPacket* pPacket);
    void OnPing(const SOCKADDR_IN* pHost, CEDPacket* pPacket);
    void OnPong(const SOCKADDR_IN* pHost, CEDPacket* pPacket);
    void OnFindNodeRequest(const SOCKADDR_IN* pHost, CEDPacket* pPacket);
    void OnFindNodeResponse(const SOCKADDR_IN* pHost, CEDPacket* pPacket);

    // Utility methods
    void SendPacket(const SOCKADDR_IN* pHost, CEDPacket* pPacket);
    bool UpdateContact(const KadContact& contact);
    void GenerateOwnKadId();
    void LogKadStatus();
    void RefreshBuckets();  // Periodic bucket refresh (eMule standard: 15 minutes)

    // Request tracking methods
    DWORD AddOutstandingRequest(KadRequestType type, const SOCKADDR_IN& targetAddr);
    bool IsRequestOutstanding(DWORD requestId, KadRequestType expectedType, const SOCKADDR_IN& fromAddr);
    void RemoveOutstandingRequest(DWORD requestId);
    void CleanupExpiredRequests();

    // Member variables
    bool m_bInitialized;
    KadId m_ownId;
    Kad2RoutingTable m_routingTable;
    DWORD m_lastBootstrapTime;
    DWORD m_lastTimerCall;

    // Request tracking
    std::map<DWORD, KadOutstandingRequest> m_outstandingRequests; // Key is request ID
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
