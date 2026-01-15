//
// Kademlia.h
//
// Kademlia DHT implementation for eDonkey2000 network
// Based on BitTorrent DHT reference implementation
//
// This file is part of Envy (getenvy.com) © 2016-2026
// Portions copyright Juliusz Chroboczek (BitTorrent DHT)
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
#include <time.h>

// Kademlia node ID is 128-bit (16 bytes) for eDonkey2000
#define KAD_ID_SIZE 16
typedef unsigned char KadId[KAD_ID_SIZE];

// Kademlia protocol constants
#define KAD_K 20                          // Bucket size (number of nodes per bucket)
#define KAD_REFRESH_INTERVAL (15 * 60)    // Bucket refresh interval (15 minutes)
#define KAD_REPUBLISH_INTERVAL (60 * 60)  // Value republish interval (1 hour)

// Maximum number of concurrent searches
#define KAD_MAX_SEARCHES 1024

// Global own node ID (defined in KBucket.cpp)
extern KadId g_own_id;

// Kademlia event types
#define KAD_EVENT_NONE 0
#define KAD_EVENT_VALUES 1
#define KAD_EVENT_SEARCH_DONE 2
#define KAD_EVENT_ADDED 3
#define KAD_EVENT_SENT 4
#define KAD_EVENT_REPLY 5
#define KAD_EVENT_REMOVED 6
#define KAD_EVENT_PUBLISH_DONE 7

// Kademlia callback function
typedef void (*kad_callback)(void *closure, int event,
                           const unsigned char *target_id,
                           const void *data, size_t data_len);

// Core Kademlia functions
int kad_init(int socket_fd, const unsigned char *node_id);
int kad_uninit(void);

int kad_insert_node(const unsigned char *node_id, const struct sockaddr *addr, int addr_len);
int kad_ping_node(const struct sockaddr *addr, int addr_len);

int kad_periodic(const unsigned char *buf, size_t buflen,
                 const struct sockaddr *from, int fromlen,
                 time_t *tosleep, kad_callback *callback, void *closure);

int kad_search(const unsigned char *target_id, int port,
               kad_callback *callback, void *closure);

int kad_nodes(int *good_return, int *dubious_return, int *cached_return,
              int *incoming_return);

int kad_get_nodes(struct sockaddr_in *nodes, unsigned char *node_ids, int *num);

// Key-value operations
int kad_store(const unsigned char *key, const char *value);
int kad_publish(const unsigned char *key, const char *value);
int kad_find_value(const unsigned char *key, kad_callback *callback, void *closure);

// Bootstrap functions
int kad_bootstrap_from_host_cache(void);

// Debug functions
void kad_dump_tables(void);
void kad_debug_print(void);

// User-provided functions (must be implemented)
int kad_blacklisted(const struct sockaddr *addr, int addr_len);
void kad_hash(void *hash_return, int hash_size,
             const void *v1, int len1,
             const void *v2, int len2,
             const void *v3, int len3);
int kad_random_bytes(void *buf, size_t size);
int kad_sendto(int socket_fd, const void *buf, int len, int flags,
              const struct sockaddr *to, int tolen);

// Utility functions
unsigned char *kad_create_node_id(void);
int kad_id_compare(const unsigned char *id1, const unsigned char *id2);
void kad_xor_distance(unsigned char *distance, const unsigned char *id1, const unsigned char *id2);

// CKademlia wrapper class for OOP interface
class CKademlia {
public:
    CKademlia() : m_bInitialized(false), m_socketFd(-1) {}
    ~CKademlia() { Uninit(); }

    // Initialize Kademlia with socket and node ID
    bool Init(int socketFd, const unsigned char* nodeId) {
        if (m_bInitialized) return false;
        m_socketFd = socketFd;
        m_bInitialized = (kad_init(socketFd, nodeId) == 0);
        return m_bInitialized;
    }

    // Uninitialize
    void Uninit() {
        if (m_bInitialized) {
            kad_uninit();
            m_bInitialized = false;
        }
    }

    // Bootstrap from an address
    void Bootstrap(const struct sockaddr_in* pHost) {
        if (pHost) {
            kad_ping_node((const struct sockaddr*)pHost, sizeof(struct sockaddr_in));
        }
    }

    // Check if initialized
    bool IsInitialized() const { return m_bInitialized; }

    // Process incoming packet
    BOOL OnPacket(const SOCKADDR_IN* pHost, class CEDPacket* pPacket) {
        // TODO: Implement Kademlia packet processing
        (void)pHost;
        (void)pPacket;
        return FALSE;
    }

private:
    bool m_bInitialized;
    int m_socketFd;
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
