//
// Kademlia.cpp
//
// Kademlia DHT implementation for eDonkey2000 network
//
// This file is part of Envy (getenvy.com) © 2016-2026
// Portions copyright Juliusz Chroboczek (BitTorrent DHT)
//
// Envy is free software. You may redistribute and/or modify it
// under the terms of the GNU Affero General Public License
// as published by the Free Software Foundation (fsf.org);
// version 3 or later at your option. (AGPLv3)
//

#include "StdAfx.h"
#include "Kademlia.h"
#include "KBucket.h"
#include "KadProtocol.h"
#include "KadStorage.h"
#include "HostCache.h"
#include "Network.h"
#include "Security.h"

#ifdef _DEBUG
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#define new DEBUG_NEW
#endif	// Debug

// Kademlia network parameters
#define KAD_K 8              // Bucket size (K)
#define KAD_ALPHA 3          // Parallelism factor (alpha)
#define KAD_ID_BITS 128      // ID size in bits (16 bytes)
#define KAD_BUCKET_SIZE 8    // Nodes per bucket

// Timeouts and intervals (in seconds)
#define KAD_RESPONCE_TIMEOUT 10
#define KAD_REFRESH_INTERVAL 3600  // 1 hour
#define KAD_REPLICATE_INTERVAL 3600
#define KAD_REPUBLISH_INTERVAL 86400  // 24 hours

// Global Kademlia wrapper instance
CKademlia Kademlia;

// Global Kademlia state
static int g_kad_socket = -1;
static bool g_initialized = false;

// Global instances (forward declared in headers)
KadStorage* g_kadStorage = NULL;

// Forward declarations
static int kad_bootstrap_from_host_cache_internal(void);

// Initialize Kademlia DHT
int kad_init(int socket_fd, const unsigned char *node_id)
{
    if (g_initialized) {
        return -1; // Already initialized
    }

    if (!node_id) {
        return -1; // Invalid node ID
    }

    g_kad_socket = socket_fd;
    memcpy(g_own_id, node_id, KAD_ID_SIZE);
    g_initialized = true;

    // Initialize routing table
    g_routingTable = new KadRoutingTable(g_own_id);

    // Initialize protocol handler
    g_kadProtocol = new KadProtocol();
    if (!g_kadProtocol->Initialize(socket_fd)) {
        delete g_routingTable;
        g_routingTable = NULL;
        g_initialized = false;
        return -1;
    }

    // Initialize storage system
    g_kadStorage = new KadStorage();

    // Bootstrap from host cache
    kad_bootstrap_from_host_cache_internal();

    return 0;
}

// Uninitialize Kademlia DHT
int kad_uninit(void)
{
    if (!g_initialized) {
        return -1;
    }

    g_kad_socket = -1;
    memset(g_own_id, 0, KAD_ID_SIZE);
    g_initialized = false;

    // TODO: Clean up routing table

    return 0;
}

// Insert a node into the routing table
int kad_insert_node(const unsigned char *node_id, const struct sockaddr *addr, int addr_len)
{
    if (!g_initialized || !node_id || !addr) {
        return -1;
    }

    // Convert sockaddr to sockaddr_in for routing table
    if (addr->sa_family != AF_INET) {
        return -1; // Only IPv4 supported for now
    }

    const struct sockaddr_in* addr_in = (const struct sockaddr_in*)addr;

    // Check if IP is blacklisted
    if (kad_blacklisted(addr, addr_len)) {
        return -1;
    }

    // Insert into routing table
    if (g_routingTable && g_routingTable->AddNode(node_id, *addr_in)) {
        return 0;
    }

    return -1;
}

// Ping a node to check if it's alive
int kad_ping_node(const struct sockaddr *addr, int addr_len)
{
    if (!g_initialized || !addr || !g_kadProtocol) {
        return -1;
    }

    if (addr->sa_family != AF_INET) {
        return -1; // Only IPv4 for now
    }

    const struct sockaddr_in* addr_in = (const struct sockaddr_in*)addr;

    // Generate a random target ID for the ping
    unsigned char targetId[KAD_ID_SIZE];
    if (kad_random_bytes(targetId, KAD_ID_SIZE) != 0) {
        // Fallback: use our own ID
        memcpy(targetId, g_own_id, KAD_ID_SIZE);
    }

    // Send hello (ping) request
    if (g_kadProtocol->SendHelloRequest(targetId, *addr_in)) {
        return 0;
    }

    return -1;
}

// Main periodic function - called regularly to maintain DHT
int kad_periodic(const unsigned char *buf, size_t buflen,
                 const struct sockaddr *from, int fromlen,
                 time_t *tosleep, kad_callback *callback, void *closure)
{
    if (!g_initialized) {
        return -1;
    }

    time_t now = time(NULL);

    // Process incoming packets if provided
    if (buf && buflen > 0 && from) {
        // Process the packet through protocol handler
        // Note: This is a simplified version. In a real implementation,
        // packets would be received asynchronously.
    }

    // Try to receive any pending packets
    if (g_kadProtocol) {
        g_kadProtocol->ReceivePacket();
    }

    // TODO: Implement periodic maintenance:
    // - Refresh buckets that need it
    // - Ping nodes that haven't been contacted recently
    // - Expire old/unresponsive nodes
    // - Handle search timeouts

    if (g_routingTable) {
        // Check for buckets that need refreshing
        auto bucketsToRefresh = g_routingTable->GetBucketsToRefresh(now);

        // TODO: Send find_node requests to refresh buckets

        // Check for nodes that need pinging
        auto nodesToPing = g_routingTable->GetNodesToPing(now);

        // TODO: Send ping requests to stale nodes
    }

    if (tosleep) {
        *tosleep = 1; // Call again in 1 second
    }

    return 0;
}

// Start a search for a target ID
int kad_search(const unsigned char *target_id, int port,
               kad_callback *callback, void *closure)
{
    if (!g_initialized || !target_id || !g_routingTable || !g_kadProtocol) {
        return -1;
    }

    // Find closest nodes to target
    auto closestNodes = g_routingTable->FindClosestNodes(target_id, KAD_ALPHA);

    if (closestNodes.empty()) {
        // No nodes to search, bootstrap first
        kad_bootstrap_from_host_cache_internal();
        return -1;
    }

    // Send FIND_NODE requests to closest nodes
    int requestsSent = 0;
    for (auto node : closestNodes) {
        if (requestsSent >= KAD_ALPHA) break;

        // Send FIND_NODE request
        if (g_kadProtocol->SendFindNodeRequest(target_id, node->addr)) {
            requestsSent++;
        }
    }

    return requestsSent > 0 ? 0 : -1;
}

// Get statistics about known nodes
int kad_nodes(int *good_return, int *dubious_return, int *cached_return,
              int *incoming_return)
{
    if (!g_initialized) {
        return -1;
    }

    if (g_routingTable) {
        int totalNodes, totalBuckets;
        g_routingTable->GetStats(totalNodes, totalBuckets);

        if (good_return) *good_return = totalNodes;  // For now, count all as good
        if (dubious_return) *dubious_return = 0;     // TODO: Track dubious nodes
        if (cached_return) *cached_return = 0;      // TODO: Track cached nodes
        if (incoming_return) *incoming_return = 0;  // TODO: Track incoming requests
    } else {
        if (good_return) *good_return = 0;
        if (dubious_return) *dubious_return = 0;
        if (cached_return) *cached_return = 0;
        if (incoming_return) *incoming_return = 0;
    }

    return 0;
}

// Get list of known good nodes
int kad_get_nodes(struct sockaddr_in *nodes, unsigned char *node_ids, int *num)
{
    if (!g_initialized || !num || !nodes || !node_ids) {
        return -1;
    }

    if (!g_routingTable) {
        *num = 0;
        return 0;
    }

    // Get nodes from all buckets (up to requested number)
    int count = 0;
    KadId zeroId = {0}; // Use zero ID as target to get arbitrary nodes

    auto closestNodes = g_routingTable->FindClosestNodes(zeroId, *num);

    for (auto node : closestNodes) {
        if (count >= *num) break;

        // Copy node address
        nodes[count] = node->addr;

        // Copy node ID
        memcpy(&node_ids[count * KAD_ID_SIZE], node->id, KAD_ID_SIZE);

        count++;
    }

    *num = count;
    return 0;
}

// Bootstrap from Envy's host cache
int kad_bootstrap_from_host_cache(void)
{
    return kad_bootstrap_from_host_cache_internal();
}

static int kad_bootstrap_from_host_cache_internal(void)
{
    if (!g_initialized) {
        return -1;
    }

    int node_count = 0;

    // First, try nodes from host cache
    for (CHostCacheIterator it = HostCache.Kademlia.Begin(); it != HostCache.Kademlia.End() && node_count < 10; ++it) {
        // Bootstrap with up to 10 nodes from cache
        CHostCacheHostPtr pHost = *it;
        if (pHost && pHost->m_pAddress.s_addr != INADDR_ANY) {
            // Create sockaddr structure
            struct sockaddr_in addr;
            memset(&addr, 0, sizeof(addr));
            addr.sin_family = AF_INET;
            addr.sin_addr = pHost->m_pAddress;
            addr.sin_port = htons(pHost->m_nUDPPort ? pHost->m_nUDPPort : pHost->m_nPort);

            // Insert node into routing table
            kad_insert_node((const unsigned char*)&pHost->m_oGUID[0], (struct sockaddr*)&addr, sizeof(addr));

            // Send initial ping to establish connection
            kad_ping_node((const struct sockaddr*)&addr, sizeof(addr));

            node_count++;
        }
    }

    // If we don't have enough nodes, try well-known bootstrap nodes
    if (node_count < 5) {
        // Well-known eMule bootstrap nodes (example IPs - should be configurable)
        static const struct {
            const char* ip;
            unsigned short port;
        } bootstrap_nodes[] = {
            {"176.103.48.36", 4672},    // Example bootstrap node
            {"5.206.185.60", 4672},     // Example bootstrap node
            // Add more well-known nodes as needed
        };

        for (size_t i = 0; i < sizeof(bootstrap_nodes)/sizeof(bootstrap_nodes[0]) && node_count < 10; i++) {
            struct sockaddr_in addr;
            memset(&addr, 0, sizeof(addr));
            addr.sin_family = AF_INET;
            addr.sin_port = htons(bootstrap_nodes[i].port);

            // Resolve IP address
            if (inet_pton(AF_INET, bootstrap_nodes[i].ip, &addr.sin_addr) == 1) {
                // Generate a dummy node ID for bootstrap (real nodes will respond with their actual ID)
                KadId dummyId;
                kad_random_bytes(dummyId, KAD_ID_SIZE);

                // Insert and ping
                kad_insert_node(dummyId, (struct sockaddr*)&addr, sizeof(addr));
                kad_ping_node((const struct sockaddr*)&addr, sizeof(addr));

                node_count++;
            }
        }
    }

    return node_count;
}

// Debug functions
void kad_dump_tables(void)
{
    if (!g_initialized) {
        return;
    }

    // TODO: Dump routing table contents for debugging
    TRACE("Kademlia routing table dump:\n");
    // Print bucket contents, node counts, etc.
}

void kad_debug_print(void)
{
    if (!g_initialized) {
        return;
    }

    // TODO: Print debug information
    TRACE("Kademlia status: Initialized\n");
}

// Utility functions

// Create a random node ID
unsigned char *kad_create_node_id(void)
{
    static unsigned char node_id[KAD_ID_SIZE];

    // Generate random 128-bit ID
    if (kad_random_bytes(node_id, KAD_ID_SIZE) != 0) {
        // Fallback: use some entropy from system
        srand((unsigned int)time(NULL));
        for (int i = 0; i < KAD_ID_SIZE; i++) {
            node_id[i] = (unsigned char)(rand() & 0xFF);
        }
    }

    return node_id;
}

// Compare two node IDs (-1, 0, 1)
int kad_id_compare(const unsigned char *id1, const unsigned char *id2)
{
    return memcmp(id1, id2, KAD_ID_SIZE);
}

// Calculate XOR distance between two IDs
void kad_xor_distance(unsigned char *distance, const unsigned char *id1, const unsigned char *id2)
{
    for (int i = 0; i < KAD_ID_SIZE; i++) {
        distance[i] = id1[i] ^ id2[i];
    }
}

// Store a key-value pair in the DHT
int kad_store(const unsigned char *key, const char *value)
{
    if (!g_initialized || !key || !value || !g_kadStorage) {
        return -1;
    }

    // Store locally
    std::string valueStr(value);
    if (g_kadStorage->Store(key, valueStr)) {
        // TODO: Also replicate to other nodes responsible for this key
        return 0;
    }

    return -1;
}

// Publish a keyword/file association to the DHT
int kad_publish(const unsigned char *key, const char *value)
{
    if (!g_initialized || !key || !value || !g_routingTable) {
        return -1;
    }

    // Find the KadProtocol instance and publish
    // In a full implementation, this would be handled by the protocol layer
    // For now, just store locally and return success

    return kad_store(key, value);
}

// Find a value by key in the DHT
int kad_find_value(const unsigned char *key, kad_callback *callback, void *closure)
{
    if (!g_initialized || !key) {
        return -1;
    }

    // First check local storage
    if (g_kadStorage) {
        auto localResults = g_kadStorage->Find(key);
        if (!localResults.empty()) {
            // Return local results via callback
            if (callback) {
                // Convert results to callback format
                std::string combinedResult;
                for (const auto& result : localResults) {
                    if (!combinedResult.empty()) combinedResult += ";";
                    combinedResult += result;
                }

                (*callback)(closure, KAD_EVENT_VALUES, key,
                        (const void*)combinedResult.c_str(), combinedResult.length());
                (*callback)(closure, KAD_EVENT_SEARCH_DONE, key, NULL, 0);
            }
            return 0;
        }
    }

    // If not found locally, search the network
    // For now, just perform a node search
    return kad_search(key, 0, callback, closure);
}
