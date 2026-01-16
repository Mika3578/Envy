//
// Kademlia.cpp
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

#include "StdAfx.h"
#include "Kademlia.h"
#include "EDPacket.h"
#include "Datagrams.h"
#include "HostCache.h"
#include "Envy.h"
#include "GProfile.h"
#include "Settings.h"
#include <array>
#include <algorithm>

#ifdef _DEBUG
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#define new DEBUG_NEW
#endif	// Debug

// Global Kademlia instance
CKademlia Kademlia;

// Helper function to check if KadID is all zeros
static bool IsZeroId(const KadId& id) {
    for (int i = 0; i < KAD_ID_SIZE; i++) {
        if (id[i] != 0) return false;
    }
    return true;
}

// KadBucket implementation
bool KadBucket::AddContact(const KadContact& contact) {
    // Check if contact already exists
    for (auto it = contacts.begin(); it != contacts.end(); ++it) {
        if (memcmp(it->id, contact.id, KAD_ID_SIZE) == 0) {
            // Update existing contact
            *it = contact;
            it->lastSeen = GetTickCount();
            return true;
        }
    }

    // Add new contact if bucket not full
    if (contacts.size() < (size_t)KAD_K) {
        contacts.push_back(contact);
        return true;
    }

    return false; // Bucket full
}

bool KadBucket::RemoveContact(const KadId& id) {
    for (auto it = contacts.begin(); it != contacts.end(); ++it) {
        if (memcmp(it->id, id, KAD_ID_SIZE) == 0) {
            contacts.erase(it);
            return true;
        }
    }
    return false;
}

const KadContact* KadBucket::FindContact(const KadId& id) const {
    for (const auto& contact : contacts) {
        if (memcmp(contact.id, id, KAD_ID_SIZE) == 0) {
            return &contact;
        }
    }
    return nullptr;
}

// Kad2RoutingTable implementation
Kad2RoutingTable::Kad2RoutingTable() {
    memset(ownId, 0, KAD_ID_SIZE);
}

Kad2RoutingTable::~Kad2RoutingTable() {
    // Nothing to clean up
}

bool Kad2RoutingTable::Initialize(const KadId& nodeId) {
    memcpy(ownId, nodeId, KAD_ID_SIZE);
    return true;
}

bool Kad2RoutingTable::AddContact(const KadContact& contact) {
    // Don't add ourselves
    if (memcmp(contact.id, ownId, KAD_ID_SIZE) == 0) {
        return false;
    }

    // Calculate bucket index based on XOR distance
    unsigned char distance[KAD_ID_SIZE];
    for (int i = 0; i < KAD_ID_SIZE; i++) {
        distance[i] = ownId[i] ^ contact.id[i];
    }

    // Find the bucket (highest bit set in distance)
    int bucketIndex = 0;
    for (int i = 0; i < KAD_ID_BITS; i++) {
        if (distance[i / 8] & (0x80 >> (i % 8))) {
            bucketIndex = KAD_ID_BITS - 1 - i;
            break;
        }
    }

    if (bucketIndex >= KAD_BUCKET_COUNT) {
        bucketIndex = KAD_BUCKET_COUNT - 1;
    }

    return buckets[bucketIndex].AddContact(contact);
}

bool Kad2RoutingTable::RemoveContact(const KadId& id) {
    for (int i = 0; i < KAD_BUCKET_COUNT; i++) {
        if (buckets[i].RemoveContact(id)) {
            return true;
        }
    }
    return false;
}

const KadContact* Kad2RoutingTable::FindContact(const KadId& id) const {
    for (int i = 0; i < KAD_BUCKET_COUNT; i++) {
        const KadContact* contact = buckets[i].FindContact(id);
        if (contact) {
            return contact;
        }
    }
    return nullptr;
}

void Kad2RoutingTable::FindClosestContacts(const KadId& targetId, std::vector<KadContact>& results, int maxCount) {
    // Simple implementation: collect contacts from all buckets and sort by XOR distance
    std::vector<std::pair<std::array<unsigned char, KAD_ID_SIZE>, const KadContact*>> candidates;

    for (int i = 0; i < KAD_BUCKET_COUNT; i++) {
        for (const auto& contact : buckets[i].contacts) {
            std::array<unsigned char, KAD_ID_SIZE> distance;
            for (int j = 0; j < KAD_ID_SIZE; j++) {
                distance[j] = targetId[j] ^ contact.id[j];
            }
            candidates.push_back(std::make_pair(distance, &contact));
        }
    }

    // Sort by XOR distance (lexicographical comparison)
    std::sort(candidates.begin(), candidates.end(),
        [](const std::pair<std::array<unsigned char, KAD_ID_SIZE>, const KadContact*>& a,
           const std::pair<std::array<unsigned char, KAD_ID_SIZE>, const KadContact*>& b) {
            return memcmp(a.first.data(), b.first.data(), KAD_ID_SIZE) < 0;
        });

    // Take the closest contacts
    for (size_t i = 0; i < candidates.size() && results.size() < (size_t)maxCount; i++) {
        results.push_back(*candidates[i].second);
    }
}

size_t Kad2RoutingTable::GetTotalContacts() const {
    size_t total = 0;
    for (int i = 0; i < KAD_BUCKET_COUNT; i++) {
        total += buckets[i].GetContactCount();
    }
    return total;
}

void Kad2RoutingTable::GetContactsForBootstrap(std::vector<KadContact>& results, int maxCount) {
    for (int i = 0; i < KAD_BUCKET_COUNT; i++) {
        for (const auto& contact : buckets[i].contacts) {
            if (results.size() >= (size_t)maxCount) return;
            results.push_back(contact);
        }
    }
}

// CKademlia implementation
CKademlia::CKademlia() :
    m_bInitialized(false),
    m_lastBootstrapTime(0),
    m_lastTimerCall(0)
{
    memset(m_ownId, 0, KAD_ID_SIZE);
}

CKademlia::~CKademlia() {
    Stop();
}

bool CKademlia::Init() {
    if (m_bInitialized) return true;

    // Generate our own Kad ID (use MyProfile GUID as base for now)
    GenerateOwnKadId();

    // Initialize routing table
    if (!m_routingTable.Initialize(m_ownId)) {
        return false;
    }

    m_bInitialized = true;
    m_lastBootstrapTime = 0;
    m_lastTimerCall = GetTickCount();

    theApp.Message(MSG_NOTICE, L"Kad2 initialized with ID: %02x%02x%02x%02x...",
        m_ownId[0], m_ownId[1], m_ownId[2], m_ownId[3]);

    // Bootstrap immediately
    Bootstrap();

    return true;
}

void CKademlia::Stop() {
    if (!m_bInitialized) return;

    m_bInitialized = false;
    memset(m_ownId, 0, KAD_ID_SIZE);

    theApp.Message(MSG_NOTICE, L"Kad2 stopped");
}

void CKademlia::GenerateOwnKadId() {
    // Use MyProfile GUID as base for Kad ID
    Hashes::Guid oGUID = MyProfile.oGUID;
    memcpy(m_ownId, &oGUID[0], std::min(oGUID.byteCount, size_t(KAD_ID_SIZE)));

    // If GUID is shorter than 16 bytes, pad with zeros or random data
    if (oGUID.byteCount < KAD_ID_SIZE) {
        // Pad with some entropy
        srand(GetTickCount());
        for (size_t i = oGUID.byteCount; i < KAD_ID_SIZE; i++) {
            m_ownId[i] = (BYTE)(rand() & 0xFF);
        }
    }
}

void CKademlia::Bootstrap() {
    if (!m_bInitialized) return;

    DWORD now = GetTickCount();
    if (now - m_lastBootstrapTime < 30000) { // Don't bootstrap more than once every 30 seconds
        return;
    }

    m_lastBootstrapTime = now;

    // Get bootstrap contacts from host cache
    std::vector<KadContact> bootstrapContacts;
    int contactsFound = 0;

    // Import from host cache
    for (CHostCacheIterator it = HostCache.Kademlia.Begin(); it != HostCache.Kademlia.End() && contactsFound < 20; ++it) {
        CHostCacheHostPtr pHost = *it;
        if (pHost && pHost->m_pAddress.s_addr != INADDR_ANY) {
            KadContact contact;
            memcpy(contact.id, &pHost->m_oGUID, KAD_ID_SIZE);
            contact.ip = ntohl(pHost->m_pAddress.s_addr);  // Convert network order to host order
            contact.udpPort = pHost->m_nUDPPort ? pHost->m_nUDPPort : pHost->m_nPort;
            contact.tcpPort = pHost->m_nPort;
            contact.verified = FALSE;
            contact.version = pHost->m_nKADVersion;

            bootstrapContacts.push_back(contact);
            contactsFound++;
        }
    }

    if (bootstrapContacts.empty()) {
        theApp.Message(MSG_DEBUG, L"Kad2: No bootstrap contacts found in host cache");
        return;
    }

    theApp.Message(MSG_DEBUG, L"Kad2: Bootstrapping with %d contacts", bootstrapContacts.size());

    // Send bootstrap requests to first few contacts
    int bootstrapRequestsSent = 0;
    int findNodeRequestsSent = 0;

    for (const auto& contact : bootstrapContacts) {
        if (bootstrapRequestsSent < 5) { // Bootstrap with up to 5 nodes initially
            SendBootstrapRequest(contact);
            bootstrapRequestsSent++;
        }

        // Also send some find node requests to build routing table
        if (findNodeRequestsSent < 3) {
            SendFindNodeRequest(contact);
            findNodeRequestsSent++;
        }
    }
}

void CKademlia::SendBootstrapRequest(const KadContact& contact) {
    if (!m_bInitialized) return;

    // Create bootstrap request packet - empty body as per eMule spec
    CEDPacket* pPacket = CEDPacket::New(KADEMLIA2_BOOTSTRAP_REQ, ED2K_PROTOCOL_KAD);
    if (!pPacket) return;

    // BOOTSTRAP_REQ has empty body according to eMule spec

    // Send packet and track the request
    sockaddr_in addr;
    contact.GetSockAddr(addr);
    DWORD requestId = AddOutstandingRequest(KAD_REQUEST_BOOTSTRAP, addr);

    theApp.Message(MSG_DEBUG, L"Kad2: Sent bootstrap request to %s (ID: %u)",
        (LPCTSTR)CString(inet_ntoa(addr.sin_addr)), requestId);

    SendPacket(&addr, pPacket);
    pPacket->Release();
}

void CKademlia::SendFindNodeRequest(const KadContact& contact) {
    if (!m_bInitialized) return;

    // Create find node request: <Type(1)><TargetID(16)><ReceiverID(16)>
    CEDPacket* pPacket = CEDPacket::New(KADEMLIA2_REQ, ED2K_PROTOCOL_KAD);
    if (!pPacket) return;

    // Add search type (1 byte) - KADEMLIA_FIND_NODE for node search
    pPacket->WriteByte(KADEMLIA_FIND_NODE);

    // Add target ID (16 bytes) - use a random ID for now to discover nodes
    KadId targetId;
    for (int i = 0; i < KAD_ID_SIZE; i++) {
        targetId[i] = (BYTE)(rand() & 0xFF);
    }
    pPacket->Write(targetId, KAD_ID_SIZE);

    // Add receiver ID (16 bytes) - target node's ID
    pPacket->Write(contact.id, KAD_ID_SIZE);

    // Send packet and track the request
    sockaddr_in addr;
    contact.GetSockAddr(addr);
    DWORD requestId = AddOutstandingRequest(KAD_REQUEST_FIND_NODE, addr);

    theApp.Message(MSG_DEBUG, L"Kad2: Sent find node request to %s (ID: %u)",
        (LPCTSTR)CString(inet_ntoa(addr.sin_addr)), requestId);

    SendPacket(&addr, pPacket);
    pPacket->Release();
}

void CKademlia::OnTimer() {
    if (!m_bInitialized) return;

    DWORD now = GetTickCount();
    if (now - m_lastTimerCall < 5000) return; // Call at most every 5 seconds

    m_lastTimerCall = now;

    // Clean up expired requests
    CleanupExpiredRequests();

    // Periodic maintenance
    LogKadStatus();

    // Re-bootstrap if we have very few contacts
    if (m_routingTable.GetTotalContacts() < 5) {
        Bootstrap();
    }
}

BOOL CKademlia::OnPacket(const SOCKADDR_IN* pHost, CEDPacket* pPacket) {
    if (!m_bInitialized || !pHost || !pPacket) {
        return FALSE;
    }

    // Route packet based on opcode
    switch (pPacket->m_nType) {
    case KADEMLIA2_BOOTSTRAP_REQ:
        OnBootstrapRequest(pHost, pPacket);
        return TRUE;

    case KADEMLIA2_BOOTSTRAP_RES:
        OnBootstrapResponse(pHost, pPacket);
        return TRUE;

    case KADEMLIA2_PING:
        OnPing(pHost, pPacket);
        return TRUE;

    case KADEMLIA2_PONG:
        OnPong(pHost, pPacket);
        return TRUE;

    case KADEMLIA2_REQ:
        OnFindNodeRequest(pHost, pPacket);
        return TRUE;

    case KADEMLIA2_RES:
        OnFindNodeResponse(pHost, pPacket);
        return TRUE;

    default:
        theApp.Message(MSG_DEBUG, L"Kad2: Unknown opcode 0x%02x from %s",
            pPacket->m_nType, (LPCTSTR)CString(inet_ntoa(pHost->sin_addr)));
        return FALSE;
    }
}

void CKademlia::OnBootstrapRequest(const SOCKADDR_IN* pHost, CEDPacket* pPacket) {
    // BOOTSTRAP_REQ should have empty body, but we'll accept it anyway
    // and extract the sender info from the packet source

    theApp.Message(MSG_DEBUG, L"Kad2: Bootstrap request from %s",
        (LPCTSTR)CString(inet_ntoa(pHost->sin_addr)));

    // Create bootstrap response: <MyKadID(16)><TCPPort(2)><KadVersion(1)><Count(2)><contacts...>
    CEDPacket* pResponse = CEDPacket::New(KADEMLIA2_BOOTSTRAP_RES, ED2K_PROTOCOL_KAD);
    if (!pResponse) return;

    // Add our node ID (16 bytes)
    pResponse->Write(m_ownId, KAD_ID_SIZE);

    // Add our TCP port (2 bytes) - use UDP port as TCP port for now
    WORD tcpPort = Settings.Connection.InPort;
    if (tcpPort == 0) tcpPort = 4672; // Default Kad port
    pResponse->WriteShortLE(tcpPort);

    // Add Kad version (1 byte)
    BYTE kadVersion = 8; // eMule Kad version
    pResponse->WriteByte(kadVersion);

    // Get closest contacts (up to 10)
    KadId zeroId = {0}; // Use zero ID to get any contacts for bootstrap
    std::vector<KadContact> closestContacts;
    m_routingTable.FindClosestContacts(zeroId, closestContacts, 10);

    // Add contact count (2 bytes)
    WORD contactCount = (WORD)closestContacts.size();
    pResponse->WriteShortLE(contactCount);

    // Add contacts: each <ID(16)><IP(4)><UDP(2)><TCP(2)><Ver(1)>
    for (const auto& contact : closestContacts) {
        pResponse->Write(contact.id, KAD_ID_SIZE);        // Node ID (16)
        pResponse->WriteLongLE(contact.ip);  // Write IP in host order LE as per eMule format
        pResponse->WriteShortLE(contact.udpPort);         // UDP Port (2)
        pResponse->WriteShortLE(contact.tcpPort);         // TCP Port (2)
        pResponse->WriteByte(contact.version);            // Version (1)
    }

    // Send response
    SendPacket(pHost, pResponse);
    pResponse->Release();

    // Don't add requester to routing table - we don't have their ID from empty request
}

void CKademlia::OnBootstrapResponse(const SOCKADDR_IN* pHost, CEDPacket* pPacket) {
    // Check if this response matches an outstanding request
    if (!IsRequestOutstanding(0, KAD_REQUEST_BOOTSTRAP, *pHost)) {
        theApp.Message(MSG_DEBUG, L"Kad2: Ignoring unsolicited bootstrap response from %s",
            (LPCTSTR)CString(inet_ntoa(pHost->sin_addr)));
        return;
    }

    theApp.Message(MSG_DEBUG, L"Kad2: Bootstrap response from %s (accepted)",
        (LPCTSTR)CString(inet_ntoa(pHost->sin_addr)));

    // Minimum size check: MyKadID(16) + TCPPort(2) + KadVersion(1) + Count(2)
    if (pPacket->GetRemaining() < (KAD_ID_SIZE + 2 + 1 + 2)) {
        theApp.Message(MSG_DEBUG, L"Kad2: Bootstrap response too small");
        return;
    }

    // Read responder's node ID (16 bytes)
    if (pPacket->GetRemaining() < KAD_ID_SIZE) return;
    KadId responderId;
    pPacket->Read(responderId, KAD_ID_SIZE);

    // Read responder's TCP port (2 bytes)
    WORD responderTcpPort = pPacket->ReadShortLE();

    // Read Kad version (1 byte)
    BYTE responderKadVersion = pPacket->ReadByte();

    // Read contact count (2 bytes)
    WORD contactCount = pPacket->ReadShortLE();

    // Sanity check on contact count
    if (contactCount > 100) {
        theApp.Message(MSG_DEBUG, L"Kad2: Bootstrap response has too many contacts (%d)", contactCount);
        return;
    }

    // Read contacts: each <ID(16)><IP(4)><UDP(2)><TCP(2)><Ver(1)>
    int contactsAdded = 0;
    for (WORD i = 0; i < contactCount; i++) {
        if (pPacket->GetRemaining() < (KAD_ID_SIZE + 4 + 2 + 2 + 1)) break;

        KadContact contact;
        if (pPacket->GetRemaining() < KAD_ID_SIZE) break;
        pPacket->Read(contact.id, KAD_ID_SIZE);
        contact.ip = pPacket->ReadLongLE();  // eMule stores IP in host order LE in payload
        contact.udpPort = pPacket->ReadShortLE();
        contact.tcpPort = pPacket->ReadShortLE();
        contact.version = pPacket->ReadByte();
        contact.verified = FALSE;

        // Add to routing table
        if (UpdateContact(contact)) {
            contactsAdded++;
        }
    }

    theApp.Message(MSG_DEBUG, L"Kad2: Bootstrap response added %d contacts", contactsAdded);

    // Add responder to routing table
    KadContact responderContact(responderId, ntohl(pHost->sin_addr.s_addr),  // Convert to host order
                               ntohs(pHost->sin_port), responderTcpPort);
    responderContact.version = responderKadVersion;
    UpdateContact(responderContact);
}

void CKademlia::OnPing(const SOCKADDR_IN* pHost, CEDPacket* pPacket) {
    theApp.Message(MSG_DEBUG, L"Kad2: Ping from %s",
        (LPCTSTR)CString(inet_ntoa(pHost->sin_addr)));

    // Send pong response - eMule format: 2 bytes (UDP port observed)
    CEDPacket* pResponse = CEDPacket::New(KADEMLIA2_PONG, ED2K_PROTOCOL_KAD);
    if (!pResponse) return;

    // Add the observed UDP port (2 bytes) - eMule PONG contains the port the peer sees us on
    WORD observedPort = ntohs(pHost->sin_port);
    pResponse->WriteShortLE(observedPort);

    SendPacket(pHost, pResponse);
    pResponse->Release();
}

void CKademlia::OnPong(const SOCKADDR_IN* pHost, CEDPacket* pPacket) {
    // eMule PONG format: 2 bytes (observed UDP port) + optional tags
    if (pPacket->GetRemaining() < 2) {
        theApp.Message(MSG_DEBUG, L"Kad2: Pong too small from %s",
            (LPCTSTR)CString(inet_ntoa(pHost->sin_addr)));
        return;
    }

    // Read observed UDP port (2 bytes) - the port the responder thinks we have
    WORD observedPort = pPacket->ReadShortLE();

    theApp.Message(MSG_DEBUG, L"Kad2: Pong from %s (observed port: %d)",
        (LPCTSTR)CString(inet_ntoa(pHost->sin_addr)), observedPort);

    // Don't add contact - we don't have the responder's ID in PONG
}

void CKademlia::OnFindNodeRequest(const SOCKADDR_IN* pHost, CEDPacket* pPacket) {
    // KADEMLIA2_REQ format: <Type(1)><TargetID(16)><ReceiverID(16)>
    // Minimum size check
    if (pPacket->GetRemaining() < (1 + KAD_ID_SIZE + KAD_ID_SIZE)) {
        theApp.Message(MSG_DEBUG, L"Kad2: Find node request too small");
        return;
    }

    // Read search type (1 byte)
    BYTE searchType = pPacket->ReadByte();
    BYTE type = (searchType & 0x1F);
    if (type == 0 || type != KADEMLIA_FIND_NODE) {
        theApp.Message(MSG_DEBUG, L"Kad2: Find node request has unsupported search type %d", searchType);
        return;
    }

    // Read target ID (16 bytes) - this is the ID we're looking for
    if (pPacket->GetRemaining() < KAD_ID_SIZE) return;
    KadId targetId;
    pPacket->Read(targetId, KAD_ID_SIZE);

    // Read receiver ID (16 bytes) - this should be our own ID or a broadcast
    if (pPacket->GetRemaining() < KAD_ID_SIZE) return;
    KadId receiverId;
    pPacket->Read(receiverId, KAD_ID_SIZE);

    // eMule expects the receiver ID to match our own KadID
    if (memcmp(receiverId, m_ownId, KAD_ID_SIZE) != 0) {
        theApp.Message(MSG_DEBUG, L"Kad2: Find node request not for us (receiver mismatch) from %s",
            (LPCTSTR)CString(inet_ntoa(pHost->sin_addr)));
        return;
    }

    theApp.Message(MSG_DEBUG, L"Kad2: Find node request for target from %s",
        (LPCTSTR)CString(inet_ntoa(pHost->sin_addr)));

    // Create response: KADEMLIA2_RES format: <TargetID(16)><Count(1)><contacts...>
    CEDPacket* pResponse = CEDPacket::New(KADEMLIA2_RES, ED2K_PROTOCOL_KAD);
    if (!pResponse) return;

    // Add target ID (16 bytes)
    pResponse->Write(targetId, KAD_ID_SIZE);

    // Get closest contacts to target
    std::vector<KadContact> closestContacts;
    m_routingTable.FindClosestContacts(targetId, closestContacts, KAD_K);

    // Add contact count (1 byte)
    BYTE contactCount = (BYTE)min(closestContacts.size(), (size_t)255);
    pResponse->WriteByte(contactCount);

    // Add contacts: each <ID(16)><IP(4)><UDP(2)><TCP(2)><Ver(1)>
    for (size_t i = 0; i < contactCount; i++) {
        const auto& contact = closestContacts[i];
        pResponse->Write(contact.id, KAD_ID_SIZE);        // Node ID (16)
        pResponse->WriteLongLE(contact.ip);  // Write IP in host order LE as per eMule format
        pResponse->WriteShortLE(contact.udpPort);         // UDP Port (2)
        pResponse->WriteShortLE(contact.tcpPort);         // TCP Port (2)
        pResponse->WriteByte(contact.version);            // Version (1)
    }

    // Send response
    SendPacket(pHost, pResponse);
    pResponse->Release();

    // Don't add requester to routing table - we don't know their ID from this packet format
}

void CKademlia::OnFindNodeResponse(const SOCKADDR_IN* pHost, CEDPacket* pPacket) {
    // Check if this response matches an outstanding request
    if (!IsRequestOutstanding(0, KAD_REQUEST_FIND_NODE, *pHost)) {
        theApp.Message(MSG_DEBUG, L"Kad2: Ignoring unsolicited find node response from %s",
            (LPCTSTR)CString(inet_ntoa(pHost->sin_addr)));
        return;
    }

    // KADEMLIA2_RES format: <TargetID(16)><Count(1)><contacts...>
    // Minimum size check: TargetID(16) + Count(1)
    if (pPacket->GetRemaining() < (KAD_ID_SIZE + 1)) {
        theApp.Message(MSG_DEBUG, L"Kad2: Find node response too small");
        return;
    }

    // Read target ID (16 bytes)
    if (pPacket->GetRemaining() < KAD_ID_SIZE) return;
    KadId targetId;
    pPacket->Read(targetId, KAD_ID_SIZE);

    // Read contact count (1 byte)
    BYTE contactCount = pPacket->ReadByte();

    theApp.Message(MSG_DEBUG, L"Kad2: Find node response from %s with %d contacts (accepted)",
        (LPCTSTR)CString(inet_ntoa(pHost->sin_addr)), contactCount);

    // Read contacts: each <ID(16)><IP(4)><UDP(2)><TCP(2)><Ver(1)>
    int contactsAdded = 0;
    for (BYTE i = 0; i < contactCount; i++) {
        if (pPacket->GetRemaining() < (KAD_ID_SIZE + 4 + 2 + 2 + 1)) break;

        KadContact contact;
        if (pPacket->GetRemaining() < KAD_ID_SIZE) break;
        pPacket->Read(contact.id, KAD_ID_SIZE);
        contact.ip = pPacket->ReadLongLE();  // eMule stores IP in host order LE in payload
        contact.udpPort = pPacket->ReadShortLE();
        contact.tcpPort = pPacket->ReadShortLE();
        contact.version = pPacket->ReadByte();
        contact.verified = FALSE;

        // Add to routing table
        if (UpdateContact(contact)) {
            contactsAdded++;
        }
    }

    if (contactsAdded > 0) {
        theApp.Message(MSG_DEBUG, L"Kad2: Find node response added %d contacts", contactsAdded);
    }

    // Don't add responder to routing table - we don't know their ID from this packet format
}

void CKademlia::SendPacket(const SOCKADDR_IN* pHost, CEDPacket* pPacket) {
    if (!pHost || !pPacket) return;

    Datagrams.Send(pHost, pPacket, FALSE);
}

bool CKademlia::UpdateContact(const KadContact& contact) {
    // Don't add ourselves
    if (memcmp(contact.id, m_ownId, KAD_ID_SIZE) == 0) {
        return false;
    }

    // Don't add unknown/invalid node IDs (all-zero)
    if (IsZeroId(contact.id)) {
        return false;
    }

    // Don't add invalid IPs
    if (contact.ip == 0 || contact.ip == INADDR_NONE || contact.ip == INADDR_ANY) {
        return false;
    }

    // Don't add loopback/private IPs for Kad (unless in LAN mode)
    if (!Settings.Experimental.LAN_Mode) {
        if ((contact.ip & 0xFF000000) == 0x7F000000 ||  // 127.x.x.x
            (contact.ip & 0xFF000000) == 0x0A000000 ||  // 10.x.x.x
            (contact.ip & 0xFFF00000) == 0xAC100000 ||  // 172.16.x.x - 172.31.x.x
            (contact.ip & 0xFFFF0000) == 0xC0A80000) {  // 192.168.x.x
            return false;
        }
    }

    return m_routingTable.AddContact(contact);
}

void CKademlia::LogKadStatus() {
    size_t contactCount = m_routingTable.GetTotalContacts();
    theApp.Message(MSG_DEBUG, L"Kad2: Routing table has %d contacts", contactCount);
}

// Request tracking implementation
DWORD CKademlia::AddOutstandingRequest(KadRequestType type, const SOCKADDR_IN& targetAddr) {
    // Simple request ID generation - use a counter for now
    static DWORD nextRequestId = 1;
    DWORD requestId = nextRequestId++;

    // Clean up expired requests first
    CleanupExpiredRequests();

    // Don't allow too many outstanding requests
    if (m_outstandingRequests.size() >= KAD2_MAX_OUTSTANDING_REQUESTS) {
        // Remove oldest request
        auto oldest = m_outstandingRequests.begin();
        for (auto it = m_outstandingRequests.begin(); it != m_outstandingRequests.end(); ++it) {
            if (it->second.sentTime < oldest->second.sentTime) {
                oldest = it;
            }
        }
        m_outstandingRequests.erase(oldest);
    }

    m_outstandingRequests[requestId] = KadOutstandingRequest(type, targetAddr);
    return requestId;
}

bool CKademlia::IsRequestOutstanding(DWORD requestId, KadRequestType expectedType, const SOCKADDR_IN& fromAddr) {
    // For now, we accept any response from the same IP as valid
    // In a full implementation, we'd track specific request IDs

    auto it = m_outstandingRequests.begin();
    while (it != m_outstandingRequests.end()) {
        if (it->second.targetAddr.sin_addr.s_addr == fromAddr.sin_addr.s_addr &&
            it->second.targetAddr.sin_port == fromAddr.sin_port &&
            it->second.type == expectedType) {
            // Found matching request, remove it
            m_outstandingRequests.erase(it);
            return true;
        }
        ++it;
    }

    return false;
}

void CKademlia::RemoveOutstandingRequest(DWORD requestId) {
    m_outstandingRequests.erase(requestId);
}

void CKademlia::CleanupExpiredRequests() {
    DWORD now = GetTickCount();
    auto it = m_outstandingRequests.begin();

    while (it != m_outstandingRequests.end()) {
        if (now - it->second.sentTime > KAD2_REQUEST_TIMEOUT) {
            it = m_outstandingRequests.erase(it);
        } else {
            ++it;
        }
    }
}
