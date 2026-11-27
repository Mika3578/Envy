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
#include "KadHello.h"
#include "EDPacket.h"
#include "Datagrams.h"
#include "HostCache.h"
#include "Envy.h"
#include "GProfile.h"
#include "Settings.h"
#include "PacketLengthValidate.h"
#include "Downloads.h"
#include "Download.h"
#include "Transfers.h"
#include "Hashes.hpp"
#include "KadFirewallCheck.h"
#include "KadSearchSourceRequest.h"
#include "Security.h"
#include "Network.h"
#include "Ed2kHelloWire.h"
#include <array>
#include <algorithm>
#include <vector>

#ifdef _DEBUG
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#define new DEBUG_NEW
#endif // Debug

// Global Kademlia instance
CKademlia Kademlia;

// Helper function to check if KadID is all zeros
static bool IsZeroId(const KadId& id)
{
	return KadIdIsZero(id);
}

static uint64_t KadNowMs()
{
	return GetTickCount64();
}

// CKademlia implementation
CKademlia::CKademlia()
    : m_bInitialized(false)
    , m_lastBootstrapTime(0)
    , m_lastTimerCall(0)
    , m_lastRateLimitCleanup(0)
    , m_lastStoreCleanup(0)
    , m_lastFirewallTcpPort(0)
{
	memset(m_ownId, 0, KAD_ID_SIZE);
}

CKademlia::~CKademlia()
{
	Stop();
}

bool CKademlia::Init()
{
	CSingleLock oLock(&m_pKadSection, TRUE);
	if (m_bInitialized) return true;

	// Generate our own Kad ID (use MyProfile GUID as base for now)
	GenerateOwnKadId();

	// Initialize routing table
	if (!m_routingTable.Initialize(m_ownId))
	{
		return false;
	}

	m_bInitialized = true;
	m_lastBootstrapTime = 0;
	m_lastTimerCall = GetTickCount();
	m_lastFirewallTcpPort = (WORD)Settings.Connection.InPort;
	m_firewall.OnKadStart(m_lastTimerCall, m_lastFirewallTcpPort);
	m_udpFirewall.OnKadStart(m_lastTimerCall);

	theApp.Message(MSG_NOTICE, L"Kad2 initialized with ID: %02x%02x%02x%02x...",
	               m_ownId[0], m_ownId[1], m_ownId[2], m_ownId[3]);
	theApp.Message(MSG_DEBUG, L"Kad2: TCP and UDP firewall checks started (state unknown)");

	oLock.Unlock();
	Bootstrap();

	return true;
}

void CKademlia::Stop()
{
	CSingleLock oLock(&m_pKadSection, TRUE);
	if (!m_bInitialized) return;

	m_bInitialized = false;
	memset(m_ownId, 0, KAD_ID_SIZE);
	m_firewall.OnKadStop();
	m_udpFirewall.OnKadStop();
	m_buddy.Reset();
	m_hasPendingBuddyConnect = false;
	m_pendingBuddyConnect = KadBuddyRecord{};
	m_pendingCallbackRelays.clear();
	m_lastFirewallTcpPort = 0;

	theApp.Message(MSG_NOTICE, L"Kad2 stopped");
}

void CKademlia::GenerateOwnKadId()
{
	// Use MyProfile GUID as base for Kad ID
	Hashes::Guid oGUID = MyProfile.oGUID;
	memcpy(m_ownId, &oGUID[0], std::min(oGUID.byteCount, size_t(KAD_ID_SIZE)));

	// If GUID is shorter than 16 bytes, pad with cryptographically secure random data
	if (oGUID.byteCount < KAD_ID_SIZE)
	{
		// Fill remaining bytes with secure random data (P0.2 security requirement)
		size_t remainingBytes = KAD_ID_SIZE - oGUID.byteCount;
		if (!GenerateCryptographicBytes(&m_ownId[oGUID.byteCount], remainingBytes))
		{
			// Critical security failure - cannot generate secure Kad ID
			theApp.Message(MSG_ERROR, L"Kademlia: Failed to generate secure random bytes for Kad ID");
			// Set remaining bytes to zero as fallback (not secure but better than rand())
			memset(&m_ownId[oGUID.byteCount], 0, remainingBytes);
		}
	}
}

void CKademlia::Bootstrap()
{
	if (!m_bInitialized) return;

	DWORD now = GetTickCount();
	if (now - m_lastBootstrapTime < 30000)
	{ // Don't bootstrap more than once every 30 seconds
		return;
	}

	m_lastBootstrapTime = now;

	// Get bootstrap contacts from host cache
	std::vector<KadContact> bootstrapContacts;
	int contactsFound = 0;

	// Import from host cache
	for (CHostCacheIterator it = HostCache.Kademlia.Begin(); it != HostCache.Kademlia.End() && contactsFound < 20; ++it)
	{
		CHostCacheHostPtr pHost = *it;
		if (pHost && pHost->m_pAddress.s_addr != INADDR_ANY)
		{
			KadContact contact;
			memcpy(contact.id, &pHost->m_oGUID, KAD_ID_SIZE);
			contact.ip = ntohl(pHost->m_pAddress.s_addr); // Convert network order to host order
			contact.udpPort = pHost->m_nUDPPort ? pHost->m_nUDPPort : pHost->m_nPort;
			contact.tcpPort = pHost->m_nPort;
			contact.verified = FALSE;
			contact.version = pHost->m_nKADVersion;

			bootstrapContacts.push_back(contact);
			contactsFound++;
		}
	}

	if (bootstrapContacts.empty())
	{
		theApp.Message(MSG_DEBUG, L"Kad2: No bootstrap contacts found in host cache");
		return;
	}

	theApp.Message(MSG_DEBUG, L"Kad2: Bootstrapping with %d contacts", bootstrapContacts.size());

	// Send bootstrap requests to first few contacts
	int bootstrapRequestsSent = 0;
	int findNodeRequestsSent = 0;

	for (const auto& contact : bootstrapContacts)
	{
		if (bootstrapRequestsSent < 5)
		{ // Bootstrap with up to 5 nodes initially
			SendBootstrapRequest(contact);
			bootstrapRequestsSent++;
		}

		// Also send some find node requests to build routing table
		if (findNodeRequestsSent < 3)
		{
			SendFindNodeRequest(contact);
			findNodeRequestsSent++;
		}
	}
}

void CKademlia::SendBootstrapRequest(const KadContact& contact)
{
	if (!m_bInitialized) return;

	// Create bootstrap request packet - empty body as per eMule spec
	CEDPacket* pPacket = CEDPacket::New(KADEMLIA2_BOOTSTRAP_REQ, ED2K_PROTOCOL_KAD);
	if (!pPacket) return;

	// BOOTSTRAP_REQ has empty body according to eMule spec

	// Send packet and track the request
	sockaddr_in addr;
	KadContactGetSockAddr(contact, addr);
	DWORD requestId = AddOutstandingRequest(KAD_REQUEST_BOOTSTRAP, addr);

	theApp.Message(MSG_DEBUG, L"Kad2: Sent bootstrap request to %s (ID: %u)",
	               (LPCTSTR)CString(inet_ntoa(addr.sin_addr)), requestId);

	SendPacket(&addr, pPacket);
	pPacket->Release();
}

void CKademlia::SendFindNodeRequest(const KadContact& contact)
{
	KadId targetId;
	if (!GenerateCryptographicBytes(targetId, KAD_ID_SIZE))
	{
		theApp.Message(MSG_ERROR, L"Kademlia: Failed to generate secure random bytes for target ID");
		memset(targetId, 0, KAD_ID_SIZE);
	}
	SendFindNodeRequest(contact, targetId);
}

void CKademlia::SendFindNodeRequest(const KadContact& contact, const KadId& targetId)
{
	if (!m_bInitialized) return;

	CEDPacket* pPacket = CEDPacket::New(KADEMLIA2_REQ, ED2K_PROTOCOL_KAD);
	if (!pPacket) return;

	pPacket->WriteByte(KADEMLIA_FIND_NODE);
	pPacket->Write(targetId, KAD_ID_SIZE);
	pPacket->Write(contact.id, KAD_ID_SIZE);

	sockaddr_in addr;
	KadContactGetSockAddr(contact, addr);
	DWORD requestId = AddOutstandingRequest(KAD_REQUEST_FIND_NODE, addr, targetId);

	theApp.Message(MSG_DEBUG, L"Kad2: Sent find node request to %s (ID: %u)",
	               (LPCTSTR)CString(inet_ntoa(addr.sin_addr)), requestId);

	SendPacket(&addr, pPacket);
	pPacket->Release();
}

void CKademlia::OnTimer()
{
	if (!m_bInitialized) return;

	CSingleLock oLock(&m_pKadSection, TRUE);
	DWORD now = GetTickCount();
	if (now - m_lastTimerCall < 5000) return; // Call at most every 5 seconds

	m_lastTimerCall = now;

	CleanupExpiredRequests();


	const WORD tcpPort = (WORD)Settings.Connection.InPort;
	if (tcpPort != m_lastFirewallTcpPort)
	{
		m_lastFirewallTcpPort = tcpPort;
		m_firewall.OnNetworkOrPortChange(now, tcpPort);
		// A different listen port invalidates every UDP probe result,
		// including a verified one.
		m_udpFirewall.OnKadStart(now);
		theApp.Message(MSG_DEBUG, L"Kad2: TCP firewall-check reset after port change");
	}

	const KadTcpFirewallState fwBefore = m_firewall.TcpState();
	if (m_firewall.OnTimer(now) && m_firewall.TcpState() != fwBefore)
	{
		theApp.Message(MSG_DEBUG, L"Kad2: TCP firewall state -> %u (acks=%u publicIP=0x%08x)",
		               (unsigned)m_firewall.TcpState(), m_firewall.AckCount(), m_firewall.PublicIpHost());
		// A TCP verdict re-runs the UDP tester (eMule RecheckFirewalled).
		m_udpFirewall.ReCheck(now, false);
	}

	const KadUdpFirewallState udpBefore = m_udpFirewall.State();
	m_udpFirewall.OnTimer(now, m_firewall.TcpState() == KadTcpFirewallState::Firewalled);
	if (m_udpFirewall.State() != udpBefore)
	{
		theApp.Message(MSG_DEBUG, L"Kad2: UDP firewall state -> %u (verified=%u used=%u)",
		               (unsigned)m_udpFirewall.State(), m_udpFirewall.IsVerified() ? 1u : 0u,
		               m_udpFirewall.UsedCount());
	}
	MaybeStartFirewallChecks();
	MaybeStartBuddySearch();

	LogHelloStatus();
	LogKadStatus();

	if (now - m_lastStoreCleanup > 5 * 60 * 1000)
	{
		CleanupExpiredEntries();
		m_lastStoreCleanup = now;
	}

	KadId entropy{};
	if (!GenerateCryptographicBytes(entropy, KAD_ID_SIZE))
		memset(entropy, 0, KAD_ID_SIZE);

	KadMaintenanceAction action;
	m_routingTable.CollectMaintenance(KadNowMs(), entropy, action);

	const bool needBootstrap = m_routingTable.GetTotalContacts() < 5;
	KadContact pingContact = action.pingContact;
	KadContact refreshPeer = action.refreshPeer;
	KadId refreshTarget;
	KadIdCopy(refreshTarget, action.refreshTarget);
	const bool doPing = action.ping;
	const bool doRefresh = action.refresh;
	oLock.Unlock();

	if (doPing)
	{
		sockaddr_in addr;
		KadContactGetSockAddr(pingContact, addr);
		SendHelloRequest(&addr);
	}
	if (doRefresh)
		SendFindNodeRequest(refreshPeer, refreshTarget);

	if (needBootstrap)
		Bootstrap();
}

BOOL CKademlia::OnPacket(const SOCKADDR_IN* pHost, CEDPacket* pPacket)
{
	if (!m_bInitialized || !pHost || !pPacket)
	{
		return FALSE;
	}

	CSingleLock oLock(&m_pKadSection, TRUE);

	// Route packet based on opcode
	switch (pPacket->m_nType)
	{
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

	case KADEMLIA2_HELLO_REQ:
		OnHelloRequest(pHost, pPacket);
		return TRUE;

	case KADEMLIA2_HELLO_RES:
		OnHelloResponse(pHost, pPacket);
		return TRUE;

	case KADEMLIA2_SEARCH_KEY_REQ:
		OnSearchKeyRequest(pHost, pPacket);
		return TRUE;

	case KADEMLIA2_SEARCH_SOURCE_REQ:
		OnSearchSourceRequest(pHost, pPacket);
		return TRUE;

	case KADEMLIA2_SEARCH_RES:
		OnSearchResponse(pHost, pPacket);
		return TRUE;

	case KADEMLIA2_PUBLISH_KEY_REQ:
		OnPublishKeyRequest(pHost, pPacket);
		return TRUE;

	case KADEMLIA2_PUBLISH_SOURCE_REQ:
		OnPublishSourceRequest(pHost, pPacket);
		return TRUE;

	case KADEMLIA2_PUBLISH_RES:
		OnPublishResponse(pHost, pPacket);
		return TRUE;

	case KADEMLIA2_FIREWALLED_REQ:
		OnFirewalledRequest(pHost, pPacket, false);
		return TRUE;

	case KADEMLIA_FIREWALLED2_REQ:
		OnFirewalledRequest(pHost, pPacket, true);
		return TRUE;

	case KADEMLIA2_FIREWALLED_RES:
		OnFirewalledResponse(pHost, pPacket);
		return TRUE;

	case KADEMLIA2_FIREWALLED_ACK_RES:
		OnFirewalledAck(pHost, pPacket);
		return TRUE;

	case KADEMLIA2_FIREWALLUDP:
		OnFirewallUdpResult(pHost, pPacket);
		return TRUE;

	case KADEMLIA_FINDBUDDY_REQ:
		OnFindBuddyRequest(pHost, pPacket);
		return TRUE;

	case KADEMLIA_FINDBUDDY_RES:
		OnFindBuddyResponse(pHost, pPacket);
		return TRUE;

	case KADEMLIA_CALLBACK_REQ:
		OnCallbackRequest(pHost, pPacket);
		return TRUE;

	default:
		theApp.Message(MSG_DEBUG, L"Kad2: Unknown opcode 0x%02x from %s",
		               pPacket->m_nType, (LPCTSTR)CString(inet_ntoa(pHost->sin_addr)));
		return FALSE;
	}
}

void CKademlia::OnBootstrapRequest(const SOCKADDR_IN* pHost, CEDPacket* pPacket)
{
	// BOOTSTRAP_REQ should have empty body, but we'll accept it anyway
	// and extract the sender info from the packet source

	theApp.Message(MSG_DEBUG, L"Kad2: Bootstrap request from %s",
	               (LPCTSTR)CString(inet_ntoa(pHost->sin_addr)));

	// A 2-byte request draws a reply of up to a few hundred bytes from an address
	// that UDP lets anyone forge; eMule and aMule answer two per minute per IP.
	if (!m_inboundLimiter.Allow(ntohl(pHost->sin_addr.s_addr), KADEMLIA2_BOOTSTRAP_REQ, 2, KadNowMs()))
		return;

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
	KadId zeroId = { 0 }; // Use zero ID to get any contacts for bootstrap
	std::vector<KadContact> closestContacts;
	m_routingTable.FindClosestContacts(zeroId, closestContacts, 10);

	// Add contact count (2 bytes)
	WORD contactCount = (WORD)closestContacts.size();
	pResponse->WriteShortLE(contactCount);

	// Add contacts: each <ID(16)><IP(4)><UDP(2)><TCP(2)><Ver(1)>
	for (const auto& contact : closestContacts)
	{
		pResponse->Write(contact.id, KAD_ID_SIZE); // Node ID (16)
		pResponse->WriteLongLE(contact.ip);        // Write IP in host order LE as per eMule format
		pResponse->WriteShortLE(contact.udpPort);  // UDP Port (2)
		pResponse->WriteShortLE(contact.tcpPort);  // TCP Port (2)
		pResponse->WriteByte(contact.version);     // Version (1)
	}

	// Send response
	SendPacket(pHost, pResponse);
	pResponse->Release();

	// Don't add requester to routing table - we don't have their ID from empty request
}

void CKademlia::OnBootstrapResponse(const SOCKADDR_IN* pHost, CEDPacket* pPacket)
{
	// Check if this response matches an outstanding request
	if (!IsRequestOutstanding(0, KAD_REQUEST_BOOTSTRAP, *pHost))
	{
		theApp.Message(MSG_DEBUG, L"Kad2: Ignoring unsolicited bootstrap response from %s",
		               (LPCTSTR)CString(inet_ntoa(pHost->sin_addr)));
		return;
	}

	theApp.Message(MSG_DEBUG, L"Kad2: Bootstrap response from %s (accepted)",
	               (LPCTSTR)CString(inet_ntoa(pHost->sin_addr)));

	// Minimum size check: MyKadID(16) + TCPPort(2) + KadVersion(1) + Count(2)
	if (pPacket->GetRemaining() < (KAD_ID_SIZE + 2 + 1 + 2))
	{
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
	if (contactCount > 100)
	{
		theApp.Message(MSG_DEBUG, L"Kad2: Bootstrap response has too many contacts (%d)", contactCount);
		return;
	}

	// Read contacts: each <ID(16)><IP(4)><UDP(2)><TCP(2)><Ver(1)>
	int contactsAdded = 0;
	for (WORD i = 0; i < contactCount; i++)
	{
		if (pPacket->GetRemaining() < (KAD_ID_SIZE + 4 + 2 + 2 + 1)) break;

		KadContact contact;
		if (pPacket->GetRemaining() < KAD_ID_SIZE) break;
		pPacket->Read(contact.id, KAD_ID_SIZE);
		contact.ip = pPacket->ReadLongLE(); // eMule stores IP in host order LE in payload
		contact.udpPort = pPacket->ReadShortLE();
		contact.tcpPort = pPacket->ReadShortLE();
		contact.version = pPacket->ReadByte();
		contact.verified = false;

		if (UpdateContact(contact, KadContactSource::Candidate, false))
		{
			contactsAdded++;
		}
	}

	theApp.Message(MSG_DEBUG, L"Kad2: Bootstrap response added %d contacts", contactsAdded);

	// Add responder to routing table
	KadContact responderContact(responderId, ntohl(pHost->sin_addr.s_addr), // Convert to host order
	                            ntohs(pHost->sin_port), responderTcpPort);
	responderContact.version = responderKadVersion;
	UpdateContact(responderContact, KadContactSource::Observed, false);
}

void CKademlia::OnPing(const SOCKADDR_IN* pHost, CEDPacket* pPacket)
{
	theApp.Message(MSG_DEBUG, L"Kad2: Ping from %s",
	               (LPCTSTR)CString(inet_ntoa(pHost->sin_addr)));

	// A 2-byte PING draws a 4-byte PONG to a forgeable address; eMule and aMule allow two per minute per IP.
	if (!m_inboundLimiter.Allow(ntohl(pHost->sin_addr.s_addr), KADEMLIA2_PING, 2, KadNowMs()))
		return;

	// Send pong response - eMule format: 2 bytes (UDP port observed)
	CEDPacket* pResponse = CEDPacket::New(KADEMLIA2_PONG, ED2K_PROTOCOL_KAD);
	if (!pResponse) return;

	// Add the observed UDP port (2 bytes) - eMule PONG contains the port the peer sees us on
	WORD observedPort = ntohs(pHost->sin_port);
	pResponse->WriteShortLE(observedPort);

	SendPacket(pHost, pResponse);
	pResponse->Release();
}

void CKademlia::OnPong(const SOCKADDR_IN* pHost, CEDPacket* pPacket)
{
	// eMule PONG format: 2 bytes (observed UDP port) + optional tags
	if (pPacket->GetRemaining() < 2)
	{
		theApp.Message(MSG_DEBUG, L"Kad2: Pong too small from %s",
		               (LPCTSTR)CString(inet_ntoa(pHost->sin_addr)));
		return;
	}

	// Read observed UDP port (2 bytes) - the port the responder thinks we have
	WORD observedPort = pPacket->ReadShortLE();

	theApp.Message(MSG_DEBUG, L"Kad2: Pong from %s (observed port: %d)",
	               (LPCTSTR)CString(inet_ntoa(pHost->sin_addr)), observedPort);

	// PONG has no Kad ID; refresh LRU only if this endpoint is already a contact.
	m_routingTable.ObserveAliveByEndpoint(ntohl(pHost->sin_addr.s_addr), ntohs(pHost->sin_port), KadNowMs());
}

void CKademlia::OnFindNodeRequest(const SOCKADDR_IN* pHost, CEDPacket* pPacket)
{
	if (!pHost || !pPacket)
	{
		theApp.Message(MSG_ERROR, L"Kad2: Invalid parameters in find node request");
		return;
	}

	// KADEMLIA2_REQ format: <Type(1)><TargetID(16)><ReceiverID(16)>
	// Minimum size check
	if (pPacket->GetRemaining() < (1 + KAD_ID_SIZE + KAD_ID_SIZE))
	{
		theApp.Message(MSG_DEBUG, L"Kad2: Find node request too small from %s",
		               (LPCTSTR)CString(inet_ntoa(pHost->sin_addr)));
		return;
	}

	try
	{
		// Read search type (1 byte)
		BYTE searchType = pPacket->ReadByte();
		BYTE type = (searchType & 0x1F);

		// Security: Only allow known search types to prevent protocol abuse
		if (type == 0 || (type != KADEMLIA_FIND_NODE && type != KADEMLIA_FIND_VALUE))
		{
			theApp.Message(MSG_WARNING, L"Kad2: Rejected find node request with unknown search type %d from %s",
			               searchType, (LPCTSTR)CString(inet_ntoa(pHost->sin_addr)));
			// Don't respond to prevent amplification attacks
			return;
		}

		// Security: Rate limiting check
		if (!CheckRateLimit(pHost, KAD_REQUEST_FIND_NODE))
		{
			theApp.Message(MSG_WARNING, L"Kad2: Rate limit exceeded for find node request from %s",
			               (LPCTSTR)CString(inet_ntoa(pHost->sin_addr)));
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
		if (memcmp(receiverId, m_ownId, KAD_ID_SIZE) != 0)
		{
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
		for (size_t i = 0; i < contactCount; i++)
		{
			const auto& contact = closestContacts[i];
			pResponse->Write(contact.id, KAD_ID_SIZE); // Node ID (16)
			pResponse->WriteLongLE(contact.ip);        // Write IP in host order LE as per eMule format
			pResponse->WriteShortLE(contact.udpPort);  // UDP Port (2)
			pResponse->WriteShortLE(contact.tcpPort);  // TCP Port (2)
			pResponse->WriteByte(contact.version);     // Version (1)
		}

		// Send response
		SendPacket(pHost, pResponse);
		pResponse->Release();

		// Don't add requester to routing table - we don't know their ID from this packet format
	}
	catch (...)
	{
		// Handle any exceptions during packet processing
		theApp.Message(MSG_WARNING, L"Kad2: Exception during find node request processing from %s",
		               (LPCTSTR)CString(inet_ntoa(pHost->sin_addr)));
	}
}

void CKademlia::OnFindNodeResponse(const SOCKADDR_IN* pHost, CEDPacket* pPacket)
{
	// KADEMLIA2_RES format: <TargetID(16)><Count(1)><contacts...>
	if (pPacket->GetRemaining() < (KAD_ID_SIZE + 1))
	{
		theApp.Message(MSG_DEBUG, L"Kad2: Find node response too small");
		return;
	}

	KadId targetId;
	pPacket->Read(targetId, KAD_ID_SIZE);
	BYTE contactCount = pPacket->ReadByte();

	const size_t recordSize = KAD_ID_SIZE + 4 + 2 + 2 + 1;
	if (pPacket->GetRemaining() < contactCount * recordSize)
	{
		theApp.Message(MSG_DEBUG, L"Kad2: Find node response truncated from %s",
		               (LPCTSTR)CString(inet_ntoa(pHost->sin_addr)));
		return;
	}

	if (!IsRequestOutstanding(0, KAD_REQUEST_FIND_NODE, *pHost, targetId))
	{
		theApp.Message(MSG_DEBUG, L"Kad2: Ignoring unsolicited find node response from %s",
		               (LPCTSTR)CString(inet_ntoa(pHost->sin_addr)));
		return;
	}

	theApp.Message(MSG_DEBUG, L"Kad2: Find node response from %s with %d contacts (accepted)",
	               (LPCTSTR)CString(inet_ntoa(pHost->sin_addr)), contactCount);

	// Read contacts: each <ID(16)><IP(4)><UDP(2)><TCP(2)><Ver(1)>
	int contactsAdded = 0;
	for (BYTE i = 0; i < contactCount; i++)
	{
		if (pPacket->GetRemaining() < (KAD_ID_SIZE + 4 + 2 + 2 + 1)) break;

		KadContact contact;
		if (pPacket->GetRemaining() < KAD_ID_SIZE) break;
		pPacket->Read(contact.id, KAD_ID_SIZE);
		contact.ip = pPacket->ReadLongLE(); // eMule stores IP in host order LE in payload
		contact.udpPort = pPacket->ReadShortLE();
		contact.tcpPort = pPacket->ReadShortLE();
		contact.version = pPacket->ReadByte();
		contact.verified = false;

		if (UpdateContact(contact, KadContactSource::Candidate, false))
		{
			contactsAdded++;
		}
	}

	if (contactsAdded > 0)
	{
		theApp.Message(MSG_DEBUG, L"Kad2: Find node response added %d contacts", contactsAdded);
	}

	// Valid, fully parsed outstanding FIND_NODE_RES proves endpoint liveness (not verified).
	m_routingTable.ObserveAliveByEndpoint(ntohl(pHost->sin_addr.s_addr), ntohs(pHost->sin_port), KadNowMs());
}

// True only when the datagram layer accepted the packet and the socket reported the whole
// datagram sent (construction of the packet is the caller's, and its failure never reaches here).
bool CKademlia::SendPacket(const SOCKADDR_IN* pHost, CEDPacket* pPacket)
{
	if (!pHost || !pPacket) return false;

	BOOL bSocketSent = FALSE;
	return Datagrams.Send(pHost, pPacket, FALSE, NULL, TRUE, &bSocketSent) != FALSE && bSocketSent != FALSE;
}

bool CKademlia::UpdateContact(const KadContact& contact, KadContactSource source, bool markVerified)
{
	if (memcmp(contact.id, m_ownId, KAD_ID_SIZE) == 0)
	{
		return false;
	}

	if (IsZeroId(contact.id))
	{
		return false;
	}

	if (contact.ip == 0 || contact.ip == INADDR_NONE || contact.ip == INADDR_ANY)
	{
		return false;
	}

	if (contact.udpPort == 0)
	{
		return false;
	}

	IN_ADDR addr;
	addr.s_addr = htonl(contact.ip);
	if (Security.IsDenied(&addr))
	{
		return false;
	}

	const bool allowLan = Settings.Experimental.LAN_Mode != FALSE;
	if (!allowLan)
	{
		if ((contact.ip & 0xFF000000) == 0x7F000000 || // 127.x.x.x
		    (contact.ip & 0xFF000000) == 0x0A000000 || // 10.x.x.x
		    (contact.ip & 0xFFF00000) == 0xAC100000 || // 172.16.x.x - 172.31.x.x
		    (contact.ip & 0xFFFF0000) == 0xC0A80000)
		{ // 192.168.x.x
			return false;
		}
	}

	KadContactUpdate upd;
	upd.source = source;
	upd.markVerified = markVerified;
	upd.markAlive = (source == KadContactSource::Observed);
	upd.nowMs = KadNowMs();
	upd.allowLan = allowLan;

	CSingleLock oLock(&m_pKadSection, TRUE);
	return m_routingTable.AddContact(contact, upd);
}

void CKademlia::MarkContactVerified(const KadId& id)
{
	CSingleLock oLock(&m_pKadSection, TRUE);
	m_routingTable.MarkContactVerified(id, KadNowMs());
}

// One bounded line a minute with HELLO counters since start; no endpoints, IDs or payloads.
void CKademlia::LogHelloStatus()
{
	const DWORD now = GetTickCount();
	if (m_lastHelloStatusLog != 0 && now - m_lastHelloStatusLog < 60000u)
		return;
	m_lastHelloStatusLog = now ? now : 1;
	theApp.Message(MSG_DEBUG,
	               L"Kad2 hello: req_sent=%u send_failed=%u res_received=%u res_verified=%u res_refused=%u res_unsolicited=%u res_malformed=%u req_received=%u req_rate_limited=%u req_malformed=%u",
	               m_helloReqSent, m_helloSendFailed, m_helloResReceived, m_helloResVerified,
	               m_helloResRefused, m_helloResUnsolicited, m_helloResMalformed,
	               m_helloReqReceived, m_helloReqLimited, m_helloReqMalformed);
}

void CKademlia::LogKadStatus()
{
	size_t contactCount = m_routingTable.GetTotalContacts();
	theApp.Message(MSG_DEBUG, L"Kad2: Routing table has %d contacts", contactCount);
}

void CKademlia::OnHelloRequest(const SOCKADDR_IN* pHost, CEDPacket* pPacket)
{
	// Only aggregate counts are logged for inbound HELLO traffic (see LogHelloStatus): a
	// per-datagram line would let a flood of forged sources fill the log.
	++m_helloReqReceived;

	// eMule and aMule allow three HELLO_REQ per minute per IP; each one costs a reply.
	if (!m_inboundLimiter.Allow(ntohl(pHost->sin_addr.s_addr), KADEMLIA2_HELLO_REQ, 3, KadNowMs()))
	{
		++m_helloReqLimited;
		return;
	}

	KadHello hello;
	if (!KadParseHello(pPacket->GetCurrent(), pPacket->GetRemaining(), hello))
	{
		++m_helloReqMalformed;
		return;
	}

	// The sender is a candidate only: nothing proves its address until it answers us.
	KadContact contact;
	memcpy(contact.id, hello.id, KAD_ID_SIZE);
	contact.ip = ntohl(pHost->sin_addr.s_addr);
	contact.tcpPort = hello.tcpPort;
	contact.version = hello.version;
	contact.udpPort = KadHelloContactUdpPort(hello, ntohs(pHost->sin_port));
	if (KadHelloMayEnterRoutingTable(hello))
		UpdateContact(contact, KadContactSource::Candidate, false);

	SendHelloResponse(pHost);
}

void CKademlia::OnHelloResponse(const SOCKADDR_IN* pHost, CEDPacket* pPacket)
{
	++m_helloResReceived;

	KadHello hello;
	if (!KadParseHello(pPacket->GetCurrent(), pPacket->GetRemaining(), hello))
	{
		++m_helloResMalformed;
		return;
	}

	if (!IsRequestOutstanding(0, KAD_REQUEST_HELLO, *pHost))
	{
		++m_helloResUnsolicited;
		return;
	}

	// Store/update contact information
	KadContact contact;
	memcpy(contact.id, hello.id, KAD_ID_SIZE);
	contact.ip = ntohl(pHost->sin_addr.s_addr);
	contact.tcpPort = hello.tcpPort;
	contact.udpPort = KadHelloContactUdpPort(hello, ntohs(pHost->sin_port));
	contact.version = hello.version;
	contact.lastSeen = KadNowMs();

	// A contact that reports itself UDP firewalled is neither added nor verified.
	if (!KadHelloMayEnterRoutingTable(hello))
	{
		++m_helloResRefused;
		return;
	}

	// HELLO_RES is the event that marks a contact IP-verified.
	if (UpdateContact(contact, KadContactSource::Observed, true))
	{
		MarkContactVerified(contact.id);
		++m_helloResVerified;
	}
	else
	{
		++m_helloResRefused;
	}
}

void CKademlia::SendHelloRequest(const SOCKADDR_IN* pTarget)
{
	CEDPacket* pPacket = CEDPacket::New(KADEMLIA2_HELLO_REQ, ED2K_PROTOCOL_KAD);
	if (!pPacket) return;

	if (!WriteHelloBody(pPacket))
	{
		pPacket->Release();
		return;
	}

	// Register before sending so a fast HELLO_RES cannot arrive unmatched, and withdraw the
	// entry if the datagram did not go out so no request is left waiting for a reply.
	const bool bSent = KadSendRegistered(
	    [&]
	    { return AddOutstandingRequest(KAD_REQUEST_HELLO, *pTarget); },
	    [&](DWORD requestId)
	    { RemoveOutstandingRequest(requestId); },
	    [&]
	    { return SendPacket(pTarget, pPacket); });
	if (bSent)
		++m_helloReqSent;
	else
		++m_helloSendFailed;
	pPacket->Release();
}

void CKademlia::SendHelloResponse(const SOCKADDR_IN* pTarget)
{
	CEDPacket* pResponse = CEDPacket::New(KADEMLIA2_HELLO_RES, ED2K_PROTOCOL_KAD);
	if (!pResponse) return;

	if (WriteHelloBody(pResponse))
		SendPacket(pTarget, pResponse);
	pResponse->Release();
}

bool CKademlia::WriteHelloBody(CEDPacket* pPacket)
{
	WORD tcpPort = (WORD)Settings.Connection.InPort;
	if (tcpPort == 0) tcpPort = 4662;
	BYTE body[KadHelloFixedBytes] = {};
	const size_t len = KadWriteHello(body, sizeof(body), m_ownId, tcpPort, KADEMLIA_VERSION);
	if (len == 0)
		return false; // never send an unwritten buffer
	return pPacket->Write(body, (DWORD)len) != FALSE;
}

// Security and rate limiting implementation
bool CKademlia::CheckRateLimit(const SOCKADDR_IN* pHost, KadRequestType type)
{
	if (!pHost) return false;

	DWORD currentTime = GetTickCount();
	DWORD clientIP = pHost->sin_addr.s_addr;

	// Clean up old entries periodically (every 5 minutes)
	if (currentTime - m_lastRateLimitCleanup > 5 * 60 * 1000)
	{
		CleanupRateLimitMap();
		m_lastRateLimitCleanup = currentTime;
	}

	auto it = m_rateLimitMap.find(clientIP);
	if (it != m_rateLimitMap.end())
	{
		DWORD lastRequestTime = it->second;
		// Allow max 10 requests per minute per IP
		if (currentTime - lastRequestTime < 6000)
		{ // 6 seconds = 10 requests per minute
			return false;
		}
	}

	// Update last request time
	m_rateLimitMap[clientIP] = currentTime;
	return true;
}

void CKademlia::CleanupRateLimitMap()
{
	DWORD currentTime = GetTickCount();
	// Remove entries older than 10 minutes
	for (auto it = m_rateLimitMap.begin(); it != m_rateLimitMap.end();)
	{
		if (currentTime - it->second > 10 * 60 * 1000)
		{
			it = m_rateLimitMap.erase(it);
		}
		else
		{
			++it;
		}
	}
}

// Request tracking implementation
DWORD CKademlia::AddOutstandingRequest(KadRequestType type, const SOCKADDR_IN& targetAddr)
{
	// Simple request ID generation - use a counter for now
	static DWORD nextRequestId = 1;
	DWORD requestId = nextRequestId++;

	// Clean up expired requests first
	CleanupExpiredRequests();

	// Don't allow too many outstanding requests
	if (m_outstandingRequests.size() >= KAD2_MAX_OUTSTANDING_REQUESTS)
	{
		// Remove oldest request
		auto oldest = m_outstandingRequests.begin();
		for (auto it = m_outstandingRequests.begin(); it != m_outstandingRequests.end(); ++it)
		{
			if (it->second.sentTime < oldest->second.sentTime)
			{
				oldest = it;
			}
		}
		m_outstandingRequests.erase(oldest);
	}

	m_outstandingRequests[requestId] = KadOutstandingRequest(type, targetAddr);
	return requestId;
}

DWORD CKademlia::AddOutstandingRequest(KadRequestType type, const SOCKADDR_IN& targetAddr, const KadId& kadTarget)
{
	DWORD requestId = AddOutstandingRequest(type, targetAddr);
	auto it = m_outstandingRequests.find(requestId);
	if (it != m_outstandingRequests.end())
	{
		memcpy(it->second.targetId, kadTarget, KAD_ID_SIZE);
		it->second.hasTargetId = true;
	}
	return requestId;
}

bool CKademlia::IsRequestOutstanding(DWORD requestId, KadRequestType expectedType, const SOCKADDR_IN& fromAddr)
{
	return MatchOutstandingRequest(requestId, expectedType, fromAddr, nullptr);
}

bool CKademlia::IsRequestOutstanding(DWORD requestId, KadRequestType expectedType, const SOCKADDR_IN& fromAddr, const KadId& kadTarget)
{
	return MatchOutstandingRequest(requestId, expectedType, fromAddr, kadTarget);
}

bool CKademlia::MatchOutstandingRequest(DWORD requestId, KadRequestType expectedType, const SOCKADDR_IN& fromAddr, const unsigned char* targetId)
{
	(void)requestId;
	auto it = m_outstandingRequests.begin();
	while (it != m_outstandingRequests.end())
	{
		if (it->second.targetAddr.sin_addr.s_addr == fromAddr.sin_addr.s_addr &&
		    it->second.targetAddr.sin_port == fromAddr.sin_port &&
		    it->second.type == expectedType)
		{
			if (targetId != nullptr)
			{
				if (!it->second.hasTargetId || memcmp(it->second.targetId, targetId, KAD_ID_SIZE) != 0)
				{
					++it;
					continue;
				}
			}
			m_outstandingRequests.erase(it);
			return true;
		}
		++it;
	}

	return false;
}

void CKademlia::RemoveOutstandingRequest(DWORD requestId)
{
	m_outstandingRequests.erase(requestId);
}

void CKademlia::CleanupExpiredRequests()
{
	DWORD now = GetTickCount();
	auto it = m_outstandingRequests.begin();

	while (it != m_outstandingRequests.end())
	{
		if (now - it->second.sentTime > KAD2_REQUEST_TIMEOUT)
		{
			it = m_outstandingRequests.erase(it);
		}
		else
		{
			++it;
		}
	}
}

//////////////////////////////////////////////////////////////////////
// DHT Storage

static KadIdKey ToKey(const KadId& id)
{
	KadIdKey key;
	memcpy(key.data(), id, KAD_ID_SIZE);
	return key;
}

bool CKademlia::StoreEntry(const KadIdKey& key, const KadStoredEntry& entry)
{
	// Enforce global limit
	size_t total = 0;
	for (const auto& bucket : m_keywordStore)
		total += bucket.second.size();
	for (const auto& bucket : m_sourceStore)
		total += bucket.second.size();
	if (total >= KAD_STORE_MAX_TOTAL)
		return false;

	return true;
}

void CKademlia::CleanupExpiredEntries()
{
	DWORD now = GetTickCount();
	auto cleanup = [now](KadStore& store)
	{
		for (auto it = store.begin(); it != store.end();)
		{
			auto& entries = it->second;
			entries.erase(
			    std::remove_if(entries.begin(), entries.end(),
			                   [now](const KadStoredEntry& e)
			                   { return now > e.lifetime; }),
			    entries.end());
			if (entries.empty())
				it = store.erase(it);
			else
				++it;
		}
	};
	cleanup(m_keywordStore);
	cleanup(m_sourceStore);
}

size_t CKademlia::GetStoredEntryCount() const
{
	size_t total = 0;
	for (const auto& bucket : m_keywordStore)
		total += bucket.second.size();
	for (const auto& bucket : m_sourceStore)
		total += bucket.second.size();
	return total;
}

void CKademlia::WriteEntryTags(CEDPacket* pPacket, const KadStoredEntry& entry)
{
	pPacket->Write(entry.sourceId, KAD_ID_SIZE);
	pPacket->WriteLongLE(entry.ip);
	pPacket->WriteShortLE(entry.udpPort);
	pPacket->WriteShortLE(entry.tcpPort);
	// Write tag count + tags
	pPacket->WriteByte((BYTE)entry.tags.size());
	for (const auto& tag : entry.tags)
	{
		pPacket->WriteByte(tag.first);
		pPacket->WriteShortLE((WORD)tag.second.size());
		if (!tag.second.empty())
			pPacket->Write(tag.second.data(), tag.second.size());
	}
}

bool CKademlia::ReadEntryTags(CEDPacket* pPacket, KadStoredEntry& entry)
{
	if (pPacket->GetRemaining() < KAD_ID_SIZE + 4 + 2 + 2 + 1)
		return false;

	pPacket->Read(entry.sourceId, KAD_ID_SIZE);
	entry.ip = pPacket->ReadLongLE();
	entry.udpPort = pPacket->ReadShortLE();
	entry.tcpPort = pPacket->ReadShortLE();
	entry.lifetime = GetTickCount() + KAD_STORE_ENTRY_LIFETIME;

	BYTE tagCount = pPacket->ReadByte();
	if (tagCount > 32) return false;

	for (BYTE t = 0; t < tagCount; t++)
	{
		if (pPacket->GetRemaining() < 3) return false;
		BYTE tagId = pPacket->ReadByte();
		WORD tagLen = pPacket->ReadShortLE();
		if (!KadStoreTagLengthOk(tagLen)) return false;
		if (pPacket->GetRemaining() < tagLen) return false;

		std::vector<BYTE> tagData(tagLen);
		if (tagLen > 0)
			pPacket->Read(tagData.data(), tagLen);
		entry.tags.push_back(std::make_pair(tagId, std::move(tagData)));
	}
	return true;
}

//////////////////////////////////////////////////////////////////////
// Search handlers

void CKademlia::OnSearchKeyRequest(const SOCKADDR_IN* pHost, CEDPacket* pPacket)
{
	// KADEMLIA2_SEARCH_KEY_REQ: <TargetID 16><StartPos 1 or 2>
	if (pPacket->GetRemaining() < KAD_ID_SIZE)
		return;

	if (!CheckRateLimit(pHost, KAD_REQUEST_SEARCH_KEY))
		return;

	KadId targetId;
	pPacket->Read(targetId, KAD_ID_SIZE);

	theApp.Message(MSG_DEBUG, L"Kad2: Search key request from %s",
	               (LPCTSTR)CString(inet_ntoa(pHost->sin_addr)));

	// Look up in keyword store
	KadIdKey key = ToKey(targetId);
	auto it = m_keywordStore.find(key);

	CEDPacket* pResponse = CEDPacket::New(KADEMLIA2_SEARCH_RES, ED2K_PROTOCOL_KAD);
	if (!pResponse) return;

	pResponse->Write(targetId, KAD_ID_SIZE);

	BYTE count = 0;
	if (it != m_keywordStore.end())
	{
		count = (BYTE)min(it->second.size(), (size_t)255);
	}
	pResponse->WriteByte(count);

	if (it != m_keywordStore.end())
	{
		for (size_t i = 0; i < count; i++)
			WriteEntryTags(pResponse, it->second[i]);
	}

	SendPacket(pHost, pResponse);
	pResponse->Release();
}

void CKademlia::OnSearchSourceRequest(const SOCKADDR_IN* pHost, CEDPacket* pPacket)
{
	// Kad2: <FileHash 16><StartPosition uint16 LE><FileSize uint64 LE>.
	// Keep the historical Envy size-only body and hash-only form readable, but
	// reject ambiguous/truncated lengths instead of interpreting partial fields.
	const DWORD nBodyLength = pPacket->GetRemaining();
	if (nBodyLength != KAD_ID_SIZE &&
	    nBodyLength != KAD_SEARCH_SOURCE_REQ_LEGACY_BODY_SIZE &&
	    nBodyLength != KAD_SEARCH_SOURCE_REQ_BODY_SIZE)
		return;

	if (!CheckRateLimit(pHost, KAD_REQUEST_SEARCH_SOURCE))
		return;

	KadId fileHash;
	pPacket->Read(fileHash, KAD_ID_SIZE);

	const size_t nTailLength = pPacket->GetRemaining();
	std::array<uint8_t, KAD_SEARCH_SOURCE_REQ_TAIL_SIZE> tail{};
	if (nTailLength != 0)
		pPacket->Read(tail.data(), static_cast<DWORD>(nTailLength));

	uint16_t nStartPosition = 0;
	uint64_t nFileSize = 0;
	if (!KadDecodeSearchSourceRequestTail(
	        tail.data(), nTailLength, nStartPosition, nFileSize))
		return;
	(void)nFileSize; // Stored answers are not filtered by size in this slice.

	theApp.Message(MSG_DEBUG, L"Kad2: Search source request from %s",
	               (LPCTSTR)CString(inet_ntoa(pHost->sin_addr)));

	KadIdKey key = ToKey(fileHash);
	auto it = m_sourceStore.find(key);

	CEDPacket* pResponse = CEDPacket::New(KADEMLIA2_SEARCH_RES, ED2K_PROTOCOL_KAD);
	if (!pResponse) return;

	pResponse->Write(fileHash, KAD_ID_SIZE);

	size_t nFirst = 0;
	BYTE count = 0;
	if (it != m_sourceStore.end())
	{
		nFirst = min(static_cast<size_t>(nStartPosition), it->second.size());
		count = (BYTE)min(it->second.size() - nFirst, (size_t)255);
	}
	pResponse->WriteByte(count);

	if (it != m_sourceStore.end())
	{
		for (size_t i = 0; i < count; i++)
			WriteEntryTags(pResponse, it->second[nFirst + i]);
	}

	SendPacket(pHost, pResponse);
	pResponse->Release();
}

void CKademlia::OnSearchResponse(const SOCKADDR_IN* pHost, CEDPacket* pPacket)
{
	ProcessSearchResponseDelivery(pHost, pPacket);
}

//////////////////////////////////////////////////////////////////////
// Publish handlers

void CKademlia::OnPublishKeyRequest(const SOCKADDR_IN* pHost, CEDPacket* pPacket)
{
	// KADEMLIA2_PUBLISH_KEY_REQ: <KeywordHash 16><PublisherID 16><TagList>
	if (pPacket->GetRemaining() < KAD_ID_SIZE)
		return;

	if (!CheckRateLimit(pHost, KAD_REQUEST_PUBLISH_KEY))
		return;

	KadId keywordHash;
	pPacket->Read(keywordHash, KAD_ID_SIZE);

	KadStoredEntry entry;
	if (!ReadEntryTags(pPacket, entry))
		return;

	theApp.Message(MSG_DEBUG, L"Kad2: Publish key request from %s",
	               (LPCTSTR)CString(inet_ntoa(pHost->sin_addr)));

	KadIdKey key = ToKey(keywordHash);
	auto& entries = m_keywordStore[key];

	BYTE load = 0; // 0 = success

	if (entries.size() < KAD_STORE_MAX_ENTRIES_PER_KEY && GetStoredEntryCount() < KAD_STORE_MAX_TOTAL)
	{
		// Check for duplicate by sourceId
		bool found = false;
		for (auto& existing : entries)
		{
			if (memcmp(existing.sourceId, entry.sourceId, KAD_ID_SIZE) == 0)
			{
				existing = entry;
				found = true;
				break;
			}
		}
		if (!found)
			entries.push_back(entry);
	}
	else
	{
		load = 100; // Overloaded
	}

	// Send PUBLISH_RES
	CEDPacket* pResponse = CEDPacket::New(KADEMLIA2_PUBLISH_RES, ED2K_PROTOCOL_KAD);
	if (!pResponse) return;

	pResponse->Write(keywordHash, KAD_ID_SIZE);
	pResponse->WriteByte(load);

	SendPacket(pHost, pResponse);
	pResponse->Release();
}

void CKademlia::OnPublishSourceRequest(const SOCKADDR_IN* pHost, CEDPacket* pPacket)
{
	// KADEMLIA2_PUBLISH_SOURCE_REQ: <FileHash 16><PublisherID 16><TagList>
	if (pPacket->GetRemaining() < KAD_ID_SIZE)
		return;

	if (!CheckRateLimit(pHost, KAD_REQUEST_PUBLISH_SOURCE))
		return;

	KadId fileHash;
	pPacket->Read(fileHash, KAD_ID_SIZE);

	KadStoredEntry entry;
	if (!ReadEntryTags(pPacket, entry))
		return;

	theApp.Message(MSG_DEBUG, L"Kad2: Publish source request from %s",
	               (LPCTSTR)CString(inet_ntoa(pHost->sin_addr)));

	KadIdKey key = ToKey(fileHash);
	auto& entries = m_sourceStore[key];

	BYTE load = 0;

	if (entries.size() < KAD_STORE_MAX_ENTRIES_PER_KEY && GetStoredEntryCount() < KAD_STORE_MAX_TOTAL)
	{
		bool found = false;
		for (auto& existing : entries)
		{
			if (memcmp(existing.sourceId, entry.sourceId, KAD_ID_SIZE) == 0)
			{
				existing = entry;
				found = true;
				break;
			}
		}
		if (!found)
			entries.push_back(entry);
	}
	else
	{
		load = 100;
	}

	CEDPacket* pResponse = CEDPacket::New(KADEMLIA2_PUBLISH_RES, ED2K_PROTOCOL_KAD);
	if (!pResponse) return;

	pResponse->Write(fileHash, KAD_ID_SIZE);
	pResponse->WriteByte(load);

	SendPacket(pHost, pResponse);
	pResponse->Release();
}

void CKademlia::OnPublishResponse(const SOCKADDR_IN* pHost, CEDPacket* pPacket)
{
	// KADEMLIA2_PUBLISH_RES: <TargetID 16><Load 1>
	if (pPacket->GetRemaining() < KAD_ID_SIZE + 1)
		return;

	KadId targetId;
	pPacket->Read(targetId, KAD_ID_SIZE);
	BYTE load = pPacket->ReadByte();

	theApp.Message(MSG_DEBUG, L"Kad2: Publish response from %s (load: %d)",
	               (LPCTSTR)CString(inet_ntoa(pHost->sin_addr)), load);
}

//////////////////////////////////////////////////////////////////////
// Search/Publish initiation (send to closest contacts)

void CKademlia::SearchKeyword(const KadId& keywordHash)
{
	if (!m_bInitialized)
		return;

	CSingleLock oLock(&m_pKadSection, TRUE);
	std::vector<KadContact> closest;
	m_routingTable.FindClosestContacts(keywordHash, closest, KAD_K);

	if (closest.empty())
	{
		theApp.Message(MSG_DEBUG, L"Kad2: No contacts for keyword search");
		return;
	}

	m_outstandingSearches.Expire(GetTickCount());
	if (!m_outstandingSearches.Register(KadSearchKind::Keyword, keywordHash, GetTickCount()))
	{
		theApp.Message(MSG_DEBUG, L"Kad2: Outstanding keyword search map full");
		return;
	}

	theApp.Message(MSG_DEBUG, L"Kad2: Starting keyword search, querying %d contacts", closest.size());

	for (const auto& contact : closest)
		SendSearchKeyRequest(contact, keywordHash);
}

void CKademlia::SearchSource(const KadId& fileHash, QWORD nFileSize)
{
	if (!m_bInitialized)
		return;

	CSingleLock oLock(&m_pKadSection, TRUE);
	std::vector<KadContact> closest;
	m_routingTable.FindClosestContacts(fileHash, closest, KAD_K);

	if (closest.empty())
	{
		theApp.Message(MSG_DEBUG, L"Kad2: No contacts for source search");
		return;
	}

	m_outstandingSearches.Expire(GetTickCount());
	if (!m_outstandingSearches.Register(KadSearchKind::Source, fileHash, GetTickCount()))
	{
		theApp.Message(MSG_DEBUG, L"Kad2: Outstanding source search map full");
		return;
	}

	theApp.Message(MSG_DEBUG, L"Kad2: Starting source search, querying %d contacts", closest.size());

	for (const auto& contact : closest)
		SendSearchSourceRequest(contact, fileHash, nFileSize);
}

void CKademlia::PublishKeyword(const KadId& keywordHash, const KadStoredEntry& entry)
{
	if (!m_bInitialized) return;

	CSingleLock oLock(&m_pKadSection, TRUE);
	std::vector<KadContact> closest;
	m_routingTable.FindClosestContacts(keywordHash, closest, KAD_K);

	theApp.Message(MSG_DEBUG, L"Kad2: Publishing keyword to %d contacts", closest.size());

	for (const auto& contact : closest)
		SendPublishKeyRequest(contact, keywordHash, entry);
}

void CKademlia::PublishSource(const KadId& fileHash, const KadStoredEntry& entry)
{
	if (!m_bInitialized) return;

	CSingleLock oLock(&m_pKadSection, TRUE);
	std::vector<KadContact> closest;
	m_routingTable.FindClosestContacts(fileHash, closest, KAD_K);

	theApp.Message(MSG_DEBUG, L"Kad2: Publishing source to %d contacts", closest.size());

	for (const auto& contact : closest)
		SendPublishSourceRequest(contact, fileHash, entry);
}

//////////////////////////////////////////////////////////////////////
// Send search/publish packets

void CKademlia::SendSearchKeyRequest(const KadContact& contact, const KadId& targetId)
{
	CEDPacket* pPacket = CEDPacket::New(KADEMLIA2_SEARCH_KEY_REQ, ED2K_PROTOCOL_KAD);
	if (!pPacket) return;

	pPacket->Write(targetId, KAD_ID_SIZE);

	sockaddr_in addr;
	KadContactGetSockAddr(contact, addr);
	AddOutstandingRequest(KAD_REQUEST_SEARCH_KEY, addr);

	SendPacket(&addr, pPacket);
	pPacket->Release();
}

void CKademlia::SendSearchSourceRequest(const KadContact& contact, const KadId& targetId, QWORD nFileSize)
{
	CEDPacket* pPacket = CEDPacket::New(KADEMLIA2_SEARCH_SOURCE_REQ, ED2K_PROTOCOL_KAD);
	if (!pPacket) return;

	// Use the tested wire encoder instead of CPacket::WriteInt64, whose endian
	// behavior follows m_bBigEndian and does not match Kad2's little-endian fields.
	std::array<uint8_t, KAD_SEARCH_SOURCE_REQ_BODY_SIZE> body{};
	const size_t nBodyLength = KadEncodeSearchSourceRequest(
	    body.data(), body.size(), targetId, 0, static_cast<uint64_t>(nFileSize));
	if (nBodyLength != body.size() ||
	    !pPacket->Write(body.data(), static_cast<DWORD>(nBodyLength)))
	{
		pPacket->Release();
		return;
	}

	sockaddr_in addr;
	KadContactGetSockAddr(contact, addr);
	AddOutstandingRequest(KAD_REQUEST_SEARCH_SOURCE, addr);

	SendPacket(&addr, pPacket);
	pPacket->Release();
}

void CKademlia::SendPublishKeyRequest(const KadContact& contact, const KadId& targetId, const KadStoredEntry& entry)
{
	CEDPacket* pPacket = CEDPacket::New(KADEMLIA2_PUBLISH_KEY_REQ, ED2K_PROTOCOL_KAD);
	if (!pPacket) return;

	pPacket->Write(targetId, KAD_ID_SIZE);
	WriteEntryTags(pPacket, entry);

	sockaddr_in addr;
	KadContactGetSockAddr(contact, addr);
	AddOutstandingRequest(KAD_REQUEST_PUBLISH_KEY, addr);

	SendPacket(&addr, pPacket);
	pPacket->Release();
}

void CKademlia::SendPublishSourceRequest(const KadContact& contact, const KadId& targetId, const KadStoredEntry& entry)
{
	CEDPacket* pPacket = CEDPacket::New(KADEMLIA2_PUBLISH_SOURCE_REQ, ED2K_PROTOCOL_KAD);
	if (!pPacket) return;

	pPacket->Write(targetId, KAD_ID_SIZE);
	WriteEntryTags(pPacket, entry);

	sockaddr_in addr;
	KadContactGetSockAddr(contact, addr);
	AddOutstandingRequest(KAD_REQUEST_PUBLISH_SOURCE, addr);

	SendPacket(&addr, pPacket);
	pPacket->Release();
}

//////////////////////////////////////////////////////////////////////
// SEARCH_RES → ED2K source delivery

void CKademlia::DeliverSourceCandidate(const BYTE* pFileHash, const KadSourceCandidate& cand)
{
	KadEd2kSourceParams params;
	if (!KadMapSourceCandidateToEd2k(cand, params) || !params.deliverable)
		return;

	Hashes::Ed2kHash oED2K;
	memcpy(&oED2K[0], pFileHash, KAD_ID_SIZE);
	oED2K.validate();
	if (!oED2K)
		return;

	Hashes::Guid oGUID;
	memcpy(&oGUID[0], params.oGUID, KAD_ID_SIZE);
	oGUID.validate();

	// Look up by stable ED2K hash at delivery time (no retained CDownload*).
	// AddSourceInternal takes Transfers.m_pSection; hold it for FindByED2K too.
	CQuickLock oLock(Transfers.m_pSection);

	CDownload* pDownload = Downloads.FindByED2K(oED2K);
	if (!pDownload)
		return;
	if (pDownload->IsCompleted() || pDownload->IsMoving())
		return;

	pDownload->AddSourceED2K(
	    params.nClientID,
	    params.nClientPort,
	    params.nServerIP,
	    params.nServerPort,
	    oGUID);
}

void CKademlia::ProcessSearchResponseDelivery(const SOCKADDR_IN* pHost, CEDPacket* pPacket)
{
	// KADEMLIA2_SEARCH_RES (eMule/aMule):
	//   <SenderID 16><TargetID 16><Count 2>
	//   [ <AnswerID 16><TagCount 1><ED2K tags...> ] * Count
	// Kind comes from outstanding search context, not from tags alone.
	const DWORD nRemaining = pPacket->GetRemaining();
	if (nRemaining < KAD_SEARCH_RES_MIN_HEADER)
		return;

	const BYTE* pBody = pPacket->m_pBuffer + pPacket->m_nPosition;
	BYTE senderId[KAD_ID_SIZE];
	BYTE targetId[KAD_ID_SIZE];
	WORD nCount = 0;
	std::vector<KadSourceCandidate> entries;

	if (!KadParseSearchResBody(pBody, nRemaining, senderId, targetId, nCount, &entries))
	{
		theApp.Message(MSG_DEBUG, L"Kad2: Rejecting malformed SEARCH_RES from %s",
		               (LPCTSTR)CString(inet_ntoa(pHost->sin_addr)));
		return;
	}

	// Consume the body so the packet position stays consistent.
	pPacket->Seek(nRemaining, CPacket::seekCurrent);

	const DWORD now = GetTickCount();
	m_outstandingSearches.Expire(now);

	KadOutstandingSearch searchCtx;
	bool bExpired = false;
	const bool bHasCtx = m_outstandingSearches.Lookup(targetId, now, searchCtx, bExpired);

	const KadSearchResDisposition disp = KadClassifySearchResponse(
	    bHasCtx, bExpired, bHasCtx /* target key match */, searchCtx.kind);

	// Peer must have been queried for this search kind (unsolicited IP reject).
	bool bPeerAsked = false;
	if (bHasCtx && !bExpired)
	{
		if (searchCtx.kind == KadSearchKind::Keyword)
			bPeerAsked = IsRequestOutstanding(0, KAD_REQUEST_SEARCH_KEY, *pHost);
		else if (searchCtx.kind == KadSearchKind::Source)
			bPeerAsked = IsRequestOutstanding(0, KAD_REQUEST_SEARCH_SOURCE, *pHost);
	}

	if (disp == KadSearchResDisposition::RejectUnsolicited ||
	    disp == KadSearchResDisposition::RejectExpired ||
	    disp == KadSearchResDisposition::RejectMismatchedTarget ||
	    !bPeerAsked)
	{
		theApp.Message(MSG_DEBUG,
		               L"Kad2: Ignoring SEARCH_RES from %s (disp=%u peerAsked=%d count=%u)",
		               (LPCTSTR)CString(inet_ntoa(pHost->sin_addr)),
		               (unsigned)disp, bPeerAsked ? 1 : 0, nCount);
		return;
	}

	theApp.Message(MSG_DEBUG, L"Kad2: Search response from %s with %u results (kind=%u)",
	               (LPCTSTR)CString(inet_ntoa(pHost->sin_addr)), nCount, (unsigned)searchCtx.kind);

	if (disp == KadSearchResDisposition::IgnoreKeywordResults)
	{
		// Keyword hits must never become download sources.
		return;
	}

	if (disp != KadSearchResDisposition::DeliverSources)
		return;

	for (const auto& cand : entries)
		DeliverSourceCandidate(targetId, cand);
}

void CKademlia::OnTcpFirewallCheckAck(const SOCKADDR_IN* pHost)
{
	if (!m_bInitialized || !pHost)
		return;

	const DWORD ipHost = ntohl(pHost->sin_addr.s_addr);
	const KadFwAckStatus st = m_firewall.OnTcpFirewallCheckAck(ipHost, GetTickCount());
	if (st == KadFwAckStatus::Accepted)
	{
		theApp.Message(MSG_DEBUG, L"Kad2: TCP firewall ACK (0xA8) from %s (acks=%u state=%u)",
		               (LPCTSTR)CString(inet_ntoa(pHost->sin_addr)),
		               m_firewall.AckCount(), (unsigned)m_firewall.TcpState());
		if (m_firewall.ShouldLogOpenTransition())
			theApp.Message(MSG_DEBUG, L"Kad2: TCP firewall state Open");
	}
}

void CKademlia::OnFirewalledRequest(const SOCKADDR_IN* pHost, CEDPacket* pPacket, bool firewalled2)
{
	if (!pHost || !pPacket)
		return;

	const DWORD ipHost = ntohl(pHost->sin_addr.s_addr);
	const WORD udpPort = ntohs(pHost->sin_port);
	const KadFwInboundReqResult r = m_firewall.OnInboundFirewalledReq(
	    ipHost, udpPort, pPacket->GetCurrent(), pPacket->GetRemaining(),
	    GetTickCount(), firewalled2);

	if (!r.sendResponse)
	{
		theApp.Message(MSG_DEBUG, L"Kad2: Ignoring FIREWALLED_REQ from %s (status=%u)",
		               (LPCTSTR)CString(inet_ntoa(pHost->sin_addr)), (unsigned)r.status);
		return;
	}

	// RES reports the IPv4 we observed. Recording a TCP probe is not a
	// completed connect-back; Buddy/callback and live TCP tests stay out.
	SendFirewalledResponse(pHost, r.observedIpHost);
	theApp.Message(MSG_DEBUG,
	               L"Kad2: FIREWALLED_RES to %s observedIP=0x%08x tcpPort=%u (probe recorded, not executed)",
	               (LPCTSTR)CString(inet_ntoa(pHost->sin_addr)), r.observedIpHost, r.tcpPort);
}

void CKademlia::OnFirewalledResponse(const SOCKADDR_IN* pHost, CEDPacket* pPacket)
{
	if (!pHost || !pPacket)
		return;

	const DWORD ipHost = ntohl(pHost->sin_addr.s_addr);
	const WORD udpPort = ntohs(pHost->sin_port);
	const KadFwResStatus st = m_firewall.OnFirewalledRes(
	    ipHost, udpPort, pPacket->GetCurrent(), pPacket->GetRemaining(), GetTickCount());

	if (st != KadFwResStatus::Accepted)
	{
		theApp.Message(MSG_DEBUG, L"Kad2: Ignoring FIREWALLED_RES from %s (status=%u)",
		               (LPCTSTR)CString(inet_ntoa(pHost->sin_addr)), (unsigned)st);
		return;
	}

	theApp.Message(MSG_DEBUG, L"Kad2: FIREWALLED_RES accepted from %s publicIP=0x%08x",
	               (LPCTSTR)CString(inet_ntoa(pHost->sin_addr)), m_firewall.PublicIpHost());
}

void CKademlia::OnFirewalledAck(const SOCKADDR_IN* pHost, CEDPacket* pPacket)
{
	if (!pHost || !pPacket)
		return;

	const DWORD ipHost = ntohl(pHost->sin_addr.s_addr);
	const WORD udpPort = ntohs(pHost->sin_port);
	const KadFwAckStatus st = m_firewall.OnFirewalledAck(
	    ipHost, udpPort, pPacket->GetRemaining(), GetTickCount());
	if (st != KadFwAckStatus::Accepted)
		return;

	theApp.Message(MSG_DEBUG, L"Kad2: FIREWALLED_ACK from %s (acks=%u state=%u)",
	               (LPCTSTR)CString(inet_ntoa(pHost->sin_addr)),
	               m_firewall.AckCount(), (unsigned)m_firewall.TcpState());
	if (m_firewall.ShouldLogOpenTransition())
		theApp.Message(MSG_DEBUG, L"Kad2: TCP firewall state Open");
}

void CKademlia::SendFirewalledResponse(const SOCKADDR_IN* pHost, DWORD observedIpHost)
{
	CEDPacket* pPacket = CEDPacket::New(KADEMLIA2_FIREWALLED_RES, ED2K_PROTOCOL_KAD);
	if (!pPacket)
		return;
	pPacket->WriteLongLE(observedIpHost);
	SendPacket(pHost, pPacket);
	pPacket->Release();
}

void CKademlia::SendFirewalledRequest(const KadContact& contact)
{
	if (!m_bInitialized)
		return;

	sockaddr_in addr;
	KadContactGetSockAddr(contact, addr);

	KadFwPeerCandidate peer;
	peer.ipHost = contact.ip;
	peer.udpPort = contact.udpPort;
	peer.tcpPort = contact.tcpPort;
	peer.version = contact.version;
	peer.verified = contact.verified != FALSE;
	peer.lastSeen = static_cast<DWORD>(contact.lastSeen);

	if (!m_firewall.BeginOutboundCheck(peer, GetTickCount()))
		return;

	CEDPacket* pPacket = CEDPacket::New(KADEMLIA2_FIREWALLED_REQ, ED2K_PROTOCOL_KAD);
	if (!pPacket)
		return;
	pPacket->WriteShortLE(m_firewall.OurTcpPort());
	AddOutstandingRequest(KAD_REQUEST_FIREWALL_CHECK, addr);
	SendPacket(&addr, pPacket);
	pPacket->Release();

	theApp.Message(MSG_DEBUG, L"Kad2: FIREWALLED_REQ to %s:%u (tcpPort=%u)",
	               (LPCTSTR)CString(inet_ntoa(addr.sin_addr)), ntohs(addr.sin_port),
	               m_firewall.OurTcpPort());
}

void CKademlia::CollectFirewallCheckCandidates(
    KadFwPeerCandidate* out, size_t outMax, size_t& outCount) const
{
	outCount = 0;
	if (!out || outMax == 0)
		return;

	KadFwPeerCandidate raw[KAD_FW_MAX_CANDIDATES * 2];
	const size_t rawMax = KAD_FW_MAX_CANDIDATES * 2;
	std::vector<KadContact> contacts;
	m_routingTable.GetContactsForBootstrap(contacts, static_cast<int>(rawMax));
	size_t nRaw = 0;
	for (const auto& contact : contacts)
	{
		if (nRaw >= rawMax)
			break;
		raw[nRaw].ipHost = contact.ip;
		raw[nRaw].udpPort = contact.udpPort;
		raw[nRaw].tcpPort = contact.tcpPort;
		raw[nRaw].version = contact.version;
		raw[nRaw].verified = contact.verified != FALSE;
		raw[nRaw].lastSeen = static_cast<DWORD>(contact.lastSeen);
		++nRaw;
	}

	outCount = KadSelectFirewallCheckPeers(raw, nRaw, out, outMax);
}

void CKademlia::MaybeStartFirewallChecks()
{
	const DWORD now = GetTickCount();
	if (!m_firewall.WantsNewOutboundCheck(now))
		return;

	KadFwPeerCandidate chosen[KAD_FW_MAX_OUTSTANDING_CHECKS];
	size_t nChosen = 0;
	CollectFirewallCheckCandidates(chosen, KAD_FW_MAX_OUTSTANDING_CHECKS, nChosen);
	if (nChosen == 0)
		return;

	for (size_t i = 0; i < nChosen; ++i)
	{
		if (m_firewall.HasOutboundCheck(chosen[i].ipHost, chosen[i].udpPort))
			continue;

		KadContact contact;
		contact.ip = chosen[i].ipHost;
		contact.udpPort = chosen[i].udpPort;
		contact.tcpPort = chosen[i].tcpPort;
		contact.version = chosen[i].version;
		contact.verified = chosen[i].verified ? TRUE : FALSE;
		contact.lastSeen = chosen[i].lastSeen;
		SendFirewalledRequest(contact);
		break; // one new REQ per timer tick
	}
}

// --- UDP firewall tester (#515) ---

void CKademlia::OnFirewallUdpResult(const SOCKADDR_IN* pHost, CEDPacket* pPacket)
{
	if (!pHost || !pPacket)
		return;

	const DWORD ipHost = ntohl(pHost->sin_addr.s_addr);
	const DWORD now = GetTickCount();
	if (!m_inboundLimiter.Allow(ipHost, KAD_OP_FIREWALLUDP, KAD_UDPFW_RESULT_PER_MINUTE, now))
	{
		theApp.Message(MSG_DEBUG, L"Kad2: FIREWALLUDP rate-limited from %s",
		               (LPCTSTR)CString(inet_ntoa(pHost->sin_addr)));
		return;
	}

	KadUdpFwResultPacket res;
	if (KadParseFirewallUdpResult(pPacket->GetCurrent(), pPacket->GetRemaining(), res) != KadUdpFwParseStatus::Ok)
	{
		theApp.Message(MSG_DEBUG, L"Kad2: Ignoring malformed FIREWALLUDP from %s",
		               (LPCTSTR)CString(inet_ntoa(pHost->sin_addr)));
		return;
	}

	// eMule listener classification: an unexpected (or zero) incoming port
	// and any non-zero errorcode both cancel the test; only errorcode 0 on
	// one of our Kad UDP ports is a success. The external port is unknown
	// until an extern-port lookup exists.
	bool succeeded = false;
	bool cancelled = true;
	if (KadUdpFwIncomingPortExpected(res.incomingPort, (WORD)Settings.Connection.InPort, 0))
	{
		if (res.errorCode == KAD_UDPFW_ERROR_OK)
		{
			succeeded = true;
			cancelled = false;
		}
	}

	const KadUdpFwResultStatus st = m_udpFirewall.OnProbeResult(ipHost, succeeded, cancelled, now);
	switch (st)
	{
	case KadUdpFwResultStatus::Succeeded:
	case KadUdpFwResultStatus::Failed:
		theApp.Message(MSG_DEBUG, L"Kad2: UDP firewall state -> %u (verified=%u) via %s",
		               (unsigned)m_udpFirewall.State(), m_udpFirewall.IsVerified() ? 1u : 0u,
		               (LPCTSTR)CString(inet_ntoa(pHost->sin_addr)));
		break;
	case KadUdpFwResultStatus::Cancelled:
		theApp.Message(MSG_DEBUG, L"Kad2: FIREWALLUDP cancelled from %s (error=%u port=%u)",
		               (LPCTSTR)CString(inet_ntoa(pHost->sin_addr)), res.errorCode, res.incomingPort);
		break;
	case KadUdpFwResultStatus::Unrequested:
	case KadUdpFwResultStatus::Duplicate:
	case KadUdpFwResultStatus::NotRunning:
	default:
		theApp.Message(MSG_DEBUG, L"Kad2: Ignoring FIREWALLUDP from %s (status=%u)",
		               (LPCTSTR)CString(inet_ntoa(pHost->sin_addr)), (unsigned)st);
		break;
	}
}

void CKademlia::OnFirewallCheckUdpRequest(const BYTE* pPayload, size_t nLen, const SOCKADDR_IN* pHost,
                                          bool requesterKnownToTransfers)
{
	if (!m_bInitialized || !pPayload || !pHost)
		return;

	KadUdpFwCheckRequest req;
	if (KadParseUdpFwCheckRequest(pPayload, nLen, req) != KadUdpFwParseStatus::Ok)
		return;

	// eMule aborts on intern port 0: there is nowhere to send the probe.
	if (req.internPort == 0)
	{
		theApp.Message(MSG_DEBUG, L"Kad2: FWCHECKUDPREQ from %s with intern port 0 ignored",
		               (LPCTSTR)CString(inet_ntoa(pHost->sin_addr)));
		return;
	}

	const DWORD ipHost = ntohl(pHost->sin_addr.s_addr);
	CSingleLock oLock(&m_pKadSection, TRUE);
	// Biased-result rule (eMule ProcessFirewallCheckUDPRequest): when we
	// already know the requester from transfers/chat or the routing zone,
	// the probe result would be pre-biased, so mark errorcode 1.
	bool known = requesterKnownToTransfers;
	if (!known)
		known = RoutingZoneHasIp(ipHost);

	const KadUdpFwProbePlan plan = KadPlanFirewallUdpProbes(req.internPort, req.externPort, known);
	for (BYTE i = 0; i < plan.count; ++i)
		SendFirewallUdpProbe(ipHost, plan.targetPort[i], plan.errorCode[i]);

	theApp.Message(MSG_DEBUG, L"Kad2: FWCHECKUDPREQ from %s answered with %u probe(s) (biased=%u)",
	               (LPCTSTR)CString(inet_ntoa(pHost->sin_addr)), plan.count, known ? 1u : 0u);
}

void CKademlia::SendFirewallUdpProbe(DWORD ipHost, WORD port, BYTE errorCode)
{
	if (ipHost == 0 || port == 0)
		return;

	BYTE body[3];
	KadBuildFirewallUdpProbe(body, errorCode, port);
	CEDPacket* pPacket = CEDPacket::New(KADEMLIA2_FIREWALLUDP, ED2K_PROTOCOL_KAD);
	if (!pPacket)
		return;
	pPacket->Write(body, 3);

	sockaddr_in addr;
	memset(&addr, 0, sizeof(sockaddr_in));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(ipHost);
	addr.sin_port = htons(port);
	// No UDP verify keys yet (#513 phase D): sent unencrypted like every
	// other Kad datagram Envy emits today.
	SendPacket(&addr, pPacket);
	pPacket->Release();

	theApp.Message(MSG_DEBUG, L"Kad2: FIREWALLUDP probe to %s:%u (error=%u)",
	               (LPCTSTR)CString(inet_ntoa(addr.sin_addr)), port, errorCode);
}

bool CKademlia::WantsUdpFirewallCheckProbe()
{
	CSingleLock oLock(&m_pKadSection, TRUE);
	if (!m_bInitialized)
		return false;
	if (Settings.Experimental.LAN_Mode != FALSE)
		return false; // LAN mode assumes open (eMule IsFirewalledUDP)
	if (m_routingTable.GetTotalContacts() == 0)
		return false; // eMule starts the UDP test once the node has contact
	return m_udpFirewall.NeedsProbeRequests();
}

bool CKademlia::BeginUdpFirewallCheckProbe(DWORD ipHost, WORD kadUdpPort, DWORD now)
{
	CSingleLock oLock(&m_pKadSection, TRUE);
	if (!m_bInitialized)
		return false;
	// Version/routing-zone/self checks belong to the client driver; here only
	// the tester's own rules apply (fresh IP per round, bounded slots).
	if (kadUdpPort == 0 || !KadIpv4IsUsableFirewallPeer(ipHost))
		return false;
	if (m_udpFirewall.AlreadyRequested(ipHost))
		return false;
	return m_udpFirewall.BeginProbeRequest(ipHost, now);
}

void CKademlia::CancelUdpFirewallCheckProbe(DWORD ipHost)
{
	CSingleLock oLock(&m_pKadSection, TRUE);
	m_udpFirewall.CancelProbeRequest(ipHost);
}

void CKademlia::OnUdpFirewallCheckClientClosed(DWORD ipHost)
{
	CSingleLock oLock(&m_pKadSection, TRUE);
	if (!m_bInitialized)
		return;
	const KadUdpFwResultStatus st = m_udpFirewall.OnProbeClientClosed(ipHost, GetTickCount());
	if (st != KadUdpFwResultStatus::Unrequested)
		theApp.Message(MSG_DEBUG, L"Kad2: UDP firewall probe client closed (%u) status=%u",
		               ipHost, (unsigned)st);
}

bool CKademlia::HasKadContactIp(DWORD ipHost)
{
	CSingleLock oLock(&m_pKadSection, TRUE);
	return RoutingZoneHasIp(ipHost);
}

bool CKademlia::RoutingZoneHasIp(DWORD ipHost)
{
	return m_routingTable.HasContactWithIp(ipHost);
}

// --- Kad buddy / callback (#516) ---

void CKademlia::OnFindBuddyRequest(const SOCKADDR_IN* pHost, CEDPacket* pPacket)
{
	if (!pHost || !pPacket)
		return;

	const DWORD ipHost = ntohl(pHost->sin_addr.s_addr);
	const WORD udpPort = ntohs(pHost->sin_port);
	const DWORD now = GetTickCount();
	// eMule InTrackListIsAllowedPacket: FINDBUDDY_REQ 2/min per IP.
	if (!m_inboundLimiter.Allow(ipHost, KAD_OP_FINDBUDDY_REQ, KAD_BUDDY_FINDBUDDY_PER_MINUTE, now))
	{
		theApp.Message(MSG_DEBUG, L"Kad2: FINDBUDDY_REQ rate-limited from %s",
		               (LPCTSTR)CString(inet_ntoa(pHost->sin_addr)));
		return;
	}

	KadFindBuddyReq req;
	if (KadParseFindBuddyReq(pPacket->GetCurrent(), pPacket->GetRemaining(), req) != KadBuddyParseStatus::Ok)
	{
		theApp.Message(MSG_DEBUG, L"Kad2: Ignoring malformed FINDBUDDY_REQ from %s",
		               (LPCTSTR)CString(inet_ntoa(pHost->sin_addr)));
		return;
	}

	// eMule guards: refuse when TCP-firewalled, UDP-firewalled, or the UDP
	// tester is not verified; refuse when the single buddy slot is taken.
	const bool tcpFirewalled = m_firewall.TcpState() == KadTcpFirewallState::Firewalled;
	const bool udpBlocked = m_udpFirewall.IsFirewalledUdp(true) || !m_udpFirewall.IsVerified();
	const DWORD ourPublicIpHost = ntohl(Network.m_pHost.sin_addr.S_un.S_addr);
	const KadBuddyAcceptStatus st = m_buddy.AcceptFindBuddyRequest(
	    ipHost, udpPort, req, tcpFirewalled, udpBlocked, ourPublicIpHost);
	if (st != KadBuddyAcceptStatus::Accept)
	{
		theApp.Message(MSG_DEBUG, L"Kad2: FINDBUDDY_REQ refused from %s (status=%u)",
		               (LPCTSTR)CString(inet_ntoa(pHost->sin_addr)), (unsigned)st);
		return;
	}

	SendFindBuddyResponse(pHost, req.buddyId);
	theApp.Message(MSG_DEBUG, L"Kad2: FINDBUDDY_RES to %s (incoming buddy candidate, tcpPort=%u)",
	               (LPCTSTR)CString(inet_ntoa(pHost->sin_addr)), req.tcpPort);
}

void CKademlia::SendFindBuddyResponse(const SOCKADDR_IN* pHost, const BYTE* pBuddyId16)
{
	// <BuddyID 16 (echo)><ClientHash 16><TCPPort 2><ConnectOptions 1>.
	// The ClientHash is the same canonical wire user hash SendHello emits
	// (eMule cross-checks the connecting buddy's HELLO against the hash
	// advertised here); ConnectOptions stays 0 while obfuscation and the
	// direct-UDP-callback bit are honestly unimplemented (#121, #513).
	BYTE clientHash[KAD_ID_SIZE];
	memcpy(clientHash, m_ownId, KAD_ID_SIZE);
	Ed2kHelloApplyGuidMutation(clientHash);
	BYTE body[KAD_BUDDY_RES_WITH_OPTIONS];
	KadBuildFindBuddyRes(body, pBuddyId16, clientHash, (WORD)Settings.Connection.InPort, 0);
	CEDPacket* pPacket = CEDPacket::New(KADEMLIA_FINDBUDDY_RES, ED2K_PROTOCOL_KAD);
	if (!pPacket)
		return;
	pPacket->Write(body, KAD_BUDDY_RES_WITH_OPTIONS);
	SendPacket(pHost, pPacket);
	pPacket->Release();
}

void CKademlia::OnFindBuddyResponse(const SOCKADDR_IN* pHost, CEDPacket* pPacket)
{
	if (!pHost || !pPacket)
		return;

	const DWORD ipHost = ntohl(pHost->sin_addr.s_addr);
	const DWORD now = GetTickCount();
	KadFindBuddyRes res;
	if (KadParseFindBuddyRes(pPacket->GetCurrent(), pPacket->GetRemaining(), res) != KadBuddyParseStatus::Ok)
	{
		theApp.Message(MSG_DEBUG, L"Kad2: Ignoring malformed FINDBUDDY_RES from %s",
		               (LPCTSTR)CString(inet_ntoa(pHost->sin_addr)));
		return;
	}

	const KadBuddyCandidateStatus st = m_buddy.OnFindBuddyResponse(ipHost, res, m_ownId, now);
	switch (st)
	{
	case KadBuddyCandidateStatus::Accepted:
		m_pendingBuddyConnect = m_buddy.Buddy();
		m_hasPendingBuddyConnect = true;
		theApp.Message(MSG_DEBUG, L"Kad2: FINDBUDDY_RES accepted from %s (tcpPort=%u) - buddy connect queued",
		               (LPCTSTR)CString(inet_ntoa(pHost->sin_addr)), res.tcpPort);
		break;
	default:
		theApp.Message(MSG_DEBUG, L"Kad2: Ignoring FINDBUDDY_RES from %s (status=%u)",
		               (LPCTSTR)CString(inet_ntoa(pHost->sin_addr)), (unsigned)st);
		break;
	}
}

void CKademlia::OnCallbackRequest(const SOCKADDR_IN* pHost, CEDPacket* pPacket)
{
	if (!pHost || !pPacket)
		return;

	const DWORD ipHost = ntohl(pHost->sin_addr.s_addr);
	const DWORD now = GetTickCount();
	// eMule InTrackListIsAllowedPacket: CALLBACK_REQ 1/min per IP.
	if (!m_inboundLimiter.Allow(ipHost, KAD_OP_CALLBACK_REQ, KAD_BUDDY_CALLBACK_PER_MINUTE, now))
	{
		theApp.Message(MSG_DEBUG, L"Kad2: CALLBACK_REQ rate-limited from %s",
		               (LPCTSTR)CString(inet_ntoa(pHost->sin_addr)));
		return;
	}

	KadCallbackReq req;
	if (KadParseCallbackReq(pPacket->GetCurrent(), pPacket->GetRemaining(), req) != KadBuddyParseStatus::Ok)
	{
		theApp.Message(MSG_DEBUG, L"Kad2: Ignoring malformed CALLBACK_REQ from %s",
		               (LPCTSTR)CString(inet_ntoa(pHost->sin_addr)));
		return;
	}

	KadCallbackRelayItem item;
	item.buddyIpHost = m_buddy.Buddy().ipHost;
	item.queuedAt = now;
	const KadBuddyRelayStatus st = m_buddy.OnCallbackRequest(ipHost, req, item.body);
	if (st != KadBuddyRelayStatus::Relay)
	{
		theApp.Message(MSG_DEBUG, L"Kad2: CALLBACK_REQ from %s not relayed (status=%u)",
		               (LPCTSTR)CString(inet_ntoa(pHost->sin_addr)), (unsigned)st);
		return;
	}

	// Bounded relay queue; the client layer delivers it over the bonded
	// buddy's TCP connection (eMule pBuddy->socket).
	if (m_pendingCallbackRelays.size() >= KAD_BUDDY_TRACK_MAX)
		m_pendingCallbackRelays.erase(m_pendingCallbackRelays.begin());
	m_pendingCallbackRelays.push_back(item);
	theApp.Message(MSG_DEBUG, L"Kad2: CALLBACK_REQ from %s queued for buddy relay",
	               (LPCTSTR)CString(inet_ntoa(pHost->sin_addr)));
}

void CKademlia::MaybeStartBuddySearch()
{
	// eMule ClientList.cpp: a buddy is sought when BOTH firewall tests report
	// firewalled, no buddy is bonded, and at least 20 minutes passed since
	// the last round. Contacts come from the verified routing pool.
	const DWORD now = GetTickCount();
	const bool tcpFirewalled = m_firewall.TcpState() == KadTcpFirewallState::Firewalled;
	const bool udpFirewalled = m_udpFirewall.IsFirewalledUdp(true);
	if (!m_buddy.WantsBuddySearch(now, tcpFirewalled, udpFirewalled))
		return;

	KadFwPeerCandidate chosen[KAD_BUDDY_REQ_CONTACTS_PER_ROUND];
	size_t nChosen = 0;
	CollectFirewallCheckCandidates(chosen, KAD_BUDDY_REQ_CONTACTS_PER_ROUND, nChosen);
	if (nChosen == 0)
		return;

	m_buddy.NoteBuddySearchRound(now);
	for (size_t i = 0; i < nChosen; ++i)
	{
		if (!m_buddy.BeginFindBuddyRequest(chosen[i].ipHost, now))
			continue;
		KadContact contact;
		contact.ip = chosen[i].ipHost;
		contact.udpPort = chosen[i].udpPort;
		contact.tcpPort = chosen[i].tcpPort;
		contact.version = chosen[i].version;
		contact.verified = chosen[i].verified ? TRUE : FALSE;
		contact.lastSeen = chosen[i].lastSeen;
		SendFindBuddyRequest(contact);
	}
}

void CKademlia::SendFindBuddyRequest(const KadContact& contact)
{
	if (!m_bInitialized)
		return;

	sockaddr_in addr;
	KadContactGetSockAddr(contact, addr);

	// <BuddyID 16 = own KadID XOR 0xFF..FF><ClientHash 16><TCPPort 2>
	// (eMule Search.cpp FINDBUDDY + ClientList.cpp lookup target). The
	// ClientHash is the canonical wire user hash SendHello emits, so the
	// responding buddy's HELLO matches what we advertised.
	BYTE body[KAD_BUDDY_REQ_MIN_SIZE];
	BYTE buddyId[KAD_ID_SIZE];
	KadKadIdToBuddyId(m_ownId, buddyId);
	BYTE clientHash[KAD_ID_SIZE];
	memcpy(clientHash, m_ownId, KAD_ID_SIZE);
	Ed2kHelloApplyGuidMutation(clientHash);
	KadBuildFindBuddyReq(body, buddyId, clientHash, (WORD)Settings.Connection.InPort);

	CEDPacket* pPacket = CEDPacket::New(KADEMLIA_FINDBUDDY_REQ, ED2K_PROTOCOL_KAD);
	if (!pPacket)
		return;
	pPacket->Write(body, KAD_BUDDY_REQ_MIN_SIZE);
	SendPacket(&addr, pPacket);
	pPacket->Release();

	theApp.Message(MSG_DEBUG, L"Kad2: FINDBUDDY_REQ to %s:%u (tcpPort=%u)",
	               (LPCTSTR)CString(inet_ntoa(addr.sin_addr)), ntohs(addr.sin_port),
	               (WORD)Settings.Connection.InPort);
}

void CKademlia::OnBuddyClientConnected(DWORD ipHost)
{
	CSingleLock oLock(&m_pKadSection, TRUE);
	const DWORD now = GetTickCount();
	const bool hadBuddy = m_buddy.HasConnectedBuddy();
	m_buddy.OnBuddyConnected(ipHost, now);
	if (!hadBuddy && m_buddy.HasConnectedBuddy())
		theApp.Message(MSG_DEBUG, L"Kad2: Buddy bond established with %u", ipHost);
}

void CKademlia::OnBuddyClientDisconnected(DWORD ipHost)
{
	CSingleLock oLock(&m_pKadSection, TRUE);
	if (!m_buddy.HasBuddyRecord() || m_buddy.Buddy().ipHost != ipHost)
		return;
	m_buddy.OnBuddyDisconnected();
	theApp.Message(MSG_DEBUG, L"Kad2: Buddy bond lost (%u)", ipHost);
}

bool CKademlia::IsIncomingBuddyEndpoint(DWORD ipHost)
{
	CSingleLock oLock(&m_pKadSection, TRUE);
	return m_buddy.HasBuddyRecord() && m_buddy.Buddy().ipHost == ipHost && !m_buddy.HasConnectedBuddy();
}

bool CKademlia::IsBondedBuddyEndpoint(DWORD ipHost)
{
	CSingleLock oLock(&m_pKadSection, TRUE);
	return m_buddy.HasConnectedBuddy() && m_buddy.Buddy().ipHost == ipHost;
}

bool CKademlia::TakePendingBuddyContact(KadBuddyRecord& out)
{
	CSingleLock oLock(&m_pKadSection, TRUE);
	if (!m_hasPendingBuddyConnect)
		return false;
	out = m_pendingBuddyConnect;
	m_hasPendingBuddyConnect = false;
	m_pendingBuddyConnect = KadBuddyRecord{};
	return true;
}

bool CKademlia::PeekPendingCallbackRelay(KadCallbackRelayItem& out, bool& expired, DWORD now)
{
	CSingleLock oLock(&m_pKadSection, TRUE);
	if (m_pendingCallbackRelays.empty())
		return false;
	out = m_pendingCallbackRelays.front();
	expired = KadTickElapsed(now, out.queuedAt, KAD_BUDDY_RELAY_RETAIN_MS);
	return true;
}

void CKademlia::PopPendingCallbackRelay()
{
	CSingleLock oLock(&m_pKadSection, TRUE);
	if (!m_pendingCallbackRelays.empty())
		m_pendingCallbackRelays.erase(m_pendingCallbackRelays.begin());
}
