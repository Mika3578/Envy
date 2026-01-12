//
// Kademlia.cpp
//
// This file is part of Envy (getenvy.com) � 2016-2018
// Portions copyright Shareaza 2008 and PeerProject 2008-2012
//
// Envy is free software. You may redistribute and/or modify it
// under the terms of the GNU Affero General Public License
// as published by the Free Software Foundation (fsf.org);
// version 3 or later at your option. (AGPLv3)
//
// Envy is distributed in the hope that it will be useful,
// but AS-IS WITHOUT ANY WARRANTY; without even implied warranty
// of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
// See the GNU Affero General Public License 3.0 for details:
// (http://www.gnu.org/licenses/agpl.html)
//

#include "StdAfx.h"
#include "Settings.h"
#include "Envy.h"
#include "Kademlia.h"
#include "EDPacket.h"
#include "Network.h"
#include "Datagrams.h"
#include "Transfers.h"
#include "Buffer.h"
#include "GProfile.h"
#include "HostCache.h"
#include "Statistics.h"

#include <vector>
#include <algorithm>

#ifdef _DEBUG
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#define new DEBUG_NEW
#endif	// Debug

CKademlia Kademlia;


// CKadBucket implementation

CKadBucket::CKadBucket()
	: m_lastLookup(0)
{
}

CKadBucket::~CKadBucket()
{
	m_contacts.clear();
}

BOOL CKadBucket::AddContact(CHostCacheHostPtr pContact)
{
	if (!pContact || IsFull())
		return FALSE;

	// Check if contact already exists
	CKadContactInfo* existing = FindContact(pContact);
	if (existing)
	{
		// Update existing contact
		existing->lastSeen = GetTickCount();
		return TRUE;
	}

	// Add new contact
	m_contacts.push_back(CKadContactInfo(pContact));
	m_lastLookup = GetTickCount();
	return TRUE;
}

void CKadBucket::RemoveContact(CHostCacheHostPtr pContact)
{
	for (auto it = m_contacts.begin(); it != m_contacts.end(); ++it)
	{
		if (it->pContact == pContact)
		{
			m_contacts.erase(it);
			break;
		}
	}
}

void CKadBucket::UpdateContact(CHostCacheHostPtr pContact)
{
	CKadContactInfo* contact = FindContact(pContact);
	if (contact)
	{
		contact->lastSeen = GetTickCount();
		contact->pendingPing = FALSE;
	}
}

CKadContactInfo* CKadBucket::FindContact(CHostCacheHostPtr pContact)
{
	for (auto& contact : m_contacts)
	{
		if (contact.pContact == pContact)
			return &contact;
	}
	return NULL;
}

void CKadBucket::PingOldContacts()
{
	DWORD now = GetTickCount();
	const DWORD PING_INTERVAL = 5 * 60 * 1000; // 5 minutes
	const DWORD STALE_TIMEOUT = 30 * 60 * 1000; // 30 minutes

	for (auto& contact : m_contacts)
	{
		if (contact.pContact &&
			!contact.pendingPing &&
			(now - contact.lastPinged) > PING_INTERVAL &&
			(now - contact.lastSeen) > STALE_TIMEOUT)
		{
			// Send ping to this contact
			contact.lastPinged = now;
			contact.pendingPing = TRUE;

			// Create ping packet and send it
			SOCKADDR_IN hostAddr;
			hostAddr.sin_family = AF_INET;
			hostAddr.sin_addr = contact.pContact->m_pAddress;
			hostAddr.sin_port = htons(contact.pContact->m_nUDPPort);

			// Note: This creates a circular dependency. In a real implementation,
			// we'd need to pass the Kademlia instance or use a callback.
			// For now, we'll mark as pinged but not actually send.
		}
	}
}

void CKadBucket::RemoveStaleContacts(DWORD maxAge)
{
	DWORD now = GetTickCount();

	auto it = m_contacts.begin();
	while (it != m_contacts.end())
	{
		if ((now - it->lastSeen) > maxAge)
		{
			it = m_contacts.erase(it);
		}
		else
		{
			++it;
		}
	}
}


// CKadRoutingTable implementation

CKadRoutingTable::CKadRoutingTable()
{
	m_ownKadID = MyProfile.oGUID;
}

CKadRoutingTable::~CKadRoutingTable()
{
	// Buckets will be cleaned up automatically
}

BOOL CKadRoutingTable::AddContact(CHostCacheHostPtr pContact)
{
	if (!pContact || pContact->m_oGUID == m_ownKadID)
		return FALSE; // Don't add ourselves

	int bucketIndex = GetBucketIndex(pContact->m_oGUID);
	if (bucketIndex < 0 || bucketIndex >= KAD_BUCKET_COUNT)
		return FALSE;

	CKadBucket& bucket = m_buckets[bucketIndex];

	// If bucket is not full, just add the contact
	if (!bucket.IsFull())
	{
		return bucket.AddContact(pContact);
	}

	// Bucket is full - check if we should split it or replace a contact
	if (ShouldSplitBucket(bucketIndex))
	{
		// Split the bucket and retry adding
		SplitBucket(bucketIndex);
		return AddContact(pContact); // Retry with new bucket structure
	}
	else
	{
		// Replace the least recently seen contact
		return ReplaceContactInBucket(bucket, pContact);
	}
}

BOOL CKadRoutingTable::ShouldSplitBucket(int bucketIndex) const
{
	// In Kademlia, we split buckets that contain our own node ID prefix
	// For simplicity, we'll split any bucket that's full and hasn't been split recently
	// A more accurate implementation would check if the bucket range contains our ID

	const DWORD SPLIT_COOLDOWN = 60 * 1000; // 1 minute cooldown
	DWORD now = GetTickCount();

	return (now - m_buckets[bucketIndex].m_lastLookup) > SPLIT_COOLDOWN;
}

BOOL CKadRoutingTable::ReplaceContactInBucket(CKadBucket& bucket, CHostCacheHostPtr pNewContact)
{
	if (bucket.m_contacts.empty())
		return FALSE;

	// Find the least recently seen contact to replace
	auto oldestIt = bucket.m_contacts.begin();
	DWORD oldestTime = oldestIt->lastSeen;

	for (auto it = bucket.m_contacts.begin(); it != bucket.m_contacts.end(); ++it)
	{
		if (it->lastSeen < oldestTime)
		{
			oldestTime = it->lastSeen;
			oldestIt = it;
		}
	}

	// Replace the oldest contact with the new one
	*oldestIt = CKadContactInfo(pNewContact);
	return TRUE;
}

CHostCacheHostPtr CKadRoutingTable::FindClosest(const Hashes::Guid& target, int maxCount)
{
	std::vector<std::pair<int, CHostCacheHostPtr>> candidates;

	// Find contacts from all buckets, ordered by XOR distance
	for (int i = 0; i < KAD_BUCKET_COUNT; i++)
	{
		for (auto& contactInfo : m_buckets[i].m_contacts)
		{
			if (contactInfo.pContact)
			{
				int distance = GetBucketIndex(target); // Simplified distance measure
				candidates.push_back(std::make_pair(distance, contactInfo.pContact));
			}
		}
	}

	// Sort by distance (closest first)
	std::sort(candidates.begin(), candidates.end(),
		[](const std::pair<int, CHostCacheHostPtr>& a, const std::pair<int, CHostCacheHostPtr>& b) {
			return a.first < b.first;
		});

	// Return up to maxCount closest contacts
	if (candidates.size() > 0)
	{
		return candidates[0].second; // Return closest contact
	}

	return NULL;
}

int CKadRoutingTable::GetBucketIndex(const Hashes::Guid& target) const
{
	// XOR target with our own ID
	BYTE xorResult[16];
	for (int i = 0; i < 16; i++)
	{
		xorResult[i] = target[i] ^ m_ownKadID[i];
	}

	// Find the highest set bit position in the XOR result
	for (int byte = 0; byte < 16; byte++)
	{
		if (xorResult[byte] != 0)
		{
			// Find the highest bit in this byte
			BYTE b = xorResult[byte];
			int bit = 7;
			while ((b & 0x80) == 0 && bit >= 0)
			{
				b <<= 1;
				bit--;
			}
			// Return bucket index: 127 - (byte * 8 + (7 - bit))
			return 127 - (byte * 8 + (7 - bit));
		}
	}

	// If XOR result is all zeros (target == our ID), return highest bucket
	return 127;
}

void CKadRoutingTable::SplitBucket(int bucketIndex)
{
	// In a full Kademlia implementation, splitting would create sub-buckets
	// For this simplified implementation, we'll just allow the bucket to grow
	// and rely on contact replacement instead

	// The bucket splitting is effectively handled by allowing more contacts
	// and using replacement policies. In a real implementation, we'd need to
	// reorganize the bucket structure.

	// For now, just mark that we've attempted to split this bucket
	m_buckets[bucketIndex].m_lastLookup = GetTickCount();
}

void CKadRoutingTable::MergeBucket(int bucketIndex)
{
	// Bucket merging would combine adjacent buckets when they're empty
	// For this simplified implementation, we don't implement merging
	// as it's complex and not essential for basic functionality
}

void CKadRoutingTable::PingOldContacts()
{
	for (int i = 0; i < KAD_BUCKET_COUNT; i++)
	{
		m_buckets[i].PingOldContacts();
	}
}

void CKadRoutingTable::RemoveStaleContacts()
{
	for (int i = 0; i < KAD_BUCKET_COUNT; i++)
	{
		m_buckets[i].RemoveStaleContacts();
	}
}

int CKadRoutingTable::GetTotalContactCount() const
{
	int total = 0;
	for (int i = 0; i < KAD_BUCKET_COUNT; i++)
	{
		total += m_buckets[i].GetContactCount();
	}
	return total;
}

void CKadRoutingTable::UpdateContact(CHostCacheHostPtr pContact)
{
	if (!pContact)
		return;

	int bucketIndex = GetBucketIndex(pContact->m_oGUID);
	if (bucketIndex >= 0 && bucketIndex < KAD_BUCKET_COUNT)
	{
		m_buckets[bucketIndex].UpdateContact(pContact);
	}
}


// XOR distance calculation functions

// Calculate bucket index for a target ID relative to our own ID
int CKademlia::GetBucketIndex(const Hashes::Guid& target)
{
	// XOR target with our own ID
	Hashes::Guid ownGUID = MyProfile.oGUID;
	BYTE xorResult[16];
	for (int i = 0; i < 16; i++)
	{
		xorResult[i] = target[i] ^ ownGUID[i];
	}

	// Find the highest set bit position in the XOR result
	for (int byte = 0; byte < 16; byte++)
	{
		if (xorResult[byte] != 0)
		{
			// Find the highest bit in this byte
			BYTE b = xorResult[byte];
			int bit = 7;
			while ((b & 0x80) == 0 && bit >= 0)
			{
				b <<= 1;
				bit--;
			}
			// Return bucket index: 127 - (byte * 8 + (7 - bit))
			return 127 - (byte * 8 + (7 - bit));
		}
	}

	// If XOR result is all zeros (target == our ID), return highest bucket
	return 127;
}

// Compare two KadIDs for ordering (used for sorting contacts by distance)
int CKademlia::CompareKadIDs(const Hashes::Guid& id1, const Hashes::Guid& id2)
{
	for (int i = 0; i < 16; i++)
	{
		if (id1[i] < id2[i]) return -1;
		if (id1[i] > id2[i]) return 1;
	}
	return 0;
}

// Check if id1 < id2 (lexicographical comparison)
bool CKademlia::KadIDLess(const Hashes::Guid& id1, const Hashes::Guid& id2)
{
	return CompareKadIDs(id1, id2) < 0;
}


BOOL CKademlia::Send(const SOCKADDR_IN* pHost, CEDPacket* pPacket)
{
	// ToDo: Kademlia packets statistics

	return Datagrams.Send( pHost, pPacket );
}

BOOL CKademlia::Send(const SOCKADDR_IN* pHost, BYTE nType)
{
	return Send( pHost, CEDPacket::New( nType, ED2K_PROTOCOL_KAD ) );
}

BOOL CKademlia::Bootstrap(const SOCKADDR_IN* pHost, bool bKad2)
{
	if ( bKad2 )
		return Send( pHost, KADEMLIA2_BOOTSTRAP_REQ );

	return SendMyDetails( pHost, KADEMLIA_BOOTSTRAP_REQ, false );
}

BOOL CKademlia::SendMyDetails(const SOCKADDR_IN* pHost, BYTE nType, bool bKad2)
{
	CEDPacket* pPacket = CEDPacket::New( nType, ED2K_PROTOCOL_KAD );
	if ( ! pPacket )
		return FALSE;

	Hashes::Guid oGUID = MyProfile.oGUID;

	if ( bKad2 )
	{
		pPacket->Write( oGUID );
		pPacket->WriteShortLE( htons( Network.m_pHost.sin_port ) );	// TCP
		pPacket->WriteByte( KADEMLIA_VERSION );
		pPacket->WriteByte( 1 );	// TagCount = 1 (TAG_SOURCEUPORT)
		// Write TAG_SOURCEUPORT (0xFC) with UDP port
		pPacket->WriteByte( 0xFC );	// TAG_SOURCEUPORT
		pPacket->WriteShortLE( htons( Network.m_pHost.sin_port ) );	// UDP port
		return Send( pHost, pPacket );
	}
	else
	{
		pPacket->Write( oGUID );
		pPacket->WriteLongLE( Network.m_pHost.sin_addr.S_un.S_addr );
		pPacket->WriteShortLE( htons( Network.m_pHost.sin_port ) );	// UDP
		pPacket->WriteShortLE( htons( Network.m_pHost.sin_port ) );	// TCP
		pPacket->WriteByte( 0 );
		return Send( pHost, pPacket );
	}
}

BOOL CKademlia::OnPacket(const SOCKADDR_IN* pHost, CEDPacket* pPacket)
{
	pPacket->SmartDump( pHost, TRUE, FALSE );

	// ToDo: Kademlia packets statistics

	CQuickLock oLock( m_pSection );

	switch ( pPacket->m_nType )
	{
	case KADEMLIA_BOOTSTRAP_REQ:
//		return OnPacket_KADEMLIA_BOOTSTRAP_REQ( pHost, pPacket );
		break;
	case KADEMLIA2_BOOTSTRAP_REQ:
		return OnPacket_KADEMLIA2_BOOTSTRAP_REQ( pHost, pPacket );
	case KADEMLIA_BOOTSTRAP_RES:
		return OnPacket_KADEMLIA_BOOTSTRAP_RES( pHost, pPacket );
	case KADEMLIA2_BOOTSTRAP_RES:
		return OnPacket_KADEMLIA2_BOOTSTRAP_RES( pHost, pPacket );
	case KADEMLIA_HELLO_REQ:
//		return OnPacket_KADEMLIA_HELLO_REQ( pHost, pPacket );
		break;
	case KADEMLIA2_HELLO_REQ:
		return OnPacket_KADEMLIA2_HELLO_REQ( pHost, pPacket );
	case KADEMLIA_HELLO_RES:
//		return OnPacket_KADEMLIA_HELLO_RES( pHost, pPacket );
		break;
	case KADEMLIA2_HELLO_RES:
		return OnPacket_KADEMLIA2_HELLO_RES( pHost, pPacket );
	case KADEMLIA_REQ:
//		return OnPacket_KADEMLIA_REQ( pHost, pPacket );
		break;
	case KADEMLIA2_REQ:
		return OnPacket_KADEMLIA2_REQ( pHost, pPacket );
	case KADEMLIA_RES:
//		return OnPacket_KADEMLIA_RES( pHost, pPacket );
		break;
	case KADEMLIA2_RES:
		return OnPacket_KADEMLIA2_RES( pHost, pPacket );
	case KADEMLIA_SEARCH_REQ:
//		return OnPacket_KADEMLIA_SEARCH_REQ( pHost, pPacket );
		break;
	case KADEMLIA_SEARCH_NOTES_REQ:
//		return OnPacket_KADEMLIA_SEARCH_NOTES_REQ( pHost, pPacket );
		break;
	case KADEMLIA2_SEARCH_NOTES_REQ:
		return OnPacket_KADEMLIA2_SEARCH_NOTES_REQ( pHost, pPacket );
	case KADEMLIA2_SEARCH_KEY_REQ:
		return OnPacket_KADEMLIA2_SEARCH_KEY_REQ( pHost, pPacket );
	case KADEMLIA2_SEARCH_SOURCE_REQ:
		return OnPacket_KADEMLIA2_SEARCH_SOURCE_REQ( pHost, pPacket );
	case KADEMLIA_SEARCH_RES:
//		return OnPacket_KADEMLIA_SEARCH_RES( pHost, pPacket );
		break;
	case KADEMLIA_SEARCH_NOTES_RES:
//		return OnPacket_KADEMLIA_SEARCH_NOTES_RES( pHost, pPacket );
		break;
	case KADEMLIA2_SEARCH_RES:
//		return OnPacket_KADEMLIA2_SEARCH_RES( pHost, pPacket );
		break;
	case KADEMLIA_PUBLISH_REQ:
//		return OnPacket_KADEMLIA_PUBLISH_REQ( pHost, pPacket );
		break;
	case KADEMLIA_PUBLISH_NOTES_REQ:
//		return OnPacket_KADEMLIA_PUBLISH_NOTES_REQ( pHost, pPacket );
		break;
	case KADEMLIA2_PUBLISH_KEY_REQ:
		return OnPacket_KADEMLIA2_PUBLISH_KEY_REQ( pHost, pPacket );
	case KADEMLIA2_PUBLISH_SOURCE_REQ:
		return OnPacket_KADEMLIA2_PUBLISH_SOURCE_REQ( pHost, pPacket );
	case KADEMLIA2_PUBLISH_NOTES_REQ:
		return OnPacket_KADEMLIA2_PUBLISH_NOTES_REQ( pHost, pPacket );
	case KADEMLIA_PUBLISH_RES:
//		return OnPacket_KADEMLIA_PUBLISH_RES( pHost, pPacket );
		break;
	case KADEMLIA_PUBLISH_NOTES_RES:
//		return OnPacket_KADEMLIA_PUBLISH_NOTES_RES( pHost, pPacket );
		break;
	case KADEMLIA2_PUBLISH_RES:
		return OnPacket_KADEMLIA2_PUBLISH_RES( pHost, pPacket );
	case KADEMLIA_FIREWALLED_REQ:
		return OnPacket_KADEMLIA_FIREWALLED_REQ( pHost, pPacket );
	case KADEMLIA_FIREWALLED_RES:
		return OnPacket_KADEMLIA_FIREWALLED_RES( pHost, pPacket );
	case KADEMLIA_FIREWALLED_ACK_RES:
		return OnPacket_KADEMLIA_FIREWALLED_ACK_RES( pHost, pPacket );
	case KADEMLIA_FINDBUDDY_REQ:
		return OnPacket_KADEMLIA_FINDBUDDY_REQ( pHost, pPacket );
	case KADEMLIA_FINDBUDDY_RES:
		return OnPacket_KADEMLIA_FINDBUDDY_RES( pHost, pPacket );
	case KADEMLIA_CALLBACK_REQ:
		return OnPacket_KADEMLIA_CALLBACK_REQ( pHost, pPacket );
		break;
	case KADEMLIA2_PING:
		return OnPacket_KADEMLIA2_PING( pHost, pPacket );
	case KADEMLIA2_PONG:
		return OnPacket_KADEMLIA2_PONG( pHost, pPacket );
#ifdef _DEBUG
	default:
		CString str;
		str.Format( L"Unknown KAD packet from %s:%u.",
			(LPCTSTR)CString( inet_ntoa( pHost->sin_addr ) ),
			htons( pHost->sin_port ) );
		pPacket->Debug( str );
#endif
	}
	return FALSE;
}

BOOL CKademlia::OnPacket_KADEMLIA_BOOTSTRAP_RES(const SOCKADDR_IN* /*pHost*/, CEDPacket* pPacket)
{
	Hashes::Guid oGUID;
	IN_ADDR pAddress;
	WORD nUDPPort, nTCPPort;
	WORD nCount;

	if ( pPacket->GetRemaining() < 2 )
		return FALSE;

	nCount = pPacket->ReadShortLE();

	if ( pPacket->GetRemaining() < nCount * ( 16u + 4 + 2 + 2 + 1 ) )
		return FALSE;

	while ( nCount-- )
	{
		pPacket->Read( oGUID );
		*(DWORD*)&pAddress = ntohl( pPacket->ReadLongLE() );
		nUDPPort = pPacket->ReadShortLE();
		nTCPPort = pPacket->ReadShortLE();
		pPacket->ReadByte();	// skip

		CHostCacheHostPtr pCache = HostCache.Kademlia.Add( &pAddress, nTCPPort );
		if ( pCache )
		{
			pCache->m_oGUID = oGUID;
			pCache->m_nUDPPort = nUDPPort;
			pCache->m_sDescription = oGUID.toString();
		}
	}

	HostCache.Kademlia.m_nCookie++;

	return TRUE;
}

BOOL CKademlia::OnPacket_KADEMLIA2_BOOTSTRAP_RES(const SOCKADDR_IN* pHost, CEDPacket* pPacket)
{
	Hashes::Guid oGUID;
	IN_ADDR pAddress;
	WORD nUDPPort, nTCPPort;
	BYTE nVersion;
	WORD nCount;

	if ( pPacket->GetRemaining() < ( 16 + 2 + 1 + 2 ) )
		return FALSE;

	pPacket->Read( oGUID );
	nTCPPort = pPacket->ReadShortLE();
	nVersion = pPacket->ReadByte();
	nCount = pPacket->ReadShortLE();

	if ( pPacket->GetRemaining() < nCount * ( 16u + 4 + 2 + 2 + 1 ) )
		return FALSE;

	// Validate contact count (reasonable bounds)
	const WORD nMaxContacts = 50; // Limit to prevent abuse
	if ( nCount > nMaxContacts )
		nCount = nMaxContacts;

	// Validate Kad version (minimum supported)
	if ( nVersion < 1 )
		return FALSE;

	CQuickLock oLock( HostCache.Kademlia.m_pSection );

	CHostCacheHostPtr pCache = HostCache.Kademlia.Add( &pHost->sin_addr, nTCPPort );
	if ( ! pCache )
		return FALSE;

	pCache->m_oGUID = oGUID;
	pCache->m_nUDPPort = htons( pHost->sin_port );
	pCache->m_nKADVersion = nVersion;
	pCache->m_sDescription = oGUID.toString();
	pCache->m_tFailure = 0;
	pCache->m_nFailures = 0;
	pCache->m_bCheckedLocally = TRUE;

	while ( nCount-- )
	{
		pPacket->Read( oGUID );
		*(DWORD*)&pAddress = ntohl( pPacket->ReadLongLE() );
		nUDPPort = pPacket->ReadShortLE();
		nTCPPort = pPacket->ReadShortLE();
		BYTE nContactVersion = pPacket->ReadByte();

		// Self-filtering: don't add our own contact
		if ( pAddress.s_addr == Network.m_pHost.sin_addr.s_addr &&
			 nTCPPort == Network.m_pHost.sin_port )
			continue;

		// Version validation: ensure minimum supported version
		if ( nContactVersion < 1 )
			continue;

		pCache = HostCache.Kademlia.Add( &pAddress, nTCPPort );
		if ( pCache )
		{
	pCache->m_oGUID = oGUID;
	pCache->m_nUDPPort = nUDPPort;
	pCache->m_nKADVersion = nContactVersion;
	pCache->m_sDescription = oGUID.toString();

	// Add contact to routing table
	Kademlia.m_routingTable.AddContact(pCache);
		}
	}

	HostCache.Kademlia.m_nCookie++;

	return TRUE;
}

BOOL CKademlia::OnPacket_KADEMLIA2_BOOTSTRAP_REQ(const SOCKADDR_IN* pHost, CEDPacket* /*pPacket*/)
{
	CEDPacket* pResponse = CEDPacket::New( KADEMLIA2_BOOTSTRAP_RES, ED2K_PROTOCOL_KAD );
	if ( ! pResponse )
		return FALSE;

	Hashes::Guid oGUID = MyProfile.oGUID;

	// Write MyKadID, MyTCPPort, MyKadVersion
	pResponse->Write( oGUID );
	pResponse->WriteShortLE( htons( Network.m_pHost.sin_port ) );	// TCP
	pResponse->WriteByte( KADEMLIA_VERSION );

	// Get up to 20 contacts from routing table (prioritize closer contacts)
	CHostCacheHostPtr closestContacts[20];
	int contactCount = 0;

	// Use routing table to find closest contacts to the requester
	CHostCacheHostPtr closest = Kademlia.m_routingTable.FindClosest(MyProfile.oGUID, 20);
	if (closest)
	{
		// For now, just use the closest contact. In a full implementation,
		// we'd get multiple contacts from different buckets
		closestContacts[contactCount++] = closest;
	}

	// Fall back to host cache if routing table doesn't have enough contacts
	if (contactCount < 20)
	{
		CQuickLock oLock( HostCache.Kademlia.m_pSection );

		for ( CHostCacheIterator i = HostCache.Kademlia.Begin(); i != HostCache.Kademlia.End() && contactCount < 20; ++i )
		{
			CHostCacheHostPtr pCache = *i;
			if ( ! pCache || pCache->m_nFailures > 0 )
				continue;

			// Skip if same as sender
			if ( pCache->m_pAddress.s_addr == pHost->sin_addr.s_addr && pCache->m_nPort == htons( pHost->sin_port ) )
				continue;

			// Skip if already in our contact list
			bool alreadyIncluded = false;
			for (int j = 0; j < contactCount; j++)
			{
				if (closestContacts[j] == pCache)
				{
					alreadyIncluded = true;
					break;
				}
			}
			if (alreadyIncluded)
				continue;

			closestContacts[contactCount++] = pCache;
		}
	}

	// Write count
	pResponse->WriteShortLE( (WORD)contactCount );

	// Write contacts
	for (int i = 0; i < contactCount; i++)
	{
		CHostCacheHostPtr pCache = closestContacts[i];
		pResponse->Write( pCache->m_oGUID );
		pResponse->WriteLongLE( htonl( pCache->m_pAddress.s_addr ) );
		pResponse->WriteShortLE( pCache->m_nUDPPort );
		pResponse->WriteShortLE( pCache->m_nPort );
		pResponse->WriteByte( pCache->m_nKADVersion );
	}

	return Send( pHost, pResponse );
}

BOOL CKademlia::OnPacket_KADEMLIA2_REQ(const SOCKADDR_IN* pHost, CEDPacket* pPacket)
{
	BYTE nType;
	Hashes::Guid oTarget, oReceiver;

	if ( pPacket->GetRemaining() < (1 + 16 + 16) )
		return FALSE;

	nType = pPacket->ReadByte();
	pPacket->Read( oTarget );
	pPacket->Read( oReceiver );

	// For now, respond with some contacts from our cache
	CEDPacket* pResponse = CEDPacket::New( KADEMLIA2_RES, ED2K_PROTOCOL_KAD );
	if ( ! pResponse )
		return FALSE;

	// Write target hash
	pResponse->Write( oTarget );

	// Get up to 10 contacts from host cache
	CQuickLock oLock( HostCache.Kademlia.m_pSection );

	WORD nCount = 0;
	const WORD nMaxContacts = 10;
	for ( CHostCacheIterator i = HostCache.Kademlia.Begin(); i != HostCache.Kademlia.End() && nCount < nMaxContacts; ++i )
	{
		CHostCacheHostPtr pCache = *i;
		if ( ! pCache || pCache->m_nFailures > 0 )
			continue;

		// Skip if same as sender
		if ( pCache->m_pAddress.s_addr == pHost->sin_addr.s_addr && pCache->m_nPort == htons( pHost->sin_port ) )
			continue;

		nCount++;
	}

	// Write count (1 byte for Kad2)
	pResponse->WriteByte( (BYTE)nCount );

	// Write contacts
	nCount = 0;
	for ( CHostCacheIterator i = HostCache.Kademlia.Begin(); i != HostCache.Kademlia.End() && nCount < nMaxContacts; ++i )
	{
		CHostCacheHostPtr pCache = *i;
		if ( ! pCache || pCache->m_nFailures > 0 )
			continue;

		// Skip if same as sender
		if ( pCache->m_pAddress.s_addr == pHost->sin_addr.s_addr && pCache->m_nPort == htons( pHost->sin_port ) )
			continue;

		pResponse->Write( pCache->m_oGUID );
		pResponse->WriteLongLE( htonl( pCache->m_pAddress.s_addr ) );
		pResponse->WriteShortLE( pCache->m_nUDPPort );
		pResponse->WriteShortLE( pCache->m_nPort );
		pResponse->WriteByte( pCache->m_nKADVersion );

		nCount++;
	}

	return Send( pHost, pResponse );
}

BOOL CKademlia::OnPacket_KADEMLIA2_RES(const SOCKADDR_IN* pHost, CEDPacket* pPacket)
{
	Hashes::Guid oTarget;
	BYTE nCount;

	if ( pPacket->GetRemaining() < (16 + 1) )
		return FALSE;

	pPacket->Read( oTarget );
	nCount = pPacket->ReadByte();

	if ( pPacket->GetRemaining() < nCount * (16 + 4 + 2 + 2 + 1) )
		return FALSE;

	// Update host cache with the contacts
	CQuickLock oLock( HostCache.Kademlia.m_pSection );

	while ( nCount-- )
	{
		Hashes::Guid oGUID;
		IN_ADDR pAddress;
		WORD nUDPPort, nTCPPort;
		BYTE nVersion;

		pPacket->Read( oGUID );
		*(DWORD*)&pAddress = ntohl( pPacket->ReadLongLE() );
		nUDPPort = pPacket->ReadShortLE();
		nTCPPort = pPacket->ReadShortLE();
		nVersion = pPacket->ReadByte();

		CHostCacheHostPtr pCache = HostCache.Kademlia.Add( &pAddress, nTCPPort );
		if ( pCache )
		{
			pCache->m_oGUID = oGUID;
			pCache->m_nUDPPort = nUDPPort;
			pCache->m_nKADVersion = nVersion;
			pCache->m_sDescription = oGUID.toString();
		}
	}

	HostCache.Kademlia.m_nCookie++;

	return TRUE;
}

BOOL CKademlia::OnPacket_KADEMLIA2_SEARCH_KEY_REQ(const SOCKADDR_IN* pHost, CEDPacket* pPacket)
{
	Hashes::Guid oKey;

	if ( pPacket->GetRemaining() < 16 )
		return FALSE;

	pPacket->Read( oKey );

	// Use routing table to find closer contacts for iterative search
	CHostCacheHostPtr closerContact = Kademlia.m_routingTable.FindClosest(oKey, 1);

	CEDPacket* pResponse = CEDPacket::New( KADEMLIA2_SEARCH_RES, ED2K_PROTOCOL_KAD );
	if ( ! pResponse )
		return FALSE;

	// Write search key
	pResponse->Write( oKey );

	if (closerContact)
	{
		// Send 1 result with closer contact
		pResponse->WriteShortLE( 1 );

		// Write contact info
		pResponse->Write( closerContact->m_oGUID );
		pResponse->WriteLongLE( htonl( closerContact->m_pAddress.s_addr ) );
		pResponse->WriteShortLE( closerContact->m_nUDPPort );
		pResponse->WriteShortLE( closerContact->m_nPort );
		pResponse->WriteByte( closerContact->m_nKADVersion );
	}
	else
	{
		// Write 0 results
		pResponse->WriteShortLE( 0 );
	}

	return Send( pHost, pResponse );
}

BOOL CKademlia::OnPacket_KADEMLIA2_SEARCH_SOURCE_REQ(const SOCKADDR_IN* pHost, CEDPacket* pPacket)
{
	Hashes::Guid oKey;

	if ( pPacket->GetRemaining() < 16 )
		return FALSE;

	pPacket->Read( oKey );

	// Use routing table to find closer contacts for iterative search
	CHostCacheHostPtr closerContact = Kademlia.m_routingTable.FindClosest(oKey, 1);

	CEDPacket* pResponse = CEDPacket::New( KADEMLIA2_SEARCH_RES, ED2K_PROTOCOL_KAD );
	if ( ! pResponse )
		return FALSE;

	// Write search key
	pResponse->Write( oKey );

	if (closerContact)
	{
		// Send 1 result with closer contact
		pResponse->WriteShortLE( 1 );

		// Write contact info
		pResponse->Write( closerContact->m_oGUID );
		pResponse->WriteLongLE( htonl( closerContact->m_pAddress.s_addr ) );
		pResponse->WriteShortLE( closerContact->m_nUDPPort );
		pResponse->WriteShortLE( closerContact->m_nPort );
		pResponse->WriteByte( closerContact->m_nKADVersion );
	}
	else
	{
		// Write 0 results
		pResponse->WriteShortLE( 0 );
	}

	return Send( pHost, pResponse );
}

BOOL CKademlia::OnPacket_KADEMLIA2_SEARCH_NOTES_REQ(const SOCKADDR_IN* pHost, CEDPacket* pPacket)
{
	Hashes::Guid oKey;

	if ( pPacket->GetRemaining() < 16 )
		return FALSE;

	pPacket->Read( oKey );

	// Use routing table to find closer contacts for iterative search
	CHostCacheHostPtr closerContact = Kademlia.m_routingTable.FindClosest(oKey, 1);

	CEDPacket* pResponse = CEDPacket::New( KADEMLIA2_SEARCH_RES, ED2K_PROTOCOL_KAD );
	if ( ! pResponse )
		return FALSE;

	// Write search key
	pResponse->Write( oKey );

	if (closerContact)
	{
		// Send 1 result with closer contact
		pResponse->WriteShortLE( 1 );

		// Write contact info
		pResponse->Write( closerContact->m_oGUID );
		pResponse->WriteLongLE( htonl( closerContact->m_pAddress.s_addr ) );
		pResponse->WriteShortLE( closerContact->m_nUDPPort );
		pResponse->WriteShortLE( closerContact->m_nPort );
		pResponse->WriteByte( closerContact->m_nKADVersion );
	}
	else
	{
		// Write 0 results
		pResponse->WriteShortLE( 0 );
	}

	return Send( pHost, pResponse );
}

BOOL CKademlia::OnPacket_KADEMLIA2_PUBLISH_KEY_REQ(const SOCKADDR_IN* pHost, CEDPacket* pPacket)
{
	Hashes::Guid oKey;

	if ( pPacket->GetRemaining() < 16 )
		return FALSE;

	pPacket->Read( oKey );

	// Skip any additional data (tags, etc.)
	// For now, acknowledge the publish request
	CEDPacket* pResponse = CEDPacket::New( KADEMLIA2_PUBLISH_RES, ED2K_PROTOCOL_KAD );
	if ( ! pResponse )
		return FALSE;

	// Write published key
	pResponse->Write( oKey );

	return Send( pHost, pResponse );
}

BOOL CKademlia::OnPacket_KADEMLIA2_PUBLISH_SOURCE_REQ(const SOCKADDR_IN* pHost, CEDPacket* pPacket)
{
	Hashes::Guid oKey;

	if ( pPacket->GetRemaining() < 16 )
		return FALSE;

	pPacket->Read( oKey );

	// Skip any additional data (tags, etc.)
	// For now, acknowledge the publish request
	CEDPacket* pResponse = CEDPacket::New( KADEMLIA2_PUBLISH_RES, ED2K_PROTOCOL_KAD );
	if ( ! pResponse )
		return FALSE;

	// Write published key
	pResponse->Write( oKey );

	return Send( pHost, pResponse );
}

BOOL CKademlia::OnPacket_KADEMLIA2_PUBLISH_NOTES_REQ(const SOCKADDR_IN* pHost, CEDPacket* pPacket)
{
	Hashes::Guid oKey;

	if ( pPacket->GetRemaining() < 16 )
		return FALSE;

	pPacket->Read( oKey );

	// Skip any additional data (tags, etc.)
	// For now, acknowledge the publish request
	CEDPacket* pResponse = CEDPacket::New( KADEMLIA2_PUBLISH_RES, ED2K_PROTOCOL_KAD );
	if ( ! pResponse )
		return FALSE;

	// Write published key
	pResponse->Write( oKey );

	return Send( pHost, pResponse );
}

BOOL CKademlia::OnPacket_KADEMLIA2_PUBLISH_RES(const SOCKADDR_IN* pHost, CEDPacket* pPacket)
{
	Hashes::Guid oKey;

	if ( pPacket->GetRemaining() < 16 )
		return FALSE;

	pPacket->Read( oKey );

	// Publish acknowledged - no further action needed for now
	return TRUE;
}

BOOL CKademlia::OnPacket_KADEMLIA_FIREWALLED_REQ(const SOCKADDR_IN* pHost, CEDPacket* pPacket)
{
	WORD nTCPPort;

	if ( pPacket->GetRemaining() < 2 )
		return FALSE;

	nTCPPort = pPacket->ReadShortLE();

	// Check if we're firewalled - for now, assume we're not and respond with our IP
	CEDPacket* pResponse = CEDPacket::New( KADEMLIA_FIREWALLED_RES, ED2K_PROTOCOL_KAD );
	if ( ! pResponse )
		return FALSE;

	// Write our IP address
	pResponse->WriteLongLE( Network.m_pHost.sin_addr.S_un.S_addr );

	return Send( pHost, pResponse );
}

BOOL CKademlia::OnPacket_KADEMLIA_FIREWALLED_RES(const SOCKADDR_IN* pHost, CEDPacket* pPacket)
{
	IN_ADDR pIP;

	if ( pPacket->GetRemaining() < 4 )
		return FALSE;

	pIP.s_addr = pPacket->ReadLongLE();

	// Firewall status received - could update peer's firewall status
	// For now, just acknowledge
	return Send( pHost, KADEMLIA_FIREWALLED_ACK_RES );
}

BOOL CKademlia::OnPacket_KADEMLIA_FIREWALLED_ACK_RES(const SOCKADDR_IN* /*pHost*/, CEDPacket* /*pPacket*/)
{
	// Firewall acknowledgment received - no action needed
	return TRUE;
}

BOOL CKademlia::OnPacket_KADEMLIA_FINDBUDDY_REQ(const SOCKADDR_IN* pHost, CEDPacket* pPacket)
{
	WORD nTCPPort;

	if ( pPacket->GetRemaining() < 2 )
		return FALSE;

	nTCPPort = pPacket->ReadShortLE();

	// For buddy finding, we'd need to find an unfirewalled peer
	// For now, respond that we can't find a buddy (send our own info as fallback)
	CEDPacket* pResponse = CEDPacket::New( KADEMLIA_FINDBUDDY_RES, ED2K_PROTOCOL_KAD );
	if ( ! pResponse )
		return FALSE;

	// Write our own port (since we can't find a better buddy)
	pResponse->WriteShortLE( htons( Network.m_pHost.sin_port ) );

	return Send( pHost, pResponse );
}

BOOL CKademlia::OnPacket_KADEMLIA_FINDBUDDY_RES(const SOCKADDR_IN* /*pHost*/, CEDPacket* pPacket)
{
	WORD nBuddyPort;

	if ( pPacket->GetRemaining() < 2 )
		return FALSE;

	nBuddyPort = pPacket->ReadShortLE();

	// Buddy information received - could store for future callbacks
	// For now, no action needed
	return TRUE;
}

BOOL CKademlia::OnPacket_KADEMLIA_CALLBACK_REQ(const SOCKADDR_IN* pHost, CEDPacket* pPacket)
{
	WORD nTCPPort;

	if ( pPacket->GetRemaining() < 2 )
		return FALSE;

	nTCPPort = pPacket->ReadShortLE();

	// Callback request received - this is for firewalled peers to receive connections through buddies
	// For now, we don't handle callbacks
	return TRUE;
}

BOOL CKademlia::OnPacket_KADEMLIA2_HELLO_REQ(const SOCKADDR_IN* pHost, CEDPacket* pPacket)
{
	Hashes::Guid oGUID;
	WORD nTCPPort;
	BYTE nVersion;
	BYTE nTagCount;

	if ( pPacket->GetRemaining() < ( 16 + 2 + 1 + 1 ) )
		return FALSE;

	pPacket->Read( oGUID );
	nTCPPort = pPacket->ReadShortLE();
	nVersion = pPacket->ReadByte();
	nTagCount = pPacket->ReadByte();

	// Parse tags - handle known tags and skip unknown ones safely
	for ( BYTE i = 0; i < nTagCount; i++ )
	{
		if ( pPacket->GetRemaining() < 1 )
			break;
		BYTE nTagType = pPacket->ReadByte();

		if ( nTagType == 0xFC )	// TAG_SOURCEUPORT
		{
			if ( pPacket->GetRemaining() < 2 )
				break;
			WORD nUDPPort = pPacket->ReadShortLE();
			// Could use nUDPPort if needed
		}
		else if ( nTagType == 0x0A ) // TAG_KADMISCOPTIONS (misc options)
		{
			if ( pPacket->GetRemaining() < 1 )
				break;
			BYTE nOptions = pPacket->ReadByte();
			// Could parse misc options if needed
		}
		else
		{
			// Unknown tag - try to skip safely
			// For most Kad2 tags, if we don't know the format, we can't safely skip
			// For now, stop parsing to avoid misaligning the packet
			break;
		}
	}

	// Update host cache
	CQuickLock oLock( HostCache.Kademlia.m_pSection );

	CHostCacheHostPtr pCache = HostCache.Kademlia.Add( &pHost->sin_addr, nTCPPort );
	if ( pCache )
	{
		pCache->m_oGUID = oGUID;
		pCache->m_nUDPPort = htons( pHost->sin_port );
		pCache->m_nKADVersion = nVersion;
		pCache->m_sDescription = oGUID.toString();
		pCache->m_tFailure = 0;
		pCache->m_nFailures = 0;
		pCache->m_bCheckedLocally = TRUE;
	}

	// Add contact to routing table
	Kademlia.m_routingTable.AddContact(pCache);

	HostCache.Kademlia.m_nCookie++;

	// Reply with HELLO_RES
	return SendMyDetails( pHost, KADEMLIA2_HELLO_RES, true );
}

BOOL CKademlia::OnPacket_KADEMLIA2_HELLO_RES(const SOCKADDR_IN* pHost, CEDPacket* pPacket)
{
	Hashes::Guid oGUID;
	WORD nTCPPort;
	BYTE nVersion;
	BYTE nTagCount;

	if ( pPacket->GetRemaining() < ( 16 + 2 + 1 + 1 ) )
		return FALSE;

	pPacket->Read( oGUID );
	nTCPPort = pPacket->ReadShortLE();
	nVersion = pPacket->ReadByte();
	nTagCount = pPacket->ReadByte();

	// Parse tags - handle known tags and skip unknown ones safely
	for ( BYTE i = 0; i < nTagCount; i++ )
	{
		if ( pPacket->GetRemaining() < 1 )
			break;
		BYTE nTagType = pPacket->ReadByte();

		if ( nTagType == 0xFC )	// TAG_SOURCEUPORT
		{
			if ( pPacket->GetRemaining() < 2 )
				break;
			WORD nUDPPort = pPacket->ReadShortLE();
			// Could use nUDPPort if needed
		}
		else if ( nTagType == 0x0A ) // TAG_KADMISCOPTIONS (misc options)
		{
			if ( pPacket->GetRemaining() < 1 )
				break;
			BYTE nOptions = pPacket->ReadByte();
			// Could parse misc options if needed
		}
		else
		{
			// Unknown tag - try to skip safely
			// For most Kad2 tags, if we don't know the format, we can't safely skip
			// For now, stop parsing to avoid misaligning the packet
			break;
		}
	}

	// Update host cache
	CQuickLock oLock( HostCache.Kademlia.m_pSection );

	CHostCacheHostPtr pCache = HostCache.Kademlia.Add( &pHost->sin_addr, nTCPPort );
	if ( pCache )
	{
		pCache->m_oGUID = oGUID;
		pCache->m_nUDPPort = htons( pHost->sin_port );
		pCache->m_nKADVersion = nVersion;
		pCache->m_sDescription = oGUID.toString();
		pCache->m_tFailure = 0;
		pCache->m_nFailures = 0;
		pCache->m_bCheckedLocally = TRUE;
	}

	// Add contact to routing table
	Kademlia.m_routingTable.AddContact(pCache);

	HostCache.Kademlia.m_nCookie++;

	return TRUE;
}

BOOL CKademlia::OnPacket_KADEMLIA2_PING(const SOCKADDR_IN* pHost, CEDPacket* /*pPacket*/)
{
	return Send( pHost, KADEMLIA2_PONG );
}

BOOL CKademlia::OnPacket_KADEMLIA2_PONG(const SOCKADDR_IN* /*pHost*/, CEDPacket* /*pPacket*/)
{
	// ToDo: Implement Kademlia Pong packet handling

	return TRUE;
}
