// Kad2 bootstrap response and request lifecycle, shared with the native regression fixture.
// This file is part of Envy (getenvy.com) (C) 2016-2026
// SPDX-License-Identifier: AGPL-3.0-or-later

void CKademlia::OnBootstrapResponse(const SOCKADDR_IN* pHost, CEDPacket* pPacket)
{
	// Check framing before consuming the matching outstanding request: a reply
	// too short to carry the fixed header is not a bootstrap answer at all.
	const size_t bodyBytes = pPacket->GetRemaining();
	if (bodyBytes < KadBootstrapResponseHeaderBytes)
	{
		++m_bootstrapMalformed;
		return;
	}

	KadId responderId;
	pPacket->Read(responderId, KAD_ID_SIZE);
	const WORD responderTcpPort = pPacket->ReadShortLE();
	const BYTE responderKadVersion = pPacket->ReadByte();
	const WORD announcedContacts = pPacket->ReadShortLE();
	// eMule 0.72a and aMule keep whatever prefix of the announced contact list
	// the datagram actually carried, so an over-counted or short list must not
	// cost the peer its answer. Read the framed prefix, bounded locally. A reply
	// that is short, or longer than the local bound, is still used but is counted
	// apart below, and only once the sender is known to have been asked.
	const size_t usableContacts = KadBootstrapUsableContacts(bodyBytes, announcedContacts);
	const bool partialReply = usableContacts < static_cast<size_t>(announcedContacts);

	const uint32_t nFromIp = ntohl(pHost->sin_addr.s_addr);
	const uint64_t now = KadNowMs();
	CleanupExpiredRequests();
	uint16_t requestedPort = 0;
	if (!m_bootstrapRotation.MatchResponse(nFromIp, ntohs(pHost->sin_port), now, requestedPort))
	{
		++m_bootstrapRejected;
		return;
	}

	// Consume only the original endpoint, even when the reply came from a
	// different port. A late response may no longer occupy an outstanding slot.
	for (auto it = m_outstandingRequests.begin(); it != m_outstandingRequests.end(); ++it)
	{
		if (it->second.type == KAD_REQUEST_BOOTSTRAP &&
		    it->second.targetAddr.sin_addr.s_addr == pHost->sin_addr.s_addr &&
		    ntohs(it->second.targetAddr.sin_port) == requestedPort)
		{
			m_outstandingRequests.erase(it);
			break;
		}
	}
	m_bootstrapRotation.Accepted(nFromIp, requestedPort, ntohs(pHost->sin_port), now);
	if (partialReply)
		++m_bootstrapPartial;
	else
		++m_bootstrapResponses;

	unsigned contactsAdded = 0;
	for (size_t i = 0; i < usableContacts; ++i)
	{
		KadContact contact;
		pPacket->Read(contact.id, KAD_ID_SIZE);
		contact.ip = pPacket->ReadLongLE();
		contact.udpPort = pPacket->ReadShortLE();
		contact.tcpPort = pPacket->ReadShortLE();
		contact.version = pPacket->ReadByte();
		contact.verified = false;

		if (UpdateContact(contact, KadContactSource::Candidate, false))
			++contactsAdded;
		else
			++m_bootstrapContactsRefused;
	}

	KadContact responderContact(responderId, nFromIp, ntohs(pHost->sin_port), responderTcpPort);
	responderContact.version = responderKadVersion;
	if (UpdateContact(responderContact, KadContactSource::Observed, false))
		++contactsAdded;
	else
		++m_bootstrapContactsRefused;
	m_bootstrapAccepted += contactsAdded;
}

DWORD CKademlia::AddOutstandingRequest(KadRequestType type, const SOCKADDR_IN& targetAddr)
{
	// Zero denotes failure; never overwrite a live request when the counter wraps.
	static DWORD nextRequestId = 1;
	DWORD requestId;
	do
	{
		requestId = nextRequestId++;
	} while (requestId == 0 || m_outstandingRequests.find(requestId) != m_outstandingRequests.end());

	// Clean up expired requests first
	CleanupExpiredRequests();

	const uint64_t now = KadNowMs();
	if (type == KAD_REQUEST_BOOTSTRAP &&
	    !m_bootstrapRotation.Sent(ntohl(targetAddr.sin_addr.s_addr), ntohs(targetAddr.sin_port), now))
	{
		// Nothing is registered or sent: the endpoint is still in flight or inside its
		// answered window, or the retry map is full of protected history.
		++m_bootstrapBlocked;
		return 0;
	}

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
		if (oldest->second.type == KAD_REQUEST_BOOTSTRAP)
			m_bootstrapRotation.Cancelled(ntohl(oldest->second.targetAddr.sin_addr.s_addr),
			                              ntohs(oldest->second.targetAddr.sin_port));
		m_outstandingRequests.erase(oldest);
	}

	m_outstandingRequests[requestId] = KadOutstandingRequest(type, targetAddr, now);
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
	CleanupExpiredRequests();
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
	const auto it = m_outstandingRequests.find(requestId);
	if (it != m_outstandingRequests.end() && it->second.type == KAD_REQUEST_BOOTSTRAP)
		m_bootstrapRotation.Cancelled(ntohl(it->second.targetAddr.sin_addr.s_addr),
		                              ntohs(it->second.targetAddr.sin_port));
	m_outstandingRequests.erase(requestId);
}

void CKademlia::CleanupExpiredRequests()
{
	const uint64_t now = KadNowMs();
	auto it = m_outstandingRequests.begin();

	while (it != m_outstandingRequests.end())
	{
		if (now - it->second.sentTime >= KAD2_REQUEST_TIMEOUT)
		{
			if (it->second.type == KAD_REQUEST_BOOTSTRAP &&
			    m_bootstrapRotation.TimedOut(ntohl(it->second.targetAddr.sin_addr.s_addr),
			                                 ntohs(it->second.targetAddr.sin_port), now))
				++m_bootstrapTimeouts;
			it = m_outstandingRequests.erase(it);
		}
		else
		{
			++it;
		}
	}
	m_bootstrapRotation.Prune(now);
}
