//
// NeighboursWithConnect.cpp
//
// This file is part of Envy (getenvy.com) © 2016-2018
// Portions copyright Shareaza 2002-2008 and PeerProject 2008-2014
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

// Determine our hub or leaf role, count connections for each, and make new ones or close them to have the right number
// http://shareaza.sourceforge.net/mediawiki/index.php/Developers.Code.CNeighboursWithConnect
// http://getenvy.com/archives/envywiki/Developers.Code.CNeighboursWithConnect.html

#include "StdAfx.h"
#include "Settings.h"
#include "Envy.h"
#include "NeighboursWithConnect.h"
#include "Neighbours.h"
#include "ShakeNeighbour.h"
#include "EDNeighbour.h"
#include "DCNeighbour.h"
#include "BTPacket.h"
#include "Kademlia.h"
#include "Network.h"
#include "Datagrams.h"
#include "Security.h"
#include "HostCache.h"
#include "DiscoveryServices.h"
//#include "Scheduler.h"

#ifdef _DEBUG
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#define new DEBUG_NEW
#endif	// Debug

//////////////////////////////////////////////////////////////////////
// CNeighboursWithConnect construction

CNeighboursWithConnect::CNeighboursWithConnect()
    : m_nBandwidthIn	( 0 )
    , m_nBandwidthOut	( 0 )
    , m_nStableCount	( 0 )
    , m_bG2Leaf			( FALSE )
    , m_bG2Hub			( FALSE )
    , m_bG1Leaf			( FALSE )
    , m_bG1Ultrapeer	( FALSE )
    , m_tHubG2Promotion	( 0 )
    , m_tPresent		( )
    , m_tPriority		( )
    , m_tLastConnect	( 0 )
{
}

CNeighboursWithConnect::~CNeighboursWithConnect()
{
}

void CNeighboursWithConnect::Close()
{
    CNeighboursWithRouting::Close();

    m_nBandwidthIn	= 0;
    m_nBandwidthOut	= 0;
    m_nStableCount	= 0;
    m_bG2Leaf		= FALSE;
    m_bG2Hub		= FALSE;
    m_bG1Leaf		= FALSE;
    m_bG1Ultrapeer	= FALSE;
    m_tHubG2Promotion = 0;
    ZeroMemory( &m_tPresent, sizeof( m_tPresent ) );
    ZeroMemory( &m_tPriority, sizeof( m_tPriority ) );
}

//////////////////////////////////////////////////////////////////////
// CNeighboursWithConnect connection initiation

// Maintain calls CHostCacheHost::ConnectTo, which calls this
// Takes an IP address and port number from the host cache, and connects to it
// Returns a pointer to the new neighbour in the connected list, or null if no connection was made
CNeighbour* CNeighboursWithConnect::ConnectTo(
    const IN_ADDR& pAddress,	// IP address from the host cache to connect to, like 67.163.208.23
    WORD       nPort,			// Port number that goes with that IP address, like 6346
    PROTOCOLID nProtocol,		// Protocol name, like PROTOCOL_G1 for Gnutella
    BOOL       bAutomatic,		// True to (do)
    BOOL       bNoUltraPeer)	// By default, false to not (do)
{
    // Don't connect to self
    if ( Settings.Connection.IgnoreOwnIP && Network.IsSelfIP( pAddress ) )
        return NULL;

    // Don't connect to blocked addresses
    if ( Security.IsDenied( &pAddress ) )
    {
        // If not automatic (do), report that this address is on the block list, and return no new connection made
        if ( ! bAutomatic )
            theApp.Message( MSG_ERROR, IDS_SECURITY_OUTGOING, (LPCTSTR)CString( inet_ntoa( pAddress ) ) );
        return NULL;
    }

    // If automatic (do) and the network object knows this IP address is firewalled and can't receive connections, give up
    if ( bAutomatic && Network.IsFirewalledAddress( &pAddress, TRUE ) )
        return NULL;

    // Get this thread exclusive access to the network (do) while this method runs
    // When control leaves the method, pLock will go out of scope and release access
    CSingleLock pLock( &Network.m_pSection );
    if ( ! pLock.Lock( 200 ) )
        return NULL;

    // If the list of connected computers already has this IP address
    if ( Get( pAddress ) )
    {
        // If not automatic (do), report that we're already connected to that computer, and return no new connection made
        if ( ! bAutomatic )
            theApp.Message( MSG_ERROR, IDS_CONNECTION_ALREADY_ABORT, (LPCTSTR)CString( inet_ntoa( pAddress ) ) );
        return NULL;
    }

    // If the caller wants automatic behavior, then make this connection request also connect the network it is for
    if ( ! bAutomatic )
    {
        // Activate the appropriate network (if required)
        switch ( nProtocol )
        {
        case PROTOCOL_G1:
            Settings.Gnutella1.Enabled = true;
            break;
        case PROTOCOL_G2:
            Settings.Gnutella2.Enabled = true;
            break;
        case PROTOCOL_ED2K:
            Settings.eDonkey.Enabled = true;
            CloseDonkeys();		// Reset the eDonkey2000 network (do)
            break;
        case PROTOCOL_BT:
            Settings.BitTorrent.Enabled = true;
            Settings.BitTorrent.EnableDHT = true;
            break;
        case PROTOCOL_DC:
            Settings.DC.Enabled = true;
            break;
        case PROTOCOL_KAD:
            Settings.eDonkey.Enabled = true;
            break;
        //default:
        //	ASSERT( ! nProtocol );
        }
    }

    // Run network connect (do), and leave if it reports an error
    if ( ! Network.Connect() )
        return NULL;

    // Create a compatible Neighbour object type connected to the IP address, and return the pointer to it

    switch ( nProtocol )
    {
    case PROTOCOL_ED2K:
        {
            augment::auto_ptr< CEDNeighbour > pNeighbour( new CEDNeighbour() );
            if ( pNeighbour->ConnectTo( &pAddress, nPort, bAutomatic ) )
                return pNeighbour.release();			// Started connecting to an ed2k neighbour
        }
        break;

    case PROTOCOL_DC:
        {
            augment::auto_ptr< CDCNeighbour > pNeighbour( new CDCNeighbour() );
            if ( pNeighbour->ConnectTo( &pAddress, nPort, bAutomatic ) )
                return pNeighbour.release();			// Started connecting to a dc++ neighbour
        }
        break;

    case PROTOCOL_BT:
        {
            DHT.Ping( &pAddress, nPort );
        }
        break;

    case PROTOCOL_KAD:
        {
            SOCKADDR_IN pHost = { AF_INET, htons( nPort ), pAddress };
            Kademlia.Bootstrap( &pHost );
        }
        break;

    default:	// PROTOCOL_G1/PROTOCOL_G2
        {
            augment::auto_ptr< CShakeNeighbour > pNeighbour( new CShakeNeighbour() );
            if ( pNeighbour->ConnectTo( &pAddress, nPort, bAutomatic, bNoUltraPeer ) )
            {
                // If we only want G1 connections now, specify that to begin with
                if ( Settings.Gnutella.SpecifyProtocol )
                    pNeighbour->m_nProtocol = nProtocol;
                return pNeighbour.release();			// Started connecting to a Gnutella/G2 neighbour
            }
        }
    }

    return NULL;	// Unable to connect, some other protocol?
}

//////////////////////////////////////////////////////////////////////
// CNeighboursWithConnect accept a connection

// CHandshake::OnRead gets an incoming socket connection, looks at the first 7 bytes, and passes Gnutella and Gnutella2 here
// Takes a pointer to the CHandshake object the program made when it accepted the new connection from the listening socket
// Makes a new CShakeNeighbour object, and calls AttachTo to have it take this incoming connection
// Returns a pointer to the CShakeNeighbour object
BOOL CNeighboursWithConnect::OnAccept(CConnection* pConnection)
{
    CSingleLock pLock( &Network.m_pSection );
    if ( ! pLock.Lock( 150 ) )
        return TRUE;	// Try again later

    if ( Neighbours.Get( pConnection->m_pHost.sin_addr ) )
    {
        pConnection->Write( _P("GNUTELLA/0.6 503 Duplicate connection\r\n\r\n") );
        pConnection->LogOutgoing();
        pConnection->DelayClose( IDS_CONNECTION_ALREADY_REFUSE );
        return TRUE;
    }

    if ( CShakeNeighbour* pNeighbour = new CShakeNeighbour() )
    {
        pNeighbour->AttachTo( pConnection );
        return FALSE;
    }

    return TRUE;
}

//////////////////////////////////////////////////////////////////////
// CNeighboursWithConnect

// If we've been demoted to the leaf role for a protocol, this function trims peers after we get a hub (do)
// Takes a protocol like PROTOCOL_G1 or PROTOCOL_G2
// If we don't need any more hub connections, closes them all (do)
void CNeighboursWithConnect::PeerPrune(PROTOCOLID nProtocol)
{
    // True if we need more hub connections for the requested protocol
    BOOL bNeedMore = NeedMoreHubs( nProtocol );

    // True if we need more hub connections for either Gnutella or Gnutella2
    BOOL bNeedMoreAnyProtocol = NeedMoreHubs( PROTOCOL_NULL );

    // Loop through all the neighbours in the list
    for ( POSITION pos = GetIterator(); pos; )
    {
        // Get the neighbour at this position in the list, and move to the next one
        CNeighbour* pNeighbour = GetNext( pos );

        // This neighbour is on the network the caller wants us to prune, and
        if ( pNeighbour->m_nProtocol == nProtocol )
        {
            // Our connection to this neighbour is not up to a hub, and
            if ( pNeighbour->m_nNodeType != ntHub )
            {
                // Either we don't need any more hubs, or we're done with the handshake so we know it wont' be a hub, then drop this connection
                if ( ! bNeedMore || pNeighbour->m_nState == nrsConnected )
                    pNeighbour->Close( IDS_CONNECTION_PEERPRUNE );
            }
        }
        else if ( pNeighbour->m_nProtocol == PROTOCOL_NULL )
        {
            // This must be a Gnutella or Gnutella2 computer in the middle of the handshake
            // If we initiated the connection, we know it's not a leaf trying to contact us, it's probably a hub
            if ( pNeighbour->m_bInitiated )
            {
                // If we don't need any more hubs, on any protocol, drop this connection
                if ( ! bNeedMoreAnyProtocol )
                    pNeighbour->Close( IDS_CONNECTION_PEERPRUNE );
            }
        }
    }
}

// Determines if we are a leaf on the Gnutella2 network right now
bool CNeighboursWithConnect::IsG2Leaf() const
{
    // If the network is enabled (do) and we have at least 1 connection up to a hub, or say so, then we're a leaf
    return ( Settings.Gnutella2.ClientMode == MODE_LEAF || m_bG2Leaf ) && Network.IsConnected();
}

// Determines if we are a hub on the Gnutella2 network right now
bool CNeighboursWithConnect::IsG2Hub() const
{
    // If the network is enabled (do) and we have at least 1 connection down to a leaf, or say so, then we're a hub
    return ( Settings.Gnutella2.ClientMode == MODE_HUB || m_bG2Hub ) && Network.IsConnected();
}

// Takes true if we are running the program in debug mode, and this method should write out debug information
// Determines if the computer and Internet connection here are strong enough for this program to run as a Gnutella2 hub
// Returns false, which is 0, if we can't be a hub, or a number 1+ that is higher the better hub we'd be
DWORD CNeighboursWithConnect::IsG2HubCapable(BOOL bIgnoreTime, BOOL bDebug) const
{
    // Start the rating at 0, which means we can't be a hub
    DWORD nRating = 0;		// Increment this number as we find signs we can be a hub

    // If the caller wants us to report debugging information, start out with a header line
    if ( bDebug ) theApp.Message( MSG_DEBUG, L"Is G2 hub capable?" );		// protocolNames[ PROTOCOL_G2 ]

    // We can't be a Gnutella2 hub if the user has not chosen to connect to Gnutella2 in the program settings
    if ( ! Network.IsConnected() || ! Settings.Gnutella2.Enabled )
    {
        // Finish the lines of debugging information, and report no, we can't be a hub
        if ( bDebug ) theApp.Message( MSG_DEBUG, L"NO: G2 not enabled" );		// protocolNames[ PROTOCOL_G2 ]
        return FALSE;
    }

    // The user can go into settings and check a box to make the program never run in hub mode, even if it could
    if ( Settings.Gnutella2.ClientMode == MODE_LEAF )	// If user disabled hub mode in settings
    {
        // Finish the lines of debugging information, and report no, we can't be a hub
        if ( bDebug ) theApp.Message( MSG_DEBUG, L"NO: hub mode disabled" );
        return FALSE;
    }

    // We are running as a Gnutella2 leaf right now
    if ( IsG2Leaf() )
    {
        // We can never be a hub because we are a leaf (do)
        if ( bDebug ) theApp.Message( MSG_DEBUG, L"NO: leaf" );
        return FALSE;
    }
    else // We are not running as a Gnutella2 leaf right now (do)
    {
        // Note this and keep going
        if ( bDebug ) theApp.Message( MSG_DEBUG, L"OK: not a leaf" );
    }

    // The user can check a box in settings to let the program become a hub without passing the additional tests below
    if ( Settings.Gnutella2.ClientMode == MODE_HUB )
    {
        // Make a note about this and keep going
        if ( bDebug ) theApp.Message( MSG_DEBUG, L"YES: hub mode forced" );
    }
    else // MODE_AUTO: User didn't check the force hub box in settings, so the client will have to pass additional tests below
    {
        // Note base physical memory check in CalculateSystemPerformanceScore

        // Check the connection speed, make sure the download speed is fast enough
        if ( Settings.Connection.InSpeed < 200 )	// If the inbound speed is less than 200 (do)
        {
            // Download speed too slow
            if ( bDebug ) theApp.Message( MSG_DEBUG, L"NO: less than 200 Kb/s in" );
            return FALSE;
        }

        // Make sure the upload speed is fast enough
        if ( Settings.Connection.OutSpeed < 200 )
        {
            // Upload speed too slow
            if ( bDebug ) theApp.Message( MSG_DEBUG, L"NO: less than 200 Kb/s out" );
            return FALSE;
        }

        // Make sure we are not also a forced ultrapeer on gnutella
        if ( IsG1Ultrapeer() )
        {
            // Already ultrapeer mode overhead
            if ( bDebug ) theApp.Message( MSG_DEBUG, L"NO: Gnutella ultrapeer active" );
            return FALSE;
        }

        // Confirm how long the node has been running.
        if ( ! bIgnoreTime )	// This is unhandled (never skipped)  ToDo: Allow for new network?
        {
            if ( Settings.Gnutella2.HubVerified )
            {
                // Systems that have been good hubs before can promote in 2 hours
                if ( Network.GetStableTime() < 7200 )
                {
                    if ( bDebug ) theApp.Message( MSG_DEBUG, L"NO: not stable for 2 hours" );
                    return FALSE;
                }

                if ( bDebug ) theApp.Message( MSG_DEBUG, L"OK: stable for 2 hours" );
            }
            else // Untested hubs need 3 hours uptime to be considered
            {
                if ( Network.GetStableTime() < 10800 )
                {
                    if ( bDebug ) theApp.Message( MSG_DEBUG, L"NO: not stable for 3 hours" );
                    return FALSE;
                }

                if ( bDebug ) theApp.Message( MSG_DEBUG, L"OK: stable for 3 hours" );
            }
        }

        // Make sure the datagram is stable (do)
        if ( Network.IsFirewalled(CHECK_UDP) )
        {
            // Record this is why we can't be a hub, and return no
            if ( bDebug ) theApp.Message( MSG_DEBUG, L"NO: datagram not stable" );
            return FALSE;
        }
        else // The datagram is stable (do)
        {
            // Make a note we passed this test, and keep going
            if ( bDebug ) theApp.Message( MSG_DEBUG, L"OK: datagram stable" );
        }

        // Report that we meet the minimum requirements to be a hub
        if ( bDebug ) theApp.Message( MSG_DEBUG, L"YES: hub capable by test" );
    }

    // If we've made it this far, change the rating number from 0 to 1
    nRating = 1 + CalculateSystemPerformanceScore( bDebug );	// The higher it is, the better a hub we can be

    // The program is not connected to other networks

    if ( ! Settings.Gnutella1.Enabled )
    {
        nRating++;
        if ( bDebug ) theApp.Message( MSG_DEBUG, L"Gnutella not enabled" );		// protocolNames[ PROTOCOL
