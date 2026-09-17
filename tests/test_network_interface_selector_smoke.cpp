//
// test_network_interface_selector_smoke.cpp
//
// Smoke tests for NetworkInterfaceSelector.h and MiniUPnPIgdPolicy.h.
// No live NIC / box dependency in CI.
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//

#include "test_framework.h"
#include "../Envy/NetworkInterfaceSelector.h"
#include "../Envy/MiniUPnPIgdPolicy.h"

#include <cstring>

struct CandidateSpec
{
	ULONG	IfIndex;
	ULONG	Ipv4Metric;
	DWORD	Address;
	DWORD	Gateway;
	bool	bPreferred = false;
	bool	bVirtual = false;
	bool	bUp = true;
	bool	bLoopback = false;
	bool	bApipa = false;
};

static NetworkIpv4Candidate MakeCandidate( const CandidateSpec& oSpec )
{
	NetworkIpv4Candidate o = {};
	o.IfIndex = oSpec.IfIndex;
	o.Ipv4Metric = oSpec.Ipv4Metric;
	o.Address = oSpec.Address;
	o.Gateway = oSpec.Gateway;
	o.bUp = oSpec.bUp;
	o.bLoopback = oSpec.bLoopback;
	o.bApipa = oSpec.bApipa;
	o.bVirtualLikely = oSpec.bVirtual;
	o.bPreferredInternet = oSpec.bPreferred;
	return o;
}

// RFC 5737 documentation addresses (TEST-NET-1 / private-style fixtures).
static const DWORD kLanAddress = 0x140200C0;	// 192.0.2.20
static const DWORD kLanGateway = 0x010200C0;	// 192.0.2.1
static const DWORD kVpnAddress = 0x0A0A0A0A;	// 10.10.10.10
static const DWORD kVpnGateway = 0x010A0A0A;	// 10.10.10.1
static const DWORD kApipaAddress = 0x0100FEA9;	// 169.254.0.1
static const DWORD kLoopback = 0x0100007F;		// 127.0.0.1

static bool test_rejects_loopback_apipa_down_no_gateway()
{
	if ( NetworkIpv4CandidateIsEligible(
			MakeCandidate( { 1, 10, kLoopback, kLanGateway, false, false, true, true } ) ) )
		return false;
	if ( NetworkIpv4CandidateIsEligible(
			MakeCandidate( { 1, 10, kApipaAddress, kLanGateway, false, false, true, false, true } ) ) )
		return false;
	if ( NetworkIpv4CandidateIsEligible(
			MakeCandidate( { 1, 10, kLanAddress, kLanGateway, false, false, false } ) ) )
		return false;
	if ( NetworkIpv4CandidateIsEligible(
			MakeCandidate( { 1, 10, kLanAddress, 0 } ) ) )
		return false;
	return NetworkIpv4CandidateIsEligible(
		MakeCandidate( { 1, 10, kLanAddress, kLanGateway } ) );
}

static bool test_virtual_skipped_unless_preferred()
{
	if ( NetworkIpv4CandidateIsEligible(
			MakeCandidate( { 2, 5, kVpnAddress, kVpnGateway, false, true } ) ) )
		return false;
	return NetworkIpv4CandidateIsEligible(
		MakeCandidate( { 2, 5, kVpnAddress, kVpnGateway, true, true } ) );
}

static bool test_preferred_internet_sorted_first()
{
	NetworkIpv4Candidate a[ 3 ];
	a[ 0 ] = MakeCandidate( { 10, 25, kVpnAddress, kVpnGateway, false, true } );
	a[ 1 ] = MakeCandidate( { 20, 40, kLanAddress, kLanGateway, true, false } );
	a[ 2 ] = MakeCandidate( { 30, 10, 0x1E0200C0, kLanGateway, false, false } );

	ULONG order[ 4 ] = {};
	const ULONG n = NetworkOrderDiscoveryCandidates( a, 3, order, 4 );
	if ( n < 2 || order[ 0 ] != 1 )
		return false;
	for ( ULONG i = 0; i < n; ++i )
	{
		if ( order[ i ] == 0 )
			return false;
	}
	return true;
}

static bool test_metric_tiebreak_and_cap()
{
	NetworkIpv4Candidate a[ 5 ];
	a[ 0 ] = MakeCandidate( { 1, 50, 0x0A0200C0, kLanGateway } );
	a[ 1 ] = MakeCandidate( { 2, 10, 0x140200C0, kLanGateway } );
	a[ 2 ] = MakeCandidate( { 3, 10, 0x1E0200C0, kLanGateway } );
	a[ 3 ] = MakeCandidate( { 4, 20, 0x280200C0, kLanGateway } );
	a[ 4 ] = MakeCandidate( { 5, 30, 0x320200C0, kLanGateway } );

	ULONG order[ NetworkInterfaceSelectorMaxDiscovery ] = {};
	const ULONG n = NetworkOrderDiscoveryCandidates(
		a, 5, order, NetworkInterfaceSelectorMaxDiscovery );
	return n == NetworkInterfaceSelectorMaxDiscovery
		&& order[ 0 ] == 1 && order[ 1 ] == 2 && order[ 2 ] == 3;
}

static bool test_format_and_virtual_description()
{
	char sz[ 16 ] = {};
	if ( ! NetworkFormatIpv4( kLanAddress, sz, sizeof( sz ) ) )
		return false;
	if ( strcmp( sz, "192.0.2.20" ) != 0 )
		return false;
	if ( ! NetworkAdapterDescriptionLooksVirtual( L"Hyper-V Virtual Ethernet Adapter" ) )
		return false;
	if ( NetworkAdapterDescriptionLooksVirtual( L"Intel(R) Ethernet Connection" ) )
		return false;
	return NetworkIpv4IsApipa( kApipaAddress ) && ! NetworkIpv4IsApipa( kLanAddress );
}

static bool test_gateway_prefer_adapter_over_nexthop()
{
	return NetworkGatewayPreferAdapterThenRouteNextHop( kLanGateway, 0x020200C0 ) == kLanGateway;
}

static bool test_gateway_fallback_to_route_nexthop()
{
	return NetworkGatewayPreferAdapterThenRouteNextHop( 0, kLanGateway ) == kLanGateway;
}

static bool test_gateway_rejects_zero_nexthop()
{
	return NetworkGatewayPreferAdapterThenRouteNextHop( 0, 0 ) == 0
		&& NetworkGatewayPreferAdapterThenRouteNextHop( 0, kLoopback ) == 0;
}

static bool test_igd_result_matrix()
{
	return ! MiniUPnPIgdResultAllowsWanCommands( 0 )
		&& MiniUPnPIgdResultAllowsWanCommands( 1 )
		&& MiniUPnPIgdResultAllowsWanCommands( 2 )
		&& ! MiniUPnPIgdResultAllowsWanCommands( 3 )
		&& MiniUPnPIgdResultMeansNoUsableIgd( 0 )
		&& MiniUPnPIgdResultMeansNoUsableIgd( 3 )
		&& MiniUPnPIgdResultOwnsUrls( 3 )
		&& ! MiniUPnPIgdResultOwnsUrls( 0 );
}

static bool test_explicit_igd_st_accepted()
{
	return MiniUPnPIsExplicitIgdAdvertisement( "urn:schemas-upnp-org:device:InternetGatewayDevice:1" )
		&& MiniUPnPIsExplicitIgdAdvertisement( "urn:schemas-upnp-org:device:InternetGatewayDevice:2" )
		&& MiniUPnPIsExplicitIgdAdvertisement( "urn:schemas-upnp-org:service:WANIPConnection:1" )
		&& MiniUPnPIsExplicitIgdAdvertisement( "urn:schemas-upnp-org:service:WANIPConnection:2" )
		&& MiniUPnPIsExplicitIgdAdvertisement( "urn:schemas-upnp-org:service:WANPPPConnection:1" );
}

static bool test_explicit_igd_st_rejected()
{
	return ! MiniUPnPIsExplicitIgdAdvertisement( "upnp:rootdevice" )
		&& ! MiniUPnPIsExplicitIgdAdvertisement( "urn:schemas-wifialliance-org:device:WFADevice:1" )
		&& ! MiniUPnPIsExplicitIgdAdvertisement( "urn:schemas-wifialliance-org:service:WFAWLANConfig:1" )
		&& ! MiniUPnPIsExplicitIgdAdvertisement( "urn:schemas-upnp-org:device:MediaServer:1" )
		&& ! MiniUPnPIsExplicitIgdAdvertisement( "uuid:761c1ff0-ca5d-d0b1-31b6-3986389157a8" )
		&& ! MiniUPnPIsExplicitIgdAdvertisement( "" )
		&& ! MiniUPnPIsExplicitIgdAdvertisement( nullptr );
}

static bool test_gateway_url_accept_reject()
{
	// Use https:// literals only: real UPnP LOCATION is HTTP, but host
	// parsing is scheme-agnostic and Sonar flags http:// as S5332.
	// RFC 5737 documentation addresses (not a local LAN snapshot).
	const char* pszGw = "192.0.2.1";
	if ( ! MiniUPnPHttpUrlHostEqualsIpv4String(
			"https://192.0.2.1:49153/root.xml", pszGw ) )
		return false;
	if ( ! MiniUPnPHttpUrlHostEqualsIpv4String(
			"https://192.0.2.1/desc.xml", pszGw ) )
		return false;
	if ( MiniUPnPHttpUrlHostEqualsIpv4String(
			"https://192.0.2.10/root.xml", pszGw ) )
		return false;
	if ( MiniUPnPHttpUrlHostEqualsIpv4String(
			"https://198.51.100.1/root.xml", pszGw ) )
		return false;
	if ( MiniUPnPHttpUrlHostEqualsIpv4String(
			"https://203.0.113.1/root.xml", pszGw ) )
		return false;
	return true;
}

static bool test_url_host_extract_no_substring_trap()
{
	char szHost[ 64 ] = {};
	if ( ! MiniUPnPExtractHttpUrlHost( "https://192.0.2.100:80/x", szHost, sizeof( szHost ) ) )
		return false;
	return strcmp( szHost, "192.0.2.100" ) == 0;
}

static bool test_dedupe_same_location_policy()
{
	// Exact duplicates collapse to one candidate.
	const char* pszLoc = "https://192.0.2.1/root.xml";
	const char* urlsDup[ 2 ] = { pszLoc, pszLoc };
	if ( MiniUPnPCountUniqueLocations( urlsDup, 2 ) != 1 )
		return false;

	// Path is case-sensitive: /root.xml and /ROOT.xml are distinct.
	const char* urlsCase[ 2 ] =
	{
		"https://192.0.2.1/root.xml",
		"https://192.0.2.1/ROOT.xml"
	};
	if ( MiniUPnPCountUniqueLocations( urlsCase, 2 ) != 2 )
		return false;

	// nullptr / empty entries are ignored; distinct hosts stay distinct.
	const char* urlsMixed[ 5 ] =
	{
		nullptr,
		"",
		"https://192.0.2.1/root.xml",
		"https://192.0.2.1/root.xml",
		"https://198.51.100.1/root.xml"
	};
	if ( MiniUPnPCountUniqueLocations( urlsMixed, 5 ) != 2 )
		return false;

	return MiniUPnPHttpUrlHostEqualsIpv4String( pszLoc, "192.0.2.1" )
		&& MiniUPnPSsdpLooksLikeNonIgd(
			"https://192.0.2.1/wps_device.xml",
			"urn:schemas-wifialliance-org:device:WFADevice:1" )
		&& ! MiniUPnPIsExplicitIgdAdvertisement( "upnp:rootdevice" );
}

void register_network_interface_selector_smoke_tests( TestSuite& suite )
{
	suite.add_test( "NetworkIface rejects loopback/APIPA/down/no-gateway",
		test_rejects_loopback_apipa_down_no_gateway );
	suite.add_test( "NetworkIface virtual only when preferred Internet",
		test_virtual_skipped_unless_preferred );
	suite.add_test( "NetworkIface preferred Internet ordered first",
		test_preferred_internet_sorted_first );
	suite.add_test( "NetworkIface metric order + discovery cap",
		test_metric_tiebreak_and_cap );
	suite.add_test( "NetworkIface format + virtual description markers",
		test_format_and_virtual_description );
	suite.add_test( "NetworkIface gateway prefers adapter over NextHop",
		test_gateway_prefer_adapter_over_nexthop );
	suite.add_test( "NetworkIface gateway falls back to route NextHop",
		test_gateway_fallback_to_route_nexthop );
	suite.add_test( "NetworkIface gateway rejects zero/loopback NextHop",
		test_gateway_rejects_zero_nexthop );
	suite.add_test( "MiniUPnP IGD result matrix 0/1/2/3",
		test_igd_result_matrix );
	suite.add_test( "MiniUPnP explicit IGD ST accepted",
		test_explicit_igd_st_accepted );
	suite.add_test( "MiniUPnP non-IGD ST rejected as direct candidates",
		test_explicit_igd_st_rejected );
	suite.add_test( "MiniUPnP gateway URL accept/reject without substring trap",
		test_gateway_url_accept_reject );
	suite.add_test( "MiniUPnP URL host extract .100 != .1",
		test_url_host_extract_no_substring_trap );
	suite.add_test( "MiniUPnP LOCATION dedupe exact match; path case-sensitive",
		test_dedupe_same_location_policy );
}
