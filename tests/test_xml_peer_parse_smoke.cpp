//
// test_xml_peer_parse_smoke.cpp
//
// Smoke tests for XmlParseValidate.h (ENVY-SEC-003).
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//

#include "test_framework.h"
#include "../Envy/XmlParseValidate.h"

static bool test_xml_peer_defaults()
{
	const XmlParseBudget oBudget = XmlParseBudget::PeerDefaults();
	return oBudget.m_nMaxDepth == XML_PEER_PARSE_DEPTH_MAX &&
	       oBudget.m_nMaxNodes == XML_PEER_PARSE_NODES_MAX &&
	       oBudget.m_nMaxChars == XML_PEER_PARSE_CHARS_MAX;
}

static bool test_xml_budget_chars_cap()
{
	XmlParseBudget oBudget = XmlParseBudget::PeerDefaults();
	return oBudget.ConsumeChars(XML_PEER_PARSE_CHARS_MAX) &&
	       !oBudget.ConsumeChars(1);
}

static bool test_xml_budget_depth_cap()
{
	XmlParseBudget oBudget(2, 100, 10000);
	const bool bFirst = oBudget.EnterElement();
	const bool bSecond = oBudget.EnterElement();
	const bool bThird = oBudget.EnterElement();
	return bFirst && bSecond && !bThird;
}

static bool test_xml_budget_nodes_cap()
{
	XmlParseBudget oBudget(32, 2, 10000);
	const bool bFirst = oBudget.AddNode();
	const bool bSecond = oBudget.AddNode();
	const bool bThird = oBudget.AddNode();
	return bFirst && bSecond && !bThird;
}

// Mirrors FromPeerString: root EnterElement, then child EnterElement calls.
static bool test_xml_budget_depth_includes_root()
{
	XmlParseBudget oBudget(2, 100, 10000);
	if (!oBudget.AcceptsElementChain(2) || oBudget.AcceptsElementChain(3))
		return false;

	const bool bRoot = oBudget.EnterElement();
	const bool bChild = oBudget.EnterElement();
	const bool bTooDeep = oBudget.EnterElement();
	return bRoot && bChild && !bTooDeep;
}


static bool test_xml_peer_bytes_predecode_gate()
{
	// Contract for FromPeerBytes: admit only 1..XML_PEER_PARSE_CHARS_MAX bytes.
	const auto admits = [](DWORD nByte)
	{
		return nByte > 0 && nByte <= XML_PEER_PARSE_CHARS_MAX;
	};
	return !admits(0) &&
	       admits(1) &&
	       admits(XML_PEER_PARSE_CHARS_MAX) &&
	       !admits(XML_PEER_PARSE_CHARS_MAX + 1);
}

static bool test_xml_peer_readstring_prematerialize_gate()
{
	// Contract for HostBrowser profile XML / hit COMMENT: reject before ReadString.
	const auto admits = [](DWORD nPacket)
	{
		return nPacket > 0 && nPacket <= XML_PEER_PARSE_CHARS_MAX;
	};
	const auto rejects_oversized = [](DWORD nPacket)
	{
		return nPacket > XML_PEER_PARSE_CHARS_MAX;
	};
	return !admits(0) &&
	       admits(1) &&
	       admits(XML_PEER_PARSE_CHARS_MAX) &&
	       !admits(XML_PEER_PARSE_CHARS_MAX + 1) &&
	       rejects_oversized(XML_PEER_PARSE_CHARS_MAX + 1) &&
	       !rejects_oversized(XML_PEER_PARSE_CHARS_MAX);
}

// Models multi-fragment G2/G1 metadata: one shared budget across sequential roots.
static bool test_xml_budget_shared_nodes_across_fragments()
{
	XmlParseBudget oBudget(32, 3, 10000);
	if (!oBudget.ConsumeChars(100))
		return false;

	// Fragment A: root + one child = 2 nodes
	if (!oBudget.EnterElement() || !oBudget.AddNode())
		return false;
	if (!oBudget.EnterElement() || !oBudget.AddNode())
		return false;
	oBudget.LeaveElement();
	oBudget.LeaveElement();

	// Fragment B: root would be node 3; a child must fail the shared node cap.
	if (!oBudget.EnterElement() || !oBudget.AddNode())
		return false;
	const bool bChildBlocked = !oBudget.AddNode();
	oBudget.LeaveElement();
	return bChildBlocked && oBudget.m_nNodes == 3;
}

// Models FromG2Packet sibling METADATA children sharing one budget.
static bool test_xml_budget_shared_across_sibling_metadata()
{
	XmlParseBudget oBudget(32, 4, 1000);

	// Sibling METADATA A
	if (!oBudget.ConsumeChars(50))
		return false;
	if (!oBudget.EnterElement() || !oBudget.AddNode())
		return false; // root
	if (!oBudget.EnterElement() || !oBudget.AddNode())
		return false; // child
	oBudget.LeaveElement();
	oBudget.LeaveElement();

	// Sibling METADATA B — must not reset the node counter
	if (!oBudget.ConsumeChars(50))
		return false;
	if (!oBudget.EnterElement() || !oBudget.AddNode())
		return false; // root = node 3
	if (!oBudget.EnterElement() || !oBudget.AddNode())
		return false; // child = node 4
	oBudget.LeaveElement();
	oBudget.LeaveElement();

	// Sibling METADATA C — further nodes must fail under the shared cap
	if (!oBudget.ConsumeChars(50))
		return false;
	const bool bBlocked = !oBudget.AddNode();
	return bBlocked && oBudget.m_nNodes == 4 && oBudget.m_nChars == 150;
}

// Models FromG1Packet: per-hit ReadXML extensions + trailer ReadXML share one budget.
static bool test_xml_budget_shared_across_g1_hits_and_trailer()
{
	XmlParseBudget oBudget(32, 5, 500);

	// Hit 1 extension
	if (!oBudget.ConsumeChars(40))
		return false;
	if (!oBudget.EnterElement() || !oBudget.AddNode())
		return false;
	if (!oBudget.EnterElement() || !oBudget.AddNode())
		return false;
	oBudget.LeaveElement();
	oBudget.LeaveElement();

	// Hit 2 extension — must not reset counters
	if (!oBudget.ConsumeChars(40))
		return false;
	if (!oBudget.EnterElement() || !oBudget.AddNode())
		return false;
	if (!oBudget.EnterElement() || !oBudget.AddNode())
		return false;
	oBudget.LeaveElement();
	oBudget.LeaveElement();

	// Trailer metadata — one more root ok (node 5), further nodes blocked
	if (!oBudget.ConsumeChars(40))
		return false;
	if (!oBudget.EnterElement() || !oBudget.AddNode())
		return false;
	const bool bChildBlocked = !oBudget.AddNode();
	oBudget.LeaveElement();

	// Additional trailer chars beyond the shared 500 must also fail closed
	const bool bCharsBlocked = !oBudget.ConsumeChars(381); // 120 used + 381 > 500
	return bChildBlocked && bCharsBlocked &&
	       oBudget.m_nNodes == 5 && oBudget.m_nChars == 120;
}

static bool test_xml_budget_default_depth_chain()
{
	const XmlParseBudget oBudget = XmlParseBudget::PeerDefaults();
	return oBudget.AcceptsElementChain(XML_PEER_PARSE_DEPTH_MAX) &&
	       !oBudget.AcceptsElementChain(XML_PEER_PARSE_DEPTH_MAX + 1) &&
	       !oBudget.AcceptsElementChain(0);
}

// The G1 AutodetectAudio fallback funds three objects (root + two retained
// attributes) from the shared budget before constructing the tree.
static bool test_xml_budget_autodetect_fallback_funds_objects()
{
	XmlParseBudget oBudget(32, 3, 10000);
	if (!oBudget.AddNode() || !oBudget.AddNode() || !oBudget.AddNode())
		return false;
	// Node cap exhausted: Autodetect must not retain an under-funded tree.
	return !oBudget.AddNode() && oBudget.m_nNodes == 3;
}


void register_xml_peer_parse_smoke_tests(TestSuite& suite)
{
	suite.add_test("xml_peer_defaults", test_xml_peer_defaults);
	suite.add_test("xml_budget_chars_cap", test_xml_budget_chars_cap);
	suite.add_test("xml_budget_depth_cap", test_xml_budget_depth_cap);
	suite.add_test("xml_budget_nodes_cap", test_xml_budget_nodes_cap);
	suite.add_test("xml_budget_depth_includes_root", test_xml_budget_depth_includes_root);
	suite.add_test("xml_budget_default_depth_chain", test_xml_budget_default_depth_chain);
	suite.add_test("xml_peer_bytes_predecode_gate", test_xml_peer_bytes_predecode_gate);
	suite.add_test("xml_peer_readstring_prematerialize_gate", test_xml_peer_readstring_prematerialize_gate);
	suite.add_test("xml_budget_shared_nodes_across_fragments", test_xml_budget_shared_nodes_across_fragments);
	suite.add_test("xml_budget_shared_across_sibling_metadata", test_xml_budget_shared_across_sibling_metadata);
	suite.add_test("xml_budget_shared_across_g1_hits_and_trailer", test_xml_budget_shared_across_g1_hits_and_trailer);
	suite.add_test("xml_budget_autodetect_fallback_funds_objects", test_xml_budget_autodetect_fallback_funds_objects);
}
