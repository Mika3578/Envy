"""Shared opcodes, result states, and Envy capability honesty tables.

Capability truth is recalculated from production code on develop after
#251/#252/#254/#255/#256/#257/#258/#261. Do not infer support from opcode
constants alone — each row cites the implementing unit.
"""

from __future__ import annotations

from enum import Enum

# ---------------------------------------------------------------------------
# Machine-readable scenario results (final run outcomes)
# ---------------------------------------------------------------------------


class Result(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    SKIP = "SKIP"
    NOT_IMPLEMENTED = "NOT_IMPLEMENTED"


# ---------------------------------------------------------------------------
# Three orthogonal axes — never conflate these
# ---------------------------------------------------------------------------


class ProductionState(str, Enum):
    """Whether ENVY production code implements the protocol behavior."""

    IMPLEMENTED = "implemented"
    PARTIAL = "partial"
    NOT_IMPLEMENTED = "not_implemented"


class HarnessState(str, Enum):
    """Whether this harness can automate or collect evidence for the behavior."""

    AUTOMATED = "automated"  # deterministic handler, no live peers needed
    EVIDENCE_HOOKS = "evidence_hooks"  # can PASS with packet/log evidence
    REGISTERED_ONLY = "registered_only"  # id reserved; no evidence path yet
    NOT_APPLICABLE = "not_applicable"  # production absent; no harness work


class EvidenceState(str, Enum):
    """Live interoperability evidence status (issue #160)."""

    VERIFIED = "verified"
    UNVERIFIED = "unverified"
    PENDING_OPERATOR = "pending_operator"
    NOT_APPLICABLE = "not_applicable"


# ---------------------------------------------------------------------------
# Network / evidence classes
# ---------------------------------------------------------------------------


class NetworkClass(str, Enum):
    NONE = "none"
    LOCAL = "local"
    EXTERNAL = "external"


class EvidenceClass(str, Enum):
    DETERMINISTIC = "deterministic"
    LOCAL_INTEGRATION = "local_integration"
    PUBLIC_NETWORK = "public_network"
    CAPTURED_EVIDENCE = "captured_evidence"
    LOCAL_DETERMINISTIC = "local_deterministic"  # e.g. nodes.dat parse fixtures


# ---------------------------------------------------------------------------
# ED2K opcodes (eMule / Envy EDPacket.h)
# ---------------------------------------------------------------------------

ED2K_PROTOCOL_EDONKEY = 0xE3
ED2K_PROTOCOL_EMULE = 0xC5
ED2K_PROTOCOL_KAD = 0xE4  # OP_KADEMLIAHEADER (UDP 2-byte header)
ED2K_PROTOCOL_KAD_PACKED = 0xE5  # OP_KADEMLIAPACKEDPROT (not inflated here)

ED2K_C2C_HELLO = 0x01
ED2K_C2C_HELLOANSWER = 0x4C
ED2K_C2C_EMULEINFO = 0x01  # on protocol 0xC5
ED2K_C2C_EMULEINFOANSWER = 0x02
ED2K_C2C_REQUESTSOURCES = 0x81
ED2K_C2C_ANSWERSOURCES = 0x82
ED2K_C2C_REQUESTSOURCES2 = 0x83
ED2K_C2C_ANSWERSOURCES2 = 0x84
ED2K_C2C_COMPRESSEDPART = 0x40
ED2K_C2C_COMPRESSEDPART_I64 = 0xA1
ED2K_C2C_PUBLICIP_REQ = 0x97
ED2K_C2C_PUBLICIP_ANSWER = 0x98
ED2K_C2C_CALLBACK = 0x99
ED2K_C2C_REASKCALLBACKTCP = 0x9A
ED2K_C2C_BUDDYPING = 0x9F
ED2K_C2C_BUDDYPONG = 0xA0
ED2K_C2C_FWCHECKUDPREQ = 0xA7
ED2K_C2C_KAD_FWTCPCHECK_ACK = 0xA8

# Kad2 opcodes (Envy/EDPacket.h) — UDP on protocol 0xE4, not eMule TCP 0xC5
KAD_OP_HELLO_REQ = 0x01
KAD_OP_HELLO_RES = 0x09
KAD_OP_PING = 0x60
KAD_OP_PONG = 0x61
KAD_OP_FIND_NODE = 0x21
KAD_OP_SEARCH_SOURCE_REQ = 0x34  # KADEMLIA2_SEARCH_SOURCE_REQ
KAD_OP_SEARCH_RES = 0x3B  # KADEMLIA2_SEARCH_RES (0x35 is SEARCH_NOTES_REQ)
KAD_OP_FIREWALLED_REQ = 0x50
KAD_OP_FIREWALLED_RES = 0x58
KAD_OP_FIREWALLED_ACK_RES = 0x59

ED2K_CT_NAME = 0x01
ED2K_CT_VERSION = 0x11
ED2K_CT_UDPPORTS = 0xF9
ED2K_CT_FEATUREVERSIONS = 0xFA
ED2K_CT_SOFTWAREVERSION = 0xFB
ED2K_CT_MOREFEATUREVERSIONS = 0xFE

ED2K_TAG_STRING = 0x02
ED2K_TAG_INT = 0x03

# Frozen Envy self-golden MiscOptions from tests/test_ed2k_hello_golden.cpp.
ENVY_GOLDEN_MISC_OPTIONS1 = 0x12102211
ENVY_GOLDEN_MISC_OPTIONS2 = 0x00000C10
ENVY_GOLDEN_CLIENT_ID = 0x11223344
ENVY_GOLDEN_TCP_PORT = 4662
ENVY_GOLDEN_SOFTWARE_VERSION = 0x50080000

# Advertised Hello bits on current develop (Ed2kHelloCapabilities.h + SendHello).
# Compression nibble 1 is now consistent with send-side COMPRESSEDPART (#252).
ENVY_ADVERTISED = {
    "aich": 0,
    "unicode": 1,
    "udp": 2,
    "compression": 1,
    "secureident": 0,
    "source_exchange": 2,
    "extended_request": 2,
    "comments": 1,
    "preview": 1,
    "captcha": 1,
    "source_exchange2": 1,
    "cryptlayer_supports": 0,
    "cryptlayer_requests": 0,
    "cryptlayer_requires": 0,
    "ext_multipacket": 0,
    "large_files": 1,
    "kad": 0,  # Hello Kad nibble stays 0 until Buddy/UDP firewall + live interop
}

# Implemented behavior on current develop — independent of advertisement.
# Sources: Ed2kCompressedUpload.h + UploadTransferED2K.cpp (#252),
# Ed2kLowIdCallback.h + EDClient.cpp (#255/#258), KadNodesDat.h (#254),
# KadFirewallCheck.h (#256), KadRoutingTable.h (#257),
# KadSearchResDelivery.h (#251), KadSearchSourceRequest.h (#261).
ENVY_IMPLEMENTED = {
    "aich_c2c": False,  # #87 — no C2C AICH handlers
    "unicode": True,
    "udp": True,
    "compression_receive": True,
    "compression_send": True,  # #252 — DispatchNextChunk COMPRESSEDPART / I64
    "secureident_rsa": False,  # #75
    "source_exchange": True,
    "source_exchange2": True,
    "extended_request": True,
    "comments": True,
    "preview": True,
    "captcha": True,
    "cryptlayer_tcp_obfuscation": False,  # #121
    "ext_multipacket": False,  # #129 / #87
    "large_files": True,
    "publicip": True,  # #255/#258 phase-1 PUBLICIP_REQ/ANSWER
    "c2c_callback": True,  # #255/#258 phase-1 CALLBACK 0x99
    "reaskcallbacktcp": False,  # needs Buddy
    "kad_app_integrated": True,  # #261 SearchSource from downloads (Hello nibble still 0)
    "kad_nodes_dat": True,  # #254 local v1/v2/v3 parse/bootstrap prep
    "kad_bootstrap": True,  # local bootstrap path; live DHT unverified
    "kad_hello": True,  # wire handlers present
    "kad_ping_pong": True,
    "kad_find_node": True,
    "kad_search_source": True,  # #261 app-trigger + wire
    "kad_search_res_delivery": True,  # #251 → AddSourceED2K
    "kad_routing": True,  # #257
    "kad_tcp_firewall": True,  # #256 baseline
    "kad_udp_firewall": False,
    "buddy": False,
    "kad_callback": False,
    "lowid_server_callback": True,  # classic server push pre-existed
}

# Documented advertise vs implement mismatches (empty when tables agree).
# Keep this tuple empty rather than inventing debt — the honesty scenario
# fails if a stale compression-send=False row reappears.
ENVY_KNOWN_ADVERTISE_DEBT: tuple = ()

# Full capability matrix for reports / honesty scenario (feature → states).
# production / harness / evidence are orthogonal.
ENVY_CAPABILITY_MATRIX = {
    "aich_c2c": {
        "production": ProductionState.NOT_IMPLEMENTED.value,
        "harness": HarnessState.NOT_APPLICABLE.value,
        "evidence": EvidenceState.NOT_APPLICABLE.value,
        "advertised": 0,
        "cite": "Ed2kHelloCapabilities.h Ed2kAichAdvertisedVersion()==0; no C2C handlers",
        "issue": 87,
    },
    "secureident_rsa": {
        "production": ProductionState.NOT_IMPLEMENTED.value,
        "harness": HarnessState.NOT_APPLICABLE.value,
        "evidence": EvidenceState.NOT_APPLICABLE.value,
        "advertised": 0,
        "cite": "SecureIdentPolicy.h / #75",
        "issue": 75,
    },
    "cryptlayer_tcp_obfuscation": {
        "production": ProductionState.NOT_IMPLEMENTED.value,
        "harness": HarnessState.NOT_APPLICABLE.value,
        "evidence": EvidenceState.NOT_APPLICABLE.value,
        "advertised": 0,
        "cite": "Ed2kCryptLayerTcpObfuscationImplemented()==FALSE (#121)",
        "issue": 121,
    },
    "ext_multipacket": {
        "production": ProductionState.NOT_IMPLEMENTED.value,
        "harness": HarnessState.NOT_APPLICABLE.value,
        "evidence": EvidenceState.NOT_APPLICABLE.value,
        "advertised": 0,
        "cite": "Ed2kExtMultipacketAdvertised()==FALSE (#129)",
        "issue": 129,
    },
    "source_exchange": {
        "production": ProductionState.IMPLEMENTED.value,
        "harness": HarnessState.EVIDENCE_HOOKS.value,
        "evidence": EvidenceState.UNVERIFIED.value,
        "advertised": 2,
        "cite": "ED2K SourceEx v1/v2 C2C (IPv4-only wire)",
        "issue": 87,
    },
    "large_files": {
        "production": ProductionState.IMPLEMENTED.value,
        "harness": HarnessState.EVIDENCE_HOOKS.value,
        "evidence": EvidenceState.UNVERIFIED.value,
        "advertised": 1,
        "cite": "REQUESTPARTS_I64 / SENDINGPART_I64 path",
        "issue": 87,
    },
    "compression_receive": {
        "production": ProductionState.IMPLEMENTED.value,
        "harness": HarnessState.EVIDENCE_HOOKS.value,
        "evidence": EvidenceState.UNVERIFIED.value,
        "advertised": 1,
        "cite": "EDPacket inflate path for COMPRESSEDPART",
        "issue": 87,
    },
    "compression_send": {
        "production": ProductionState.IMPLEMENTED.value,
        "harness": HarnessState.EVIDENCE_HOOKS.value,
        "evidence": EvidenceState.UNVERIFIED.value,
        "advertised": 1,
        "cite": "UploadTransferED2K::DispatchNextChunk + Ed2kCompressedUpload.h (#252)",
        "issue": 87,
    },
    "publicip": {
        "production": ProductionState.PARTIAL.value,
        "harness": HarnessState.EVIDENCE_HOOKS.value,
        "evidence": EvidenceState.UNVERIFIED.value,
        "advertised": None,
        "cite": "Ed2kLowIdCallback.h PUBLICIP_REQ/ANSWER (#255/#258)",
        "issue": 87,
    },
    "c2c_callback": {
        "production": ProductionState.PARTIAL.value,
        "harness": HarnessState.EVIDENCE_HOOKS.value,
        "evidence": EvidenceState.UNVERIFIED.value,
        "advertised": None,
        "cite": "CEDClient CALLBACK 0x99 38-byte Buddy layout (#255/#258)",
        "issue": 87,
    },
    "reaskcallbacktcp": {
        "production": ProductionState.NOT_IMPLEMENTED.value,
        "harness": HarnessState.REGISTERED_ONLY.value,
        "evidence": EvidenceState.NOT_APPLICABLE.value,
        "advertised": None,
        "cite": "REASKCALLBACKTCP ignored until Buddy exists",
        "issue": 87,
    },
    "kad_source_search": {
        "production": ProductionState.IMPLEMENTED.value,
        "harness": HarnessState.EVIDENCE_HOOKS.value,
        "evidence": EvidenceState.UNVERIFIED.value,
        "advertised": 0,
        "cite": "DownloadWithSearch::MaybeSearchKadSources (#261); Hello Kad nibble still 0",
        "issue": 86,
    },
    "kad_routing": {
        "production": ProductionState.IMPLEMENTED.value,
        "harness": HarnessState.EVIDENCE_HOOKS.value,
        "evidence": EvidenceState.UNVERIFIED.value,
        "advertised": 0,
        "cite": "KadRoutingTable.h (#257)",
        "issue": 86,
    },
    "kad_tcp_firewall": {
        "production": ProductionState.PARTIAL.value,
        "harness": HarnessState.EVIDENCE_HOOKS.value,
        "evidence": EvidenceState.UNVERIFIED.value,
        "advertised": 0,
        "cite": "KadFirewallCheck.h FIREWALLED_REQ/RES/ACK (#256)",
        "issue": 86,
    },
    "kad_udp_firewall": {
        "production": ProductionState.NOT_IMPLEMENTED.value,
        "harness": HarnessState.REGISTERED_ONLY.value,
        "evidence": EvidenceState.NOT_APPLICABLE.value,
        "advertised": 0,
        "cite": "FWCHECKUDPREQ / UDP tester absent",
        "issue": 86,
    },
    "buddy": {
        "production": ProductionState.NOT_IMPLEMENTED.value,
        "harness": HarnessState.REGISTERED_ONLY.value,
        "evidence": EvidenceState.NOT_APPLICABLE.value,
        "advertised": 0,
        "cite": "FINDBUDDY / BUDDYPING / BUDDYPONG absent",
        "issue": 86,
    },
    "kad_callback": {
        "production": ProductionState.NOT_IMPLEMENTED.value,
        "harness": HarnessState.REGISTERED_ONLY.value,
        "evidence": EvidenceState.NOT_APPLICABLE.value,
        "advertised": 0,
        "cite": "Kad callback mechanism absent",
        "issue": 86,
    },
}
