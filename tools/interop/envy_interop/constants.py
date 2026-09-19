"""Shared opcodes, result states, and Envy capability honesty tables."""

from __future__ import annotations

from enum import Enum

# ---------------------------------------------------------------------------
# Machine-readable scenario results
# ---------------------------------------------------------------------------


class Result(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    SKIP = "SKIP"
    NOT_IMPLEMENTED = "NOT_IMPLEMENTED"


# ---------------------------------------------------------------------------
# Network classes — never disguise external P2P as deterministic tests
# ---------------------------------------------------------------------------


class NetworkClass(str, Enum):
    NONE = "none"  # no sockets; harness mechanics / golden parse
    LOCAL = "local"  # loopback / explicit LAN
    EXTERNAL = "external"  # public ED2K/Kad infrastructure


class EvidenceClass(str, Enum):
    DETERMINISTIC = "deterministic"  # first-party, #91-adjacent, no live peers
    LOCAL_INTEGRATION = "local_integration"  # opt-in, real processes, isolated
    PUBLIC_NETWORK = "public_network"  # opt-in, Internet-dependent
    CAPTURED_EVIDENCE = "captured_evidence"  # operator-supplied packets/logs


# ---------------------------------------------------------------------------
# ED2K opcodes (eMule / Envy EDPacket.h)
# ---------------------------------------------------------------------------

ED2K_PROTOCOL_EDONKEY = 0xE3
ED2K_PROTOCOL_EMULE = 0xC5

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

ED2K_CT_NAME = 0x01
ED2K_CT_VERSION = 0x11
ED2K_CT_UDPPORTS = 0xF9
ED2K_CT_FEATUREVERSIONS = 0xFA
ED2K_CT_SOFTWAREVERSION = 0xFB
ED2K_CT_MOREFEATUREVERSIONS = 0xFE

ED2K_TAG_STRING = 0x02
ED2K_TAG_INT = 0x03

# Frozen Envy self-golden MiscOptions from tests/test_ed2k_hello_golden.cpp.
# Do not "fix" production Hello bits from this harness if they diverge.
ENVY_GOLDEN_MISC_OPTIONS1 = 0x12102211
ENVY_GOLDEN_MISC_OPTIONS2 = 0x00000C10
ENVY_GOLDEN_CLIENT_ID = 0x11223344
ENVY_GOLDEN_TCP_PORT = 4662
ENVY_GOLDEN_SOFTWARE_VERSION = 0x50080000

# Advertised Hello bits on current develop (Ed2kHelloCapabilities.h + SendHello).
# Compression nibble 1 is advertised while compressed *upload* is missing (#87).
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
    "kad": 0,
}

# Implemented behavior on current develop — independent of advertisement.
# Keep this table honest; do not flip production bits to satisfy the harness.
ENVY_IMPLEMENTED = {
    "aich_c2c": False,  # #87
    "unicode": True,
    "udp": True,
    "compression_receive": True,
    "compression_send": False,  # #87 — COMPRESSEDPART send missing
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
    "kad_app_integrated": False,  # #86 — Hello Kad nibble stays 0
    "lowid_callback": False,  # #87
    "buddy": False,  # #86 / #87
}

# Documented mismatches (advertise vs implement). Reported, not patched.
ENVY_KNOWN_ADVERTISE_DEBT = (
    {
        "field": "compression",
        "advertised": 1,
        "implemented_send": False,
        "issue": 87,
        "note": "Compression nibble is still advertised while compressed upload is missing.",
    },
)
