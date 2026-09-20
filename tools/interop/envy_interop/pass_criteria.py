"""Documented PASS criteria per scenario.

A process being alive is never enough for a protocol PASS unless the scenario
is explicitly a startup check.
"""

from __future__ import annotations

from typing import Dict

# scenario_id → human-readable PASS condition (also embedded in reports)
PASS_CRITERIA: Dict[str, str] = {
    "harness_self_check": "Harness version and git SHA recorded.",
    "envy_capability_honesty": (
        "Advertise/implement tables match current develop; compression_send is True; "
        "no stale compression-send debt; AICH/SecureIdent/CryptLayer/ExtMP/Kad Hello "
        "bits remain honest zeros where unimplemented."
    ),
    "golden_envy_hello_parse": "Committed Envy self-golden Hello parses and matches advertise table.",
    "golden_envy_helloanswer_parse": "Committed Envy self-golden HelloAnswer parses and matches advertise table.",
    "fixture_generation": "Deterministic 64 KiB fixture written with ED2K/SHA-256 digests.",
    "hello_capture_import": "Operator capture ingested, parsed, and written as sanitized candidate.",
    "envy_startup": "Owned Envy process launched into isolated profile and stayed alive for startup timeout.",
    "reference_startup": "Owned reference process launched into isolated profile and stayed alive for startup timeout.",
    "ed2k_connection": "TCP connection evidence between ENVY and reference (log or pcap) on configured ports.",
    "hello": "Hello (0x01) packet/log evidence with parseable MiscOptions.",
    "hello_answer": "HelloAnswer (0x4C) packet/log evidence with parseable MiscOptions.",
    "muleinfo": "MuleInfo (0xC5/0x01) or MuleInfoAnswer (0xC5/0x02) packet evidence.",
    "capability_negotiation": "Both Hello-family frames show expected capability bits for the scenario.",
    "peer_transfer": "Fixture transfer completed with matching digests (or equivalent transfer evidence).",
    "source_exchange": "SourceEx REQUEST/ANSWER (0x81–0x84) packet evidence observed.",
    "large_file_capability": "Large-file bit negotiated and I64 request/part evidence where practical.",
    "compressed_transfer_ref_to_envy": (
        "COMPRESSEDPART (0x40) from reference accepted by ENVY plus transfer correctness evidence."
    ),
    "compressed_transfer_envy_to_ref": (
        "COMPRESSEDPART (0x40) emitted by ENVY and accepted by reference plus transfer correctness."
    ),
    "compressed_transfer_i64": (
        "COMPRESSEDPART_I64 (0xA1) path evidenced (emit or accept) with transfer correctness."
    ),
    "compressed_transfer_uncompressed_fallback": (
        "Uncompressed SENDINGPART used when compression not beneficial/supported, with evidence."
    ),
    "lowid_highid_highid": "HighID↔HighID baseline session evidenced (Hello + optional transfer).",
    "lowid_publicip_req": "PUBLICIP_REQ (0x97) packet evidence.",
    "lowid_publicip_answer": "PUBLICIP_ANSWER (0x98) with 4-byte IPv4 body evidence.",
    "lowid_server_callback": "Classic server callback path evidenced (requires external infra + flag).",
    "lowid_c2c_callback": "C2C CALLBACK (0x99) 38-byte layout evidenced and consumed.",
    "lowid_reaskcallback": "Production not implemented — cannot PASS.",
    "lowid_buddy": "Production not implemented — cannot PASS.",
    "lowid_buddyping": "Production not implemented — cannot PASS.",
    "lowid_buddypong": "Production not implemented — cannot PASS.",
    "kad_nodes_dat_local": "EnvyTests cover nodes.dat parse (#254); harness SKIP until sanitized Windows bootstrap logs are attached (#160).",
    "kad_bootstrap": "Kad bootstrap contact acquisition evidenced (local or opt-in external).",
    "kad_hello": "Kad HELLO request/response evidence.",
    "kad_ping_pong": "Kad PING/PONG evidence.",
    "kad_find_node": "Kad FIND_NODE evidence.",
    "kad_search_source": "SEARCH_SOURCE_REQ (0x34) evidence from app-trigger path.",
    "kad_search_res": "SEARCH_RES (0x3B) delivered into ED2K sources (not merely Kad process alive).",
    "kad_routing": "Routing-table maintenance evidence (contact insert/verify/evict logs or fixture).",
    "kad_tcp_firewall": "FIREWALLED_REQ/RES/ACK baseline evidence.",
    "kad_udp_firewall": "Production not implemented — cannot PASS.",
    "kad_findbuddy": "Production not implemented — cannot PASS.",
    "kad_buddy_lifecycle": "Production not implemented — cannot PASS.",
    "kad_callback": "Production not implemented — cannot PASS.",
    "optional_pcap": "dumpcap/tshark started and stopped as owned process, or SKIP when tools absent.",
}


def criteria_for(scenario_id: str) -> str:
    return PASS_CRITERIA.get(scenario_id, "Documented PASS criteria missing for this scenario id.")
