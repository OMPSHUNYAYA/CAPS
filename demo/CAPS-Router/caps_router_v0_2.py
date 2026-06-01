#!/usr/bin/env python3
"""
CAPS-Router v0.2
Capability Admissibility Protection System

Structural visibility demonstration for the network infrastructure domain.

Core principle:
capability_visible iff protection_structure_complete AND protection_structure_consistent AND request_structure_complete AND request_structure_consistent

Formula:
capability_visible = resolve(capability, scenario, protection_profile, request_structure)
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from dataclasses import dataclass
from typing import Dict, Tuple


VISIBLE = "VISIBLE"
ISOLATED = "ISOLATED"
DORMANT = "DORMANT"
FORBIDDEN = "FORBIDDEN"
BLOCKED = "BLOCKED"

PROJECT_NAME = "CAPS-Router"

TELEMETRY_RESOLUTION_BASIS = "Telemetry is event-admitted by observability export structure, not automatic router capability visibility."
REMOTE_ADMIN_RESOLUTION_BASIS = "Remote administration is admitted only by bounded maintenance or managed-service structure, not by network capability existence."
GUEST_NETWORK_RESOLUTION_BASIS = "Guest network capability may exist while internal network visibility remains structurally refused."


def command_name() -> str:
    return Path(sys.argv[0]).name


@dataclass(frozen=True)
class Capability:
    name: str
    purpose: str
    exposure: int
    required_for: Tuple[str, ...]


CAPABILITIES: Dict[str, Capability] = {
    "packet_forwarding": Capability("Packet Forwarding", "Core packet movement", 1, ("home_browse", "guest_wifi", "vpn_access", "mesh_join", "qos_streaming", "firmware_update", "remote_admin", "traffic_observe")),
    "nat": Capability("NAT", "Address translation boundary", 2, ("home_browse", "guest_wifi", "vpn_access", "qos_streaming")),
    "stateful_firewall": Capability("Stateful Firewall", "Boundary protection", 2, ("home_browse", "guest_wifi", "vpn_access", "mesh_join", "qos_streaming", "remote_admin")),
    "dhcp_server": Capability("DHCP Server", "Local address assignment", 2, ("home_browse", "guest_wifi", "mesh_join")),
    "dns_resolver": Capability("DNS Resolver", "Name resolution support", 3, ("home_browse", "guest_wifi", "qos_streaming")),
    "wifi_radio": Capability("WiFi Radio", "Wireless access surface", 4, ("home_browse", "guest_wifi", "mesh_join", "qos_streaming")),
    "guest_network": Capability("Guest Network", "Segmented guest connectivity", 5, ("guest_wifi",)),
    "lan_switch": Capability("LAN Switch", "Local wired switching", 3, ("home_browse", "qos_streaming", "traffic_observe")),
    "local_admin_console": Capability("Local Admin Console", "Local configuration surface", 6, ("local_admin", "firmware_update")),
    "remote_admin_api": Capability("Remote Admin API", "External management surface", 9, ("remote_admin", "managed_service")),
    "firmware_update": Capability("Firmware Update", "Router firmware update channel", 8, ("firmware_update", "managed_service")),
    "vpn_server": Capability("VPN Server", "Authenticated remote network entry", 8, ("vpn_access",)),
    "vpn_client": Capability("VPN Client", "Outbound tunnel participation", 7, ("vpn_access",)),
    "cloud_management": Capability("Cloud Management", "Vendor or operator cloud control plane", 9, ("remote_admin", "managed_service", "firmware_update")),
    "telemetry_export": Capability("Telemetry Export", "Network statistics and diagnostic export", 8, ()),
    "traffic_analytics": Capability("Traffic Analytics", "Traffic classification and observation", 7, ("traffic_observe", "qos_streaming")),
    "qos_engine": Capability("QoS Engine", "Priority and flow shaping", 5, ("qos_streaming",)),
    "mesh_pairing": Capability("Mesh Pairing", "Nearby mesh node admission", 6, ("mesh_join",)),
    "parental_controls": Capability("Parental Controls", "Policy-based local access control", 6, ("parental_policy",)),
    "usb_sharing": Capability("USB Sharing", "Local peripheral sharing surface", 6, ("local_admin",)),
}


SCENARIOS = {
    "home_browse": {
        "intent": "Normal home browsing through local router structure",
        "allow_external": False,
        "allow_observability_export": False,
        "maintenance_window": False,
        "authenticated_remote": False,
        "segmentation_required": False,
        "admin_required": False,
        "vpn_required": False,
        "cloud_required": False,
        "mesh_required": False,
        "policy_required": False,
        "timing_window_required": False,
        "proximity_required": True,
    },
    "guest_wifi": {
        "intent": "Guest device receives segmented internet access",
        "allow_external": False,
        "allow_observability_export": False,
        "maintenance_window": False,
        "authenticated_remote": False,
        "segmentation_required": True,
        "admin_required": False,
        "vpn_required": False,
        "cloud_required": False,
        "mesh_required": False,
        "policy_required": False,
        "timing_window_required": True,
        "proximity_required": True,
    },
    "vpn_access": {
        "intent": "Authenticated VPN access under bounded remote structure",
        "allow_external": True,
        "allow_observability_export": False,
        "maintenance_window": False,
        "authenticated_remote": True,
        "segmentation_required": True,
        "admin_required": False,
        "vpn_required": True,
        "cloud_required": False,
        "mesh_required": False,
        "policy_required": False,
        "timing_window_required": True,
        "proximity_required": False,
    },
    "local_admin": {
        "intent": "Local administrator configures router from local network",
        "allow_external": False,
        "allow_observability_export": False,
        "maintenance_window": False,
        "authenticated_remote": False,
        "segmentation_required": False,
        "admin_required": True,
        "vpn_required": False,
        "cloud_required": False,
        "mesh_required": False,
        "policy_required": False,
        "timing_window_required": True,
        "proximity_required": True,
    },
    "remote_admin": {
        "intent": "Remote administrator requests bounded management visibility",
        "allow_external": True,
        "allow_observability_export": False,
        "maintenance_window": True,
        "authenticated_remote": True,
        "segmentation_required": True,
        "admin_required": True,
        "vpn_required": False,
        "cloud_required": True,
        "mesh_required": False,
        "policy_required": False,
        "timing_window_required": True,
        "proximity_required": False,
    },
    "firmware_update": {
        "intent": "Authenticated firmware update during maintenance posture",
        "allow_external": True,
        "allow_observability_export": False,
        "maintenance_window": True,
        "authenticated_remote": True,
        "segmentation_required": True,
        "admin_required": True,
        "vpn_required": False,
        "cloud_required": True,
        "mesh_required": False,
        "policy_required": False,
        "timing_window_required": True,
        "proximity_required": False,
    },
    "managed_service": {
        "intent": "Managed service provider performs bounded diagnostic maintenance",
        "allow_external": True,
        "allow_observability_export": True,
        "maintenance_window": True,
        "authenticated_remote": True,
        "segmentation_required": True,
        "admin_required": True,
        "vpn_required": False,
        "cloud_required": True,
        "mesh_required": False,
        "policy_required": False,
        "timing_window_required": True,
        "proximity_required": False,
    },
    "traffic_observe": {
        "intent": "Local diagnostic visibility for traffic observation",
        "allow_external": False,
        "allow_observability_export": True,
        "maintenance_window": False,
        "authenticated_remote": False,
        "segmentation_required": False,
        "admin_required": True,
        "vpn_required": False,
        "cloud_required": False,
        "mesh_required": False,
        "policy_required": False,
        "timing_window_required": True,
        "proximity_required": True,
    },
    "qos_streaming": {
        "intent": "Local streaming flow receives bounded QoS treatment",
        "allow_external": False,
        "allow_observability_export": False,
        "maintenance_window": False,
        "authenticated_remote": False,
        "segmentation_required": False,
        "admin_required": False,
        "vpn_required": False,
        "cloud_required": False,
        "mesh_required": False,
        "policy_required": False,
        "timing_window_required": False,
        "proximity_required": True,
    },
    "mesh_join": {
        "intent": "Nearby mesh node joins through bounded pairing structure",
        "allow_external": False,
        "allow_observability_export": False,
        "maintenance_window": False,
        "authenticated_remote": False,
        "segmentation_required": True,
        "admin_required": False,
        "vpn_required": False,
        "cloud_required": False,
        "mesh_required": True,
        "policy_required": False,
        "timing_window_required": True,
        "proximity_required": True,
    },
    "parental_policy": {
        "intent": "Local policy structure applies bounded parental control visibility",
        "allow_external": False,
        "allow_observability_export": False,
        "maintenance_window": False,
        "authenticated_remote": False,
        "segmentation_required": False,
        "admin_required": True,
        "vpn_required": False,
        "cloud_required": False,
        "mesh_required": False,
        "policy_required": True,
        "timing_window_required": True,
        "proximity_required": True,
    },
    "unsafe_remote_admin": {
        "intent": "Remote administration requested without admissible provenance",
        "allow_external": True,
        "allow_observability_export": True,
        "maintenance_window": False,
        "authenticated_remote": False,
        "segmentation_required": False,
        "admin_required": True,
        "vpn_required": False,
        "cloud_required": True,
        "mesh_required": False,
        "policy_required": False,
        "timing_window_required": True,
        "proximity_required": False,
    },
}


PROFILES = {
    "minimal": {
        "description": "Only basic local routing visibility is admitted; external, cloud, VPN, telemetry, admin, mesh, and USB surfaces are refused.",
        "max_exposure_visible": 3,
        "allow_isolated_external": False,
        "allow_dormant_network": False,
        "allow_guest_network": False,
        "allow_admin": False,
        "allow_remote_admin": False,
        "allow_ota": False,
        "allow_vpn": False,
        "allow_cloud": False,
        "allow_telemetry": False,
        "allow_analytics": False,
        "allow_mesh": False,
        "allow_policy": False,
        "allow_usb": False,
    },
    "balanced": {
        "description": "Core local routing remains available; guest, QoS, DNS, firewall, and dormant network surfaces are bounded.",
        "max_exposure_visible": 4,
        "allow_isolated_external": False,
        "allow_dormant_network": True,
        "allow_guest_network": True,
        "allow_admin": True,
        "allow_remote_admin": False,
        "allow_ota": False,
        "allow_vpn": False,
        "allow_cloud": False,
        "allow_telemetry": False,
        "allow_analytics": True,
        "allow_mesh": False,
        "allow_policy": True,
        "allow_usb": False,
    },
    "connected": {
        "description": "VPN and selected remote surfaces may be admitted only through isolated visibility; cloud and telemetry remain refused.",
        "max_exposure_visible": 4,
        "allow_isolated_external": True,
        "allow_dormant_network": True,
        "allow_guest_network": True,
        "allow_admin": True,
        "allow_remote_admin": False,
        "allow_ota": False,
        "allow_vpn": True,
        "allow_cloud": False,
        "allow_telemetry": False,
        "allow_analytics": True,
        "allow_mesh": True,
        "allow_policy": True,
        "allow_usb": False,
    },
    "maintenance": {
        "description": "Maintenance, firmware, remote admin, and cloud management may be admitted only during authenticated maintenance posture.",
        "max_exposure_visible": 2,
        "allow_isolated_external": True,
        "allow_dormant_network": True,
        "allow_guest_network": False,
        "allow_admin": True,
        "allow_remote_admin": True,
        "allow_ota": True,
        "allow_vpn": False,
        "allow_cloud": True,
        "allow_telemetry": False,
        "allow_analytics": True,
        "allow_mesh": False,
        "allow_policy": False,
        "allow_usb": False,
    },
    "observability": {
        "description": "Diagnostic visibility is admitted under bounded local or managed observability; export remains structural.",
        "max_exposure_visible": 3,
        "allow_isolated_external": True,
        "allow_dormant_network": True,
        "allow_guest_network": False,
        "allow_admin": True,
        "allow_remote_admin": True,
        "allow_ota": False,
        "allow_vpn": False,
        "allow_cloud": True,
        "allow_telemetry": True,
        "allow_analytics": True,
        "allow_mesh": False,
        "allow_policy": False,
        "allow_usb": False,
    },
    "strict": {
        "description": "Maximum protection posture; only essential routing and boundary controls are visible.",
        "max_exposure_visible": 2,
        "allow_isolated_external": False,
        "allow_dormant_network": False,
        "allow_guest_network": False,
        "allow_admin": False,
        "allow_remote_admin": False,
        "allow_ota": False,
        "allow_vpn": False,
        "allow_cloud": False,
        "allow_telemetry": False,
        "allow_analytics": False,
        "allow_mesh": False,
        "allow_policy": False,
        "allow_usb": False,
    },
}


REQUESTS = {
    "normal": {
        "description": "Normal request aligned with the selected scenario.",
        "target": None,
        "forced_visibility": False,
        "external_request": False,
        "observability_export_request": False,
        "update_request": False,
        "admin_request": False,
        "vpn_request": False,
        "cloud_request": False,
        "mesh_request": False,
        "policy_request": False,
        "usb_request": False,
        "credential_valid": True,
        "identity_valid": True,
        "context_valid": True,
        "scope_valid": True,
        "timing_valid": True,
        "proximity_valid": True,
        "segmentation_valid": True,
    },
    "wan_probe": {
        "description": "Untrusted WAN request probes remote management visibility.",
        "target": "remote_admin_api",
        "forced_visibility": True,
        "external_request": True,
        "observability_export_request": False,
        "update_request": False,
        "admin_request": True,
        "vpn_request": False,
        "cloud_request": False,
        "mesh_request": False,
        "policy_request": False,
        "usb_request": False,
        "credential_valid": False,
        "identity_valid": False,
        "context_valid": False,
        "scope_valid": False,
        "timing_valid": False,
        "proximity_valid": True,
        "segmentation_valid": False,
    },
    "cloud_takeover": {
        "description": "Cloud management path attempts broad router visibility without admissible structure.",
        "target": "cloud_management",
        "forced_visibility": True,
        "external_request": True,
        "observability_export_request": False,
        "update_request": False,
        "admin_request": True,
        "vpn_request": False,
        "cloud_request": True,
        "mesh_request": False,
        "policy_request": False,
        "usb_request": False,
        "credential_valid": False,
        "identity_valid": False,
        "context_valid": False,
        "scope_valid": False,
        "timing_valid": False,
        "proximity_valid": True,
        "segmentation_valid": False,
    },
    "telemetry_exfiltration": {
        "description": "Telemetry export is requested without valid observability scope.",
        "target": "telemetry_export",
        "forced_visibility": True,
        "external_request": True,
        "observability_export_request": True,
        "update_request": False,
        "admin_request": False,
        "vpn_request": False,
        "cloud_request": True,
        "mesh_request": False,
        "policy_request": False,
        "usb_request": False,
        "credential_valid": True,
        "identity_valid": True,
        "context_valid": False,
        "scope_valid": False,
        "timing_valid": True,
        "proximity_valid": True,
        "segmentation_valid": False,
    },
    "forced_update": {
        "description": "Firmware update is requested without valid identity, timing, or maintenance context.",
        "target": "firmware_update",
        "forced_visibility": True,
        "external_request": True,
        "observability_export_request": False,
        "update_request": True,
        "admin_request": True,
        "vpn_request": False,
        "cloud_request": True,
        "mesh_request": False,
        "policy_request": False,
        "usb_request": False,
        "credential_valid": False,
        "identity_valid": False,
        "context_valid": False,
        "scope_valid": False,
        "timing_valid": False,
        "proximity_valid": True,
        "segmentation_valid": False,
    },
    "vpn_bruteforce": {
        "description": "VPN surface is forced without valid credentials or scope.",
        "target": "vpn_server",
        "forced_visibility": True,
        "external_request": True,
        "observability_export_request": False,
        "update_request": False,
        "admin_request": False,
        "vpn_request": True,
        "cloud_request": False,
        "mesh_request": False,
        "policy_request": False,
        "usb_request": False,
        "credential_valid": False,
        "identity_valid": False,
        "context_valid": False,
        "scope_valid": False,
        "timing_valid": True,
        "proximity_valid": True,
        "segmentation_valid": False,
    },
    "guest_escape": {
        "description": "Guest network attempts visibility into internal routing or administration surface.",
        "target": "guest_network",
        "forced_visibility": True,
        "external_request": False,
        "observability_export_request": False,
        "update_request": False,
        "admin_request": True,
        "vpn_request": False,
        "cloud_request": False,
        "mesh_request": False,
        "policy_request": False,
        "usb_request": False,
        "credential_valid": True,
        "identity_valid": True,
        "context_valid": False,
        "scope_valid": False,
        "timing_valid": True,
        "proximity_valid": True,
        "segmentation_valid": False,
    },
    "mesh_spoof": {
        "description": "Nearby mesh pairing path is probed without valid proximity and pairing scope.",
        "target": "mesh_pairing",
        "forced_visibility": True,
        "external_request": False,
        "observability_export_request": False,
        "update_request": False,
        "admin_request": False,
        "vpn_request": False,
        "cloud_request": False,
        "mesh_request": True,
        "policy_request": False,
        "usb_request": False,
        "credential_valid": False,
        "identity_valid": False,
        "context_valid": False,
        "scope_valid": False,
        "timing_valid": True,
        "proximity_valid": False,
        "segmentation_valid": False,
    },
    "dns_poison_attempt": {
        "description": "Name-resolution behavior is forced outside admissible context.",
        "target": "dns_resolver",
        "forced_visibility": True,
        "external_request": True,
        "observability_export_request": False,
        "update_request": False,
        "admin_request": False,
        "vpn_request": False,
        "cloud_request": False,
        "mesh_request": False,
        "policy_request": False,
        "usb_request": False,
        "credential_valid": False,
        "identity_valid": False,
        "context_valid": False,
        "scope_valid": False,
        "timing_valid": True,
        "proximity_valid": True,
        "segmentation_valid": False,
    },
    "usb_data_pull": {
        "description": "USB sharing surface is requested without local administrative structure.",
        "target": "usb_sharing",
        "forced_visibility": True,
        "external_request": False,
        "observability_export_request": False,
        "update_request": False,
        "admin_request": True,
        "vpn_request": False,
        "cloud_request": False,
        "mesh_request": False,
        "policy_request": False,
        "usb_request": True,
        "credential_valid": False,
        "identity_valid": False,
        "context_valid": False,
        "scope_valid": False,
        "timing_valid": True,
        "proximity_valid": True,
        "segmentation_valid": False,
    },
}


SCENARIO_ORDER = (
    "home_browse",
    "guest_wifi",
    "vpn_access",
    "local_admin",
    "remote_admin",
    "firmware_update",
    "managed_service",
    "traffic_observe",
    "qos_streaming",
    "mesh_join",
    "parental_policy",
    "unsafe_remote_admin",
)

PROFILE_ORDER = ("minimal", "balanced", "connected", "maintenance", "observability", "strict")

REQUEST_ORDER = (
    "wan_probe",
    "cloud_takeover",
    "telemetry_exfiltration",
    "forced_update",
    "vpn_bruteforce",
    "guest_escape",
    "mesh_spoof",
    "dns_poison_attempt",
    "usb_data_pull",
)


def protection_certificate_full(payload: dict) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def protection_certificate(payload: dict) -> str:
    return protection_certificate_full(payload)[:16]


def request_structure_status(request: dict) -> Tuple[bool, bool, bool]:
    complete = (
        request["credential_valid"]
        and request["identity_valid"]
        and request["context_valid"]
        and request["scope_valid"]
        and request["timing_valid"]
        and request["proximity_valid"]
        and request["segmentation_valid"]
    )
    consistency_checks = [
        not request["forced_visibility"],
        not (request["external_request"] and not request["identity_valid"]),
        not (request["observability_export_request"] and not request["scope_valid"]),
        not (request["update_request"] and not request["timing_valid"]),
        not (request["admin_request"] and not request["identity_valid"]),
        not (request["vpn_request"] and not request["credential_valid"]),
        not (request["cloud_request"] and not request["identity_valid"]),
        not (request["mesh_request"] and not request["proximity_valid"]),
        not (request["usb_request"] and not request["proximity_valid"]),
    ]
    consistent = all(consistency_checks)
    return complete, consistent, complete and consistent


def scenario_profile_consistent(scenario: dict, profile: dict) -> bool:
    checks = [
        not (scenario["allow_external"] and not scenario["authenticated_remote"]),
        not (scenario["allow_external"] and not profile["allow_isolated_external"]),
        not (scenario["allow_observability_export"] and not profile["allow_telemetry"] and scenario["cloud_required"]),
        not (scenario["maintenance_window"] and not profile["allow_ota"] and not profile["allow_remote_admin"] and not profile["allow_admin"]),
        not (scenario["vpn_required"] and not profile["allow_vpn"]),
        not (scenario["cloud_required"] and not profile["allow_cloud"]),
        not (scenario["mesh_required"] and not profile["allow_mesh"]),
        not (scenario["policy_required"] and not profile["allow_policy"]),
        not (scenario["admin_required"] and not profile["allow_admin"] and not profile["allow_remote_admin"]),
    ]
    return all(checks)


def request_profile_consistent(request: dict, profile: dict) -> bool:
    checks = [
        not (request["external_request"] and not profile["allow_isolated_external"]),
        not (request["observability_export_request"] and not profile["allow_telemetry"]),
        not (request["update_request"] and not profile["allow_ota"]),
        not (request["admin_request"] and not profile["allow_admin"] and not profile["allow_remote_admin"]),
        not (request["vpn_request"] and not profile["allow_vpn"]),
        not (request["cloud_request"] and not profile["allow_cloud"]),
        not (request["mesh_request"] and not profile["allow_mesh"]),
        not (request["policy_request"] and not profile["allow_policy"]),
        not (request["usb_request"] and not profile["allow_usb"]),
    ]
    return all(checks)


def protection_status(scenario: dict, profile: dict, request: dict) -> Tuple[bool, bool, bool, bool, bool, bool]:
    request_complete, request_consistent, request_admissible = request_structure_status(request)
    protection_complete = True
    scenario_profile_ok = scenario_profile_consistent(scenario, profile)
    request_profile_ok = request_profile_consistent(request, profile)
    protection_consistent = scenario_profile_ok and request_profile_ok
    protection_admissible = protection_complete and protection_consistent
    caps_admissible = protection_admissible and request_admissible
    return protection_complete, protection_consistent, protection_admissible, request_complete, request_consistent, caps_admissible


def raw_state_and_reason(capability_key: str, capability: Capability, scenario_key: str, scenario: dict, profile: dict, request: dict) -> Tuple[str, str]:
    required = scenario_key in capability.required_for

    if request["forced_visibility"] and request["target"] == capability_key:
        return BLOCKED, "Forced visibility attempted; structural admissibility refuses forced exposure."

    if capability_key == "telemetry_export":
        if scenario["allow_observability_export"] and profile["allow_telemetry"]:
            return ISOLATED, "Telemetry export is admitted only inside observability structure."
        return FORBIDDEN, "Telemetry capability exists, but export visibility is not admitted by the selected structure."

    if capability_key == "remote_admin_api":
        if required and scenario["allow_external"] and scenario["authenticated_remote"] and profile["allow_remote_admin"]:
            return ISOLATED, "Remote admin is required and admitted only through isolated maintenance visibility."
        if required:
            return BLOCKED, "Remote admin was requested but remote administrative structure is insufficient."
        return FORBIDDEN, "Remote admin API is not required for this scenario."

    if capability_key == "cloud_management":
        if required and scenario["cloud_required"] and profile["allow_cloud"] and scenario["authenticated_remote"]:
            return ISOLATED, "Cloud management is required and admitted only under bounded authenticated structure."
        if required:
            return BLOCKED, "Cloud management was requested but cloud or authentication structure is insufficient."
        return FORBIDDEN, "Cloud management is not required for this scenario."

    if capability_key == "firmware_update":
        if required and profile["allow_ota"] and scenario["maintenance_window"] and scenario["authenticated_remote"]:
            return ISOLATED, "Firmware update is required and admitted inside maintenance posture."
        if required:
            return BLOCKED, "Firmware update was requested but maintenance structure is insufficient."
        return FORBIDDEN, "Firmware update is not required for this scenario."

    if capability_key in {"vpn_server", "vpn_client"}:
        if required and scenario["vpn_required"] and profile["allow_vpn"] and scenario["authenticated_remote"]:
            return ISOLATED, "VPN capability is required and admitted only through authenticated isolated visibility."
        if required:
            return BLOCKED, "VPN was requested but VPN or authentication structure is insufficient."
        return FORBIDDEN, "VPN capability is not required for this scenario."

    if capability_key == "guest_network":
        if required and profile["allow_guest_network"] and scenario["segmentation_required"]:
            return ISOLATED, "Guest network is required and admitted only through segmentation structure."
        if required:
            return BLOCKED, "Guest network was requested but guest or segmentation structure is insufficient."
        return FORBIDDEN, "Guest network is not required for this scenario."

    if capability_key == "traffic_analytics":
        if required and profile["allow_analytics"]:
            if scenario["allow_observability_export"]:
                return ISOLATED, "Traffic analytics is admitted inside diagnostic visibility."
            return ISOLATED, "Traffic analytics is admitted as bounded local classification visibility."
        if required:
            return BLOCKED, "Traffic analytics was requested but analytics visibility is not admitted."
        return FORBIDDEN, "Traffic analytics is not required for this scenario."

    if capability_key == "qos_engine":
        if required and profile["allow_analytics"]:
            return VISIBLE if capability.exposure <= profile["max_exposure_visible"] else ISOLATED, "QoS is admitted for bounded flow treatment."
        if required:
            return BLOCKED, "QoS was requested but policy structure is insufficient."
        return FORBIDDEN, "QoS engine is not required for this scenario."

    if capability_key == "mesh_pairing":
        if required and profile["allow_mesh"] and scenario["mesh_required"] and scenario["proximity_required"]:
            return ISOLATED, "Mesh pairing is admitted only through bounded proximity structure."
        if required:
            return BLOCKED, "Mesh join was requested but mesh or proximity structure is insufficient."
        if profile["allow_dormant_network"]:
            return DORMANT, "Mesh pairing exists but is not currently required."
        return FORBIDDEN, "Mesh pairing is not admitted by the selected profile."

    if capability_key == "parental_controls":
        if required and profile["allow_policy"] and scenario["policy_required"]:
            return ISOLATED, "Parental policy visibility is admitted only under local policy structure."
        if required:
            return BLOCKED, "Parental policy was requested but policy structure is insufficient."
        return FORBIDDEN, "Parental controls are not required for this scenario."

    if capability_key == "usb_sharing":
        if required and profile["allow_usb"] and profile["allow_admin"]:
            return ISOLATED, "USB sharing is admitted only under local administrative structure."
        if required:
            return BLOCKED, "USB sharing was requested but local administrative structure is insufficient."
        return FORBIDDEN, "USB sharing is not required for this scenario."

    if capability_key == "local_admin_console":
        if required and profile["allow_admin"] and scenario["admin_required"] and not scenario["allow_external"]:
            if capability.exposure <= profile["max_exposure_visible"]:
                return VISIBLE, "Local admin console is required and exposure is within visible limit."
            return ISOLATED, "Local admin console is required and constrained into isolated visibility."
        if required and profile["allow_remote_admin"] and scenario["allow_external"]:
            return ISOLATED, "Administrative visibility is admitted only through remote maintenance structure."
        if required:
            return BLOCKED, "Administrative surface was requested but admin structure is insufficient."
        return FORBIDDEN, "Local admin console is not required for this scenario."

    if capability_key in {"wifi_radio", "lan_switch"}:
        if required:
            if capability.exposure <= profile["max_exposure_visible"]:
                return VISIBLE, "Access medium is required and exposure is within visible limit."
            return ISOLATED, "Access medium is required but constrained into isolated visibility."
        if profile["allow_dormant_network"]:
            return DORMANT, "Access medium exists but is not currently required."
        return FORBIDDEN, "Access medium is not admitted by the selected profile."

    if required:
        if capability.exposure <= profile["max_exposure_visible"]:
            return VISIBLE, "Capability is required and exposure is within the visible limit of the selected profile."
        if profile["allow_isolated_external"] or profile["allow_dormant_network"]:
            return ISOLATED, "Capability is required but constrained into isolated visibility."
        return BLOCKED, "Capability is required but exposure exceeds visible limit and isolation is not admitted."

    if capability.exposure <= profile["max_exposure_visible"]:
        return DORMANT, "Capability exists but is not required for this scenario."
    return FORBIDDEN, "Capability is not required and exposure exceeds the profile visibility limit."


def apply_global_admissibility_gate(raw_state: str, caps_admissible: bool) -> Tuple[str, str]:
    if caps_admissible:
        return raw_state, "Global admissibility gate remains open."
    if raw_state in {VISIBLE, ISOLATED}:
        return BLOCKED, "Global admissibility gate closed; would-be visible or isolated capability is blocked."
    return raw_state, "Global admissibility gate closed, but this capability was not visible or isolated."


def resolve_caps(scenario_key: str, profile_key: str, request_key: str = "normal") -> dict:
    if scenario_key not in SCENARIOS:
        raise ValueError(f"Unknown scenario: {scenario_key}")
    if profile_key not in PROFILES:
        raise ValueError(f"Unknown profile: {profile_key}")
    if request_key not in REQUESTS:
        raise ValueError(f"Unknown request: {request_key}")

    scenario = SCENARIOS[scenario_key]
    profile = PROFILES[profile_key]
    request = REQUESTS[request_key]

    protection_complete, protection_consistent, protection_admissible, request_complete, request_consistent, caps_admissible = protection_status(scenario, profile, request)

    states = {}
    for key, capability in CAPABILITIES.items():
        raw_state, raw_reason = raw_state_and_reason(key, capability, scenario_key, scenario, profile, request)
        final_state, gate_reason = apply_global_admissibility_gate(raw_state, caps_admissible)
        states[key] = {
            "name": capability.name,
            "purpose": capability.purpose,
            "exposure": capability.exposure,
            "raw_state": raw_state,
            "state": final_state,
            "reason": raw_reason,
            "gate_reason": gate_reason,
        }

    summary = {VISIBLE: 0, ISOLATED: 0, DORMANT: 0, FORBIDDEN: 0, BLOCKED: 0}
    for item in states.values():
        summary[item["state"]] += 1

    visible_output = [
        item["name"]
        for item in states.values()
        if item["state"] in {VISIBLE, ISOLATED}
    ]

    total_capabilities = len(states)
    admitted_count = summary[VISIBLE] + summary[ISOLATED]
    visibility_ratio = round((admitted_count / total_capabilities) * 100, 2)

    result = {
        "project": PROJECT_NAME,
        "version": "v0.2",
        "definition": "Capability Admissibility Protection System",
        "scenario": scenario_key,
        "intent": scenario["intent"],
        "profile": profile_key,
        "profile_description": profile["description"],
        "request": request_key,
        "request_description": request["description"],
        "principle": "capability_visible iff protection_structure_complete AND protection_structure_consistent AND request_structure_complete AND request_structure_consistent",
        "formula": "capability_visible = resolve(capability, scenario, protection_profile, request_structure)",
        "capability": "network_infrastructure",
        "visibility": "admissibility",
        "protection": "structure",
        "request_structure": "provenance",
        "global_admissibility_gate": "if protection or request structure is incomplete or inconsistent, visible and isolated capabilities collapse to BLOCKED",
        "telemetry_resolution_basis": TELEMETRY_RESOLUTION_BASIS,
        "remote_admin_resolution_basis": REMOTE_ADMIN_RESOLUTION_BASIS,
        "guest_network_resolution_basis": GUEST_NETWORK_RESOLUTION_BASIS,
        "protection_structure_complete": protection_complete,
        "protection_structure_consistent": protection_consistent,
        "protection_admissible": protection_admissible,
        "request_structure_complete": request_complete,
        "request_structure_consistent": request_consistent,
        "caps_admissible": caps_admissible,
        "states": states,
        "summary": summary,
        "total_capabilities": total_capabilities,
        "admitted_visibility_count": admitted_count if caps_admissible else 0,
        "visibility_ratio_percent": visibility_ratio if caps_admissible else 0.0,
        "final_visible_output": visible_output if caps_admissible else [],
    }
    certificate_payload = dict(result)
    result["certificate"] = protection_certificate(certificate_payload)
    result["certificate_full"] = protection_certificate_full(certificate_payload)
    return result


def print_report(result: dict, explain: bool = False) -> None:
    print(PROJECT_NAME)
    print("Capability Admissibility Protection System")
    print("-" * 72)
    print(f"Scenario: {result['scenario']}")
    print(f"Intent: {result['intent']}")
    print(f"Profile: {result['profile']}")
    print(f"Profile Note: {result['profile_description']}")
    print(f"Request: {result['request']}")
    print(f"Request Note: {result['request_description']}")
    print()
    print("Core Principle:")
    print("capability_visible iff protection_structure_complete AND protection_structure_consistent AND request_structure_complete AND request_structure_consistent")
    print()
    print("Formula:")
    print("capability_visible = resolve(capability, scenario, protection_profile, request_structure)")
    print()
    print("Structural Separation:")
    print("capability = network_infrastructure")
    print("visibility = admissibility")
    print("protection = structure")
    print("request_structure = provenance")
    print()
    print("Global Admissibility Gate:")
    print("if protection or request structure is incomplete or inconsistent, visible and isolated capabilities collapse to BLOCKED")
    print()
    print("Protection Structure:")
    print(f"complete   : {result['protection_structure_complete']}")
    print(f"consistent : {result['protection_structure_consistent']}")
    print(f"admissible : {result['protection_admissible']}")
    print()
    print("Request Structure:")
    print(f"complete   : {result['request_structure_complete']}")
    print(f"consistent : {result['request_structure_consistent']}")
    print()
    print(f"CAPS Admissible: {result['caps_admissible']}")
    print()
    print("Capability States:")
    for item in result["states"].values():
        transition = item["state"]
        if item["raw_state"] != item["state"] and item["state"] != BLOCKED:
            transition = f"candidate={item['raw_state']} -> final={item['state']}"
        print(f"- {item['name']:<22} -> {transition:<27} exposure={item['exposure']}  {item['purpose']}")
    if explain:
        print()
        print("Structural Explanation:")
        for item in result["states"].values():
            print(f"- {item['name']}: {item['reason']} {item['gate_reason']}")
    print()
    print("Summary:")
    for key, value in result["summary"].items():
        print(f"{key:<9}: {value}")
    print()
    print("Capability Surface:")
    print(f"Total capabilities: {result['total_capabilities']}")
    print(f"Admitted visibility count: {result['admitted_visibility_count']}")
    print(f"Visibility ratio: {result['visibility_ratio_percent']}%")
    print()
    print(f"Certificate: {result['certificate']}")
    print()
    print("Final Visible Output:")
    if result["caps_admissible"]:
        visible = result["final_visible_output"]
        print(", ".join(visible) if visible else "No visible capability")
    else:
        print("NO FORCED VISIBILITY")


def print_profiles() -> None:
    print(PROJECT_NAME)
    print("Available Protection Profiles")
    print("-" * 72)
    for key in PROFILE_ORDER:
        print(f"{key:<14} {PROFILES[key]['description']}")


def print_requests() -> None:
    print(PROJECT_NAME)
    print("Available Request Structures")
    print("-" * 72)
    for key in ("normal",) + REQUEST_ORDER:
        print(f"{key:<26} {REQUESTS[key]['description']}")


def compare_results(profile_key: str, request_key: str) -> list:
    return [resolve_caps(name, profile_key, request_key) for name in SCENARIO_ORDER]


def request_results(scenario_key: str, profile_key: str) -> list:
    return [resolve_caps(scenario_key, profile_key, request_key) for request_key in REQUEST_ORDER]


def matrix_results() -> list:
    rows = []
    for profile_key in PROFILE_ORDER:
        for scenario_key in SCENARIO_ORDER:
            rows.append(resolve_caps(scenario_key, profile_key, "normal"))
    return rows


def surface_results() -> list:
    return [
        resolve_caps("home_browse", "balanced", "normal"),
        resolve_caps("guest_wifi", "balanced", "normal"),
        resolve_caps("vpn_access", "connected", "normal"),
        resolve_caps("local_admin", "balanced", "normal"),
        resolve_caps("remote_admin", "maintenance", "normal"),
        resolve_caps("firmware_update", "maintenance", "normal"),
        resolve_caps("managed_service", "observability", "normal"),
        resolve_caps("traffic_observe", "observability", "normal"),
        resolve_caps("qos_streaming", "balanced", "normal"),
        resolve_caps("mesh_join", "connected", "normal"),
        resolve_caps("remote_admin", "maintenance", "wan_probe"),
        resolve_caps("firmware_update", "maintenance", "forced_update"),
        resolve_caps("managed_service", "observability", "telemetry_exfiltration"),
        resolve_caps("vpn_access", "connected", "vpn_bruteforce"),
    ]


def print_compare(results: list, profile_key: str, request_key: str) -> None:
    print(PROJECT_NAME)
    print(f"Comparison Mode: profile={profile_key}, request={request_key}")
    print("-" * 124)
    print(f"{'scenario':<20} {'admissible':<10} {'visible':>7} {'isolated':>9} {'dormant':>8} {'forbidden':>10} {'blocked':>8} {'ratio':>8} {'certificate':<16}")
    print("-" * 124)
    for result in results:
        s = result["summary"]
        print(f"{result['scenario']:<20} {str(result['caps_admissible']):<10} {s[VISIBLE]:>7} {s[ISOLATED]:>9} {s[DORMANT]:>8} {s[FORBIDDEN]:>10} {s[BLOCKED]:>8} {str(result['visibility_ratio_percent']) + '%':>8} {result['certificate']:<16}")
    print("-" * 124)
    print("Formula: capability_visible = resolve(capability, scenario, protection_profile, request_structure)")


def print_request_compare(results: list, scenario_key: str, profile_key: str) -> None:
    print(PROJECT_NAME)
    print(f"Request Comparison Mode: scenario={scenario_key}, profile={profile_key}")
    print("-" * 142)
    print(f"{'request':<26} {'prot_ok':<8} {'req_ok':<8} {'admissible':<10} {'visible':>7} {'isolated':>9} {'blocked':>8} {'target_result':<22} {'certificate':<16}")
    print("-" * 142)
    for result in results:
        s = result["summary"]
        request = REQUESTS[result["request"]]
        target = request["target"]
        if target is None:
            target_result = "none"
        else:
            raw_state = result["states"][target]["raw_state"]
            final_state = result["states"][target]["state"]
            target_result = final_state if raw_state == final_state or final_state == BLOCKED else f"{raw_state}->{final_state}"
        prot_ok = result["protection_admissible"]
        req_ok = result["request_structure_complete"] and result["request_structure_consistent"]
        print(f"{result['request']:<26} {str(prot_ok):<8} {str(req_ok):<8} {str(result['caps_admissible']):<10} {s[VISIBLE]:>7} {s[ISOLATED]:>9} {s[BLOCKED]:>8} {target_result:<22} {result['certificate']:<16}")
    print("-" * 142)
    print("Principle: unsafe request provenance blocks visibility even when router capability exists.")
    print("Formula: capability_visible = resolve(capability, scenario, protection_profile, request_structure)")


def print_matrix(results: list) -> None:
    print(PROJECT_NAME)
    print("Profile Matrix Mode")
    print("-" * 136)
    print(f"{'profile':<14} {'scenario':<20} {'admissible':<10} {'visible':>7} {'isolated':>9} {'dormant':>8} {'forbidden':>10} {'blocked':>8} {'ratio':>8} {'certificate':<16}")
    print("-" * 136)
    for result in results:
        s = result["summary"]
        print(f"{result['profile']:<14} {result['scenario']:<20} {str(result['caps_admissible']):<10} {s[VISIBLE]:>7} {s[ISOLATED]:>9} {s[DORMANT]:>8} {s[FORBIDDEN]:>10} {s[BLOCKED]:>8} {str(result['visibility_ratio_percent']) + '%':>8} {result['certificate']:<16}")
    print("-" * 136)
    print("Principle: same router capability surface, different profile, different admitted visibility.")


def print_surface(results: list) -> None:
    print(PROJECT_NAME)
    print("Capability Surface Mode")
    print("-" * 132)
    print("Principle: network capabilities may grow, but admitted visibility can remain bounded by structure.")
    print("-" * 132)
    print(f"{'scenario':<20} {'profile':<14} {'request':<26} {'admissible':<10} {'admitted':>8} {'total':>6} {'ratio':>8} {'certificate':<16}")
    print("-" * 132)
    for result in results:
        print(f"{result['scenario']:<20} {result['profile']:<14} {result['request']:<26} {str(result['caps_admissible']):<10} {result['admitted_visibility_count']:>8} {result['total_capabilities']:>6} {str(result['visibility_ratio_percent']) + '%':>8} {result['certificate']:<16}")
    print("-" * 132)
    print("Formula: capability_visible = resolve(capability, scenario, protection_profile, request_structure)")


def invariant_results() -> list:
    cases = [
        ("strict_remote_refusal", "remote_admin", "strict", "normal", False, 0),
        ("wan_probe_refusal", "remote_admin", "maintenance", "wan_probe", False, 0),
        ("cloud_takeover_refusal", "remote_admin", "maintenance", "cloud_takeover", False, 0),
        ("telemetry_exfiltration_refusal", "managed_service", "observability", "telemetry_exfiltration", False, 0),
        ("vpn_bruteforce_refusal", "vpn_access", "connected", "vpn_bruteforce", False, 0),
        ("guest_escape_refusal", "guest_wifi", "balanced", "guest_escape", False, 0),
        ("remote_admin_admission", "remote_admin", "maintenance", "normal", True, None),
        ("firmware_maintenance_admission", "firmware_update", "maintenance", "normal", True, None),
        ("vpn_normal_admission", "vpn_access", "connected", "normal", True, None),
        ("managed_observability_admission", "managed_service", "observability", "normal", True, None),
    ]
    rows = []
    for name, scenario_key, profile_key, request_key, expected_admissible, expected_count in cases:
        result = resolve_caps(scenario_key, profile_key, request_key)
        admitted = result["admitted_visibility_count"]
        pass_condition = result["caps_admissible"] == expected_admissible
        if expected_count is not None:
            pass_condition = pass_condition and admitted == expected_count
        rows.append({
            "invariant": name,
            "scenario": scenario_key,
            "profile": profile_key,
            "request": request_key,
            "expected_admissible": expected_admissible,
            "actual_admissible": result["caps_admissible"],
            "admitted_visibility_count": admitted,
            "visibility_ratio_percent": result["visibility_ratio_percent"],
            "pass": pass_condition,
            "certificate": result["certificate"],
        })
    return rows


def print_invariants(rows: list) -> None:
    print(PROJECT_NAME)
    print("Invariant Check Mode")
    print("-" * 140)
    print("Principle: unsafe or disallowed visibility must collapse while admissible structure remains reproducible.")
    print("-" * 140)
    print(f"{'invariant':<36} {'scenario':<20} {'profile':<14} {'request':<26} {'pass':<6} {'admitted':>8} {'ratio':>8} {'certificate':<16}")
    print("-" * 140)
    for row in rows:
        print(f"{row['invariant']:<36} {row['scenario']:<20} {row['profile']:<14} {row['request']:<26} {str(row['pass']):<6} {row['admitted_visibility_count']:>8} {str(row['visibility_ratio_percent']) + '%':>8} {row['certificate']:<16}")
    print("-" * 140)
    final = "PASS" if all(row["pass"] for row in rows) else "FAIL"
    print(f"Invariant Result: {final}")


VERIFY_CASE_GROUPS = {
    "baseline_local": (
        ("home_browse", "balanced", "normal"),
        ("guest_wifi", "balanced", "normal"),
        ("qos_streaming", "balanced", "normal"),
    ),
    "isolated_admission": (
        ("vpn_access", "connected", "normal"),
        ("remote_admin", "maintenance", "normal"),
        ("firmware_update", "maintenance", "normal"),
        ("managed_service", "observability", "normal"),
        ("mesh_join", "connected", "normal"),
    ),
    "unsafe_request_refusal": (
        ("remote_admin", "maintenance", "wan_probe"),
        ("remote_admin", "maintenance", "cloud_takeover"),
        ("managed_service", "observability", "telemetry_exfiltration"),
        ("firmware_update", "maintenance", "forced_update"),
        ("vpn_access", "connected", "vpn_bruteforce"),
        ("guest_wifi", "balanced", "guest_escape"),
        ("mesh_join", "connected", "mesh_spoof"),
        ("home_browse", "balanced", "dns_poison_attempt"),
        ("local_admin", "balanced", "usb_data_pull"),
    ),
    "strict_profile_refusal": (
        ("remote_admin", "strict", "normal"),
        ("vpn_access", "strict", "normal"),
        ("mesh_join", "strict", "normal"),
    ),
    "inconsistent_scenario_refusal": (
        ("unsafe_remote_admin", "balanced", "normal"),
    ),
}

VERIFY_CASES = tuple(case for group in VERIFY_CASE_GROUPS.values() for case in group)


def verification_signature(result: dict) -> dict:
    return {
        "scenario": result["scenario"],
        "profile": result["profile"],
        "request": result["request"],
        "caps_admissible": result["caps_admissible"],
        "summary": result["summary"],
        "final_visible_output": result["final_visible_output"],
        "visibility_ratio_percent": result["visibility_ratio_percent"],
        "certificate": result["certificate"],
        "certificate_full": result["certificate_full"],
    }


def run_verification() -> dict:
    first_pass = []
    second_pass = []
    for scenario_key, profile_key, request_key in VERIFY_CASES:
        first_pass.append(verification_signature(resolve_caps(scenario_key, profile_key, request_key)))
        second_pass.append(verification_signature(resolve_caps(scenario_key, profile_key, request_key)))

    case_results = []
    all_pass = True
    for first, second in zip(first_pass, second_pass):
        same = first == second
        all_pass = all_pass and same
        case_results.append({
            "scenario": first["scenario"],
            "profile": first["profile"],
            "request": first["request"],
            "same_replay": same,
            "caps_admissible": first["caps_admissible"],
            "summary": first["summary"],
            "final_visible_output": first["final_visible_output"],
            "visibility_ratio_percent": first["visibility_ratio_percent"],
            "certificate": first["certificate"],
        })

    verification_payload = {
        "project": PROJECT_NAME,
        "verification": "deterministic replay verification",
        "principle": "same structure -> same output -> same certificate",
        "case_groups": list(VERIFY_CASE_GROUPS.keys()),
        "cases": case_results,
        "result": "PASS" if all_pass else "FAIL",
    }
    verification_certificate_payload = dict(verification_payload)
    verification_payload["verification_certificate"] = protection_certificate(verification_certificate_payload)
    verification_payload["verification_certificate_full"] = protection_certificate_full(verification_certificate_payload)
    return verification_payload


def print_verify_report(report: dict) -> None:
    print(PROJECT_NAME)
    print("Deterministic Verification Mode")
    print("-" * 142)
    print("Principle: same structure -> same output -> same certificate")
    print("-" * 142)
    print(f"{'scenario':<20} {'profile':<14} {'request':<26} {'same':<6} {'admissible':<10} {'visible_output':<32} {'ratio':>8} {'certificate':<16}")
    print("-" * 142)
    for case in report["cases"]:
        visible_output = ", ".join(case["final_visible_output"]) if case["final_visible_output"] else "none"
        if len(visible_output) > 31:
            visible_output = visible_output[:28] + "..."
        print(
            f"{case['scenario']:<20} "
            f"{case['profile']:<14} "
            f"{case['request']:<26} "
            f"{str(case['same_replay']):<6} "
            f"{str(case['caps_admissible']):<10} "
            f"{visible_output:<32} "
            f"{str(case['visibility_ratio_percent']) + '%':>8} "
            f"{case['certificate']:<16}"
        )
    print("-" * 142)
    print(f"Verification Result: {report['result']}")
    print(f"Verification Certificate: {report['verification_certificate']}")
    print("Verification Certificate Meaning: deterministic fingerprint of all verification case results")
    print()
    if report["result"] == "PASS":
        print("Deterministic replay confirmed.")
    else:
        print("Deterministic replay failed.")



def challenge_results() -> list:
    cases = [
        ("capability_does_not_force_visibility", "home_browse", "balanced", "normal", "remote_admin_api", "FORBIDDEN"),
        ("telemetry_not_automatic", "home_browse", "balanced", "normal", "telemetry_export", "FORBIDDEN"),
        ("vpn_not_visible_without_vpn_structure", "home_browse", "connected", "normal", "vpn_server", "FORBIDDEN"),
        ("guest_does_not_escape_segmentation", "guest_wifi", "balanced", "guest_escape", "guest_network", "BLOCKED"),
        ("wan_probe_refused", "remote_admin", "maintenance", "wan_probe", "remote_admin_api", "BLOCKED"),
        ("cloud_takeover_refused", "remote_admin", "maintenance", "cloud_takeover", "cloud_management", "BLOCKED"),
        ("forced_update_refused", "firmware_update", "maintenance", "forced_update", "firmware_update", "BLOCKED"),
        ("dns_poison_refused", "home_browse", "balanced", "dns_poison_attempt", "dns_resolver", "BLOCKED"),
        ("vpn_admitted_when_structure_complete", "vpn_access", "connected", "normal", "vpn_server", "ISOLATED"),
        ("remote_admin_admitted_when_structure_complete", "remote_admin", "maintenance", "normal", "remote_admin_api", "ISOLATED"),
    ]
    rows = []
    for name, scenario_key, profile_key, request_key, target, expected_state in cases:
        result = resolve_caps(scenario_key, profile_key, request_key)
        actual_state = result["states"][target]["state"]
        rows.append({
            "challenge": name,
            "scenario": scenario_key,
            "profile": profile_key,
            "request": request_key,
            "target": target,
            "expected_state": expected_state,
            "actual_state": actual_state,
            "pass": actual_state == expected_state,
            "caps_admissible": result["caps_admissible"],
            "certificate": result["certificate"],
        })
    return rows


def print_challenge(rows: list) -> None:
    print(PROJECT_NAME)
    print("Challenge Mode")
    print("-" * 144)
    print("Principle: capability existence must not automatically create visibility.")
    print("-" * 144)
    print(f"{'challenge':<42} {'scenario':<20} {'profile':<14} {'request':<26} {'target':<20} {'state':<10} {'pass':<6} {'certificate':<16}")
    print("-" * 144)
    for row in rows:
        print(f"{row['challenge']:<42} {row['scenario']:<20} {row['profile']:<14} {row['request']:<26} {row['target']:<20} {row['actual_state']:<10} {str(row['pass']):<6} {row['certificate']:<16}")
    print("-" * 144)
    final = "PASS" if all(row["pass"] for row in rows) else "FAIL"
    print(f"Challenge Result: {final}")
    print("Falsification Rule: if unsafe or unrelated capability visibility is admitted, CAPS-Router fails inside this demonstrated visibility space.")


def release_manifest() -> dict:
    verification = run_verification()
    invariants = invariant_results()
    challenges = challenge_results()
    payload = {
        "project": PROJECT_NAME,
        "version": "v0.2",
        "release": "external release candidate",
        "formula": "capability_visible = resolve(capability, scenario, protection_profile, request_structure)",
        "principle": "capability_visible iff protection_structure_complete AND protection_structure_consistent AND request_structure_complete AND request_structure_consistent",
        "total_capabilities": len(CAPABILITIES),
        "scenario_count": len(SCENARIOS),
        "profile_count": len(PROFILES),
        "request_count": len(REQUESTS),
        "verification_result": verification["result"],
        "verification_certificate": verification["verification_certificate"],
        "invariant_result": "PASS" if all(row["pass"] for row in invariants) else "FAIL",
        "challenge_result": "PASS" if all(row["pass"] for row in challenges) else "FAIL",
        "capability_names": [capability.name for capability in CAPABILITIES.values()],
        "scenarios": list(SCENARIOS.keys()),
        "profiles": list(PROFILES.keys()),
        "requests": list(REQUESTS.keys()),
    }
    manifest_payload = dict(payload)
    payload["release_certificate"] = protection_certificate(manifest_payload)
    payload["release_certificate_full"] = protection_certificate_full(manifest_payload)
    return payload


def print_manifest(manifest: dict) -> None:
    print(PROJECT_NAME)
    print("Release Manifest Mode")
    print("-" * 72)
    print(f"Version: {manifest['version']}")
    print(f"Release: {manifest['release']}")
    print(f"Total capabilities: {manifest['total_capabilities']}")
    print(f"Scenario count: {manifest['scenario_count']}")
    print(f"Profile count: {manifest['profile_count']}")
    print(f"Request count: {manifest['request_count']}")
    print(f"Verification Result: {manifest['verification_result']}")
    print(f"Verification Certificate: {manifest['verification_certificate']}")
    print(f"Invariant Result: {manifest['invariant_result']}")
    print(f"Challenge Result: {manifest['challenge_result']}")
    print(f"Release Certificate: {manifest['release_certificate']}")
    print()
    print("Formula:")
    print(manifest["formula"])
    print()
    print("Principle:")
    print(manifest["principle"])
    print()
    print("Release Meaning:")
    print("Router capabilities persist. Visibility is admitted only when structure is complete and consistent.")


def print_quickstart() -> None:
    print(PROJECT_NAME)
    print("Quickstart")
    print("-" * 72)
    print("Project:")
    print("Capability Admissibility Protection System")
    print()
    print("Core Principle:")
    print("capability_visible iff protection_structure_complete AND protection_structure_consistent AND request_structure_complete AND request_structure_consistent")
    print()
    print("Formula:")
    print("capability_visible = resolve(capability, scenario, protection_profile, request_structure)")
    print()
    script = command_name()
    commands = [
        "--profiles",
        "--requests",
        "--compare --profile balanced --request normal",
        "--scenario home_browse --profile balanced --request normal --explain",
        "--scenario guest_wifi --profile balanced --request normal --explain",
        "--scenario vpn_access --profile connected --request normal --explain",
        "--scenario remote_admin --profile maintenance --request normal --explain",
        "--scenario remote_admin --profile maintenance --request wan_probe --explain",
        "--scenario firmware_update --profile maintenance --request forced_update --explain",
        "--scenario managed_service --profile observability --request telemetry_exfiltration --explain",
        "--request-compare --scenario remote_admin --profile maintenance",
        "--surface",
        "--matrix",
        "--invariants",
        "--challenge",
        "--manifest",
        "--verify",
        "--verify --json",
        "--manifest --json",
    ]
    print("Recommended Commands:")
    for command in commands:
        print(f"python {script} {command}")
    print()
    print("Expected Verification Result:")
    print("Verification Result: PASS")
    print()
    print("Release Meaning:")
    print("Router capability may exist, but network visibility is admitted only by complete and consistent protection and request structure.")


def main() -> None:
    parser = argparse.ArgumentParser(description="CAPS-Router v0.2 structural protection demo")
    parser.add_argument("--scenario", default="home_browse", choices=sorted(SCENARIOS.keys()), help="Scenario to resolve")
    parser.add_argument("--profile", default="balanced", choices=sorted(PROFILES.keys()), help="Protection profile to apply")
    parser.add_argument("--request", default="normal", choices=sorted(REQUESTS.keys()), help="Request structure to test")
    parser.add_argument("--profiles", action="store_true", help="List available protection profiles")
    parser.add_argument("--requests", action="store_true", help="List available request structures")
    parser.add_argument("--compare", action="store_true", help="Print all scenarios under one profile and request structure")
    parser.add_argument("--request-compare", "--request_compare", dest="request_compare", action="store_true", help="Print all request structures under one scenario and profile")
    parser.add_argument("--matrix", action="store_true", help="Print all scenarios across all protection profiles with normal requests")
    parser.add_argument("--surface", action="store_true", help="Print capability surface admission comparison")
    parser.add_argument("--invariants", action="store_true", help="Run focused structural invariant checks")
    parser.add_argument("--challenge", action="store_true", help="Run falsification-oriented challenge checks")
    parser.add_argument("--manifest", action="store_true", help="Print release manifest and release certificate")
    parser.add_argument("--explain", action="store_true", help="Print structural explanation for each capability state")
    parser.add_argument("--verify", action="store_true", help="Run deterministic replay verification")
    parser.add_argument("--quickstart", action="store_true", help="Print release-ready quickstart commands")
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON")
    args = parser.parse_args()

    if args.quickstart:
        print_quickstart()
        return

    if args.verify:
        report = run_verification()
        if args.json:
            print(json.dumps(report, indent=2, sort_keys=True))
        else:
            print_verify_report(report)
        return

    if args.profiles:
        print_profiles()
        return

    if args.requests:
        print_requests()
        return

    if args.matrix:
        results = matrix_results()
        if args.json:
            print(json.dumps(results, indent=2, sort_keys=True))
        else:
            print_matrix(results)
        return

    if args.surface:
        results = surface_results()
        if args.json:
            print(json.dumps(results, indent=2, sort_keys=True))
        else:
            print_surface(results)
        return

    if args.invariants:
        rows = invariant_results()
        if args.json:
            print(json.dumps(rows, indent=2, sort_keys=True))
        else:
            print_invariants(rows)
        return

    if args.challenge:
        rows = challenge_results()
        if args.json:
            print(json.dumps(rows, indent=2, sort_keys=True))
        else:
            print_challenge(rows)
        return

    if args.manifest:
        manifest = release_manifest()
        if args.json:
            print(json.dumps(manifest, indent=2, sort_keys=True))
        else:
            print_manifest(manifest)
        return

    if args.request_compare:
        results = request_results(args.scenario, args.profile)
        if args.json:
            print(json.dumps(results, indent=2, sort_keys=True))
        else:
            print_request_compare(results, args.scenario, args.profile)
        return

    if args.compare:
        results = compare_results(args.profile, args.request)
        if args.json:
            print(json.dumps(results, indent=2, sort_keys=True))
        else:
            print_compare(results, args.profile, args.request)
        return

    result = resolve_caps(args.scenario, args.profile, args.request)
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print_report(result, explain=args.explain)


if __name__ == "__main__":
    main()
