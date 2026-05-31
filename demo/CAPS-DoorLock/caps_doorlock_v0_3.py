#!/usr/bin/env python3
"""
CAPS-DoorLock v0.3
Capability Admissibility Protection System

A structural demonstration showing that physical-access capability may exist
without becoming visible or exposed.

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

PROJECT_NAME = "CAPS-DoorLock"

ACCESS_LOG_RESOLUTION_BASIS = "Access logs are event-admitted by audit export structure, not automatic lock capability visibility."


def command_name() -> str:
    return Path(sys.argv[0]).name


@dataclass(frozen=True)
class Capability:
    name: str
    purpose: str
    exposure: int
    required_for: Tuple[str, ...]


CAPABILITIES: Dict[str, Capability] = {
    "deadbolt_mechanism": Capability("Deadbolt Mechanism", "Physical locking structure", 1, ("local_lock", "local_unlock", "remote_unlock", "guest_unlock", "emergency_override")),
    "lock_actuator": Capability("Lock Actuator", "Motorized lock and unlock movement", 2, ("local_lock", "local_unlock", "remote_unlock", "guest_unlock", "emergency_override")),
    "local_keypad": Capability("Local Keypad", "Local credential entry", 2, ("local_unlock", "guest_unlock")),
    "credential_store": Capability("Credential Store", "Stored codes, tokens, and authorized identities", 4, ("local_unlock", "remote_unlock", "guest_unlock", "maintenance", "emergency_override")),
    "tamper_sensor": Capability("Tamper Sensor", "Physical tamper observation", 3, ("local_lock", "local_unlock", "remote_unlock", "guest_unlock", "emergency_override")),
    "wifi": Capability("WiFi", "Network participation", 6, ("remote_unlock", "firmware_update", "maintenance")),
    "remote_unlock_api": Capability("Remote Unlock API", "External unlock command path", 9, ("remote_unlock",)),
    "guest_access_manager": Capability("Guest Access Manager", "Temporary guest credential control", 7, ("guest_unlock",)),
    "access_logs": Capability("Access Logs", "Access history and audit export", 7, ()),
    "firmware_update": Capability("Firmware Update", "Lock firmware update channel", 8, ("firmware_update",)),
    "bluetooth_pairing": Capability("Bluetooth Pairing", "Nearby pairing interface", 5, ("pair_device",)),
    "admin_console": Capability("Admin Console", "Maintenance and administrative control surface", 8, ("maintenance",)),
}


SCENARIOS = {
    "local_lock": {
        "intent": "Lock door using local physical action",
        "allow_external": False,
        "allow_audit_export": False,
        "maintenance_window": False,
        "authenticated_remote": False,
        "credential_required": False,
        "proximity_required": True,
        "time_window_required": False,
        "emergency_context": False,
    },
    "local_unlock": {
        "intent": "Unlock door using local admissible credential",
        "allow_external": False,
        "allow_audit_export": False,
        "maintenance_window": False,
        "authenticated_remote": False,
        "credential_required": True,
        "proximity_required": True,
        "time_window_required": False,
        "emergency_context": False,
    },
    "remote_unlock": {
        "intent": "Unlock door remotely using authenticated remote structure",
        "allow_external": True,
        "allow_audit_export": False,
        "maintenance_window": False,
        "authenticated_remote": True,
        "credential_required": True,
        "proximity_required": False,
        "time_window_required": True,
        "emergency_context": False,
    },
    "guest_unlock": {
        "intent": "Unlock door using temporary guest access structure",
        "allow_external": True,
        "allow_audit_export": False,
        "maintenance_window": False,
        "authenticated_remote": True,
        "credential_required": True,
        "proximity_required": True,
        "time_window_required": True,
        "emergency_context": False,
    },
    "pair_device": {
        "intent": "Pair nearby device using admissible proximity structure",
        "allow_external": False,
        "allow_audit_export": False,
        "maintenance_window": False,
        "authenticated_remote": False,
        "credential_required": True,
        "proximity_required": True,
        "time_window_required": True,
        "emergency_context": False,
    },
    "maintenance": {
        "intent": "Perform authenticated maintenance on the lock",
        "allow_external": True,
        "allow_audit_export": True,
        "maintenance_window": True,
        "authenticated_remote": True,
        "credential_required": True,
        "proximity_required": False,
        "time_window_required": True,
        "emergency_context": False,
    },
    "firmware_update": {
        "intent": "Perform authenticated firmware update",
        "allow_external": True,
        "allow_audit_export": False,
        "maintenance_window": True,
        "authenticated_remote": True,
        "credential_required": True,
        "proximity_required": False,
        "time_window_required": True,
        "emergency_context": False,
    },
    "emergency_override": {
        "intent": "Emergency override under bounded emergency structure",
        "allow_external": False,
        "allow_audit_export": True,
        "maintenance_window": False,
        "authenticated_remote": False,
        "credential_required": True,
        "proximity_required": True,
        "time_window_required": True,
        "emergency_context": True,
    },
    "unsafe_remote": {
        "intent": "Remote unlock request without admissible provenance",
        "allow_external": True,
        "allow_audit_export": True,
        "maintenance_window": False,
        "authenticated_remote": False,
        "credential_required": True,
        "proximity_required": False,
        "time_window_required": True,
        "emergency_context": False,
    },
}


PROFILES = {
    "minimal": {
        "description": "Only local lock structure is visible; external and audit surfaces are refused.",
        "max_exposure_visible": 2,
        "allow_isolated_external": False,
        "allow_dormant_network": False,
        "allow_audit_export": False,
        "allow_guest_access": False,
        "allow_ota": False,
        "allow_admin": False,
        "allow_emergency_override": False,
    },
    "balanced": {
        "description": "Local access remains available; higher exposure surfaces require isolation.",
        "max_exposure_visible": 3,
        "allow_isolated_external": True,
        "allow_dormant_network": True,
        "allow_audit_export": False,
        "allow_guest_access": True,
        "allow_ota": True,
        "allow_admin": False,
        "allow_emergency_override": True,
    },
    "connected": {
        "description": "Remote and guest access may be admitted only through isolated visibility. Currently shares the same visibility surface as Balanced and exists separately for future structural specialization.",
        "max_exposure_visible": 3,
        "allow_isolated_external": True,
        "allow_dormant_network": True,
        "allow_audit_export": False,
        "allow_guest_access": True,
        "allow_ota": True,
        "allow_admin": False,
        "allow_emergency_override": True,
    },
    "maintenance": {
        "description": "Maintenance and firmware visibility are admitted under authenticated maintenance posture.",
        "max_exposure_visible": 1,
        "allow_isolated_external": True,
        "allow_dormant_network": True,
        "allow_audit_export": True,
        "allow_guest_access": False,
        "allow_ota": True,
        "allow_admin": True,
        "allow_emergency_override": False,
    },
    "strict": {
        "description": "Maximum protection posture; remote, guest, audit, admin, update, and pairing surfaces are refused.",
        "max_exposure_visible": 1,
        "allow_isolated_external": False,
        "allow_dormant_network": False,
        "allow_audit_export": False,
        "allow_guest_access": False,
        "allow_ota": False,
        "allow_admin": False,
        "allow_emergency_override": False,
    },
}


REQUESTS = {
    "normal": {
        "description": "Normal request aligned with the selected scenario.",
        "target": None,
        "forced_visibility": False,
        "external_request": False,
        "audit_export_request": False,
        "update_request": False,
        "admin_request": False,
        "credential_valid": True,
        "identity_valid": True,
        "context_valid": True,
        "scope_valid": True,
        "timing_valid": True,
        "proximity_valid": True,
    },
    "forged_remote_unlock": {
        "description": "Remote unlock path attempts visibility without valid identity, scope, or timing.",
        "target": "remote_unlock_api",
        "forced_visibility": True,
        "external_request": True,
        "audit_export_request": False,
        "update_request": False,
        "admin_request": False,
        "credential_valid": False,
        "identity_valid": False,
        "context_valid": False,
        "scope_valid": False,
        "timing_valid": False,
        "proximity_valid": True,
    },
    "credential_replay": {
        "description": "Previously valid credential is replayed outside admissible context.",
        "target": "credential_store",
        "forced_visibility": True,
        "external_request": False,
        "audit_export_request": False,
        "update_request": False,
        "admin_request": False,
        "credential_valid": False,
        "identity_valid": True,
        "context_valid": False,
        "scope_valid": False,
        "timing_valid": False,
        "proximity_valid": True,
    },
    "guest_access_escalation": {
        "description": "Temporary guest access attempts to become broader unlock authority.",
        "target": "guest_access_manager",
        "forced_visibility": True,
        "external_request": True,
        "audit_export_request": False,
        "update_request": False,
        "admin_request": False,
        "credential_valid": True,
        "identity_valid": True,
        "context_valid": False,
        "scope_valid": False,
        "timing_valid": False,
        "proximity_valid": False,
    },
    "maintenance_bypass": {
        "description": "Admin surface is requested without admissible maintenance structure.",
        "target": "admin_console",
        "forced_visibility": True,
        "external_request": True,
        "audit_export_request": False,
        "update_request": False,
        "admin_request": True,
        "credential_valid": False,
        "identity_valid": False,
        "context_valid": False,
        "scope_valid": False,
        "timing_valid": False,
        "proximity_valid": True,
    },
    "forced_update": {
        "description": "Firmware update path is requested without valid timing and identity.",
        "target": "firmware_update",
        "forced_visibility": True,
        "external_request": True,
        "audit_export_request": False,
        "update_request": True,
        "admin_request": False,
        "credential_valid": False,
        "identity_valid": False,
        "context_valid": False,
        "scope_valid": False,
        "timing_valid": False,
        "proximity_valid": True,
    },
    "bluetooth_probe": {
        "description": "Nearby pairing interface is probed without valid pairing intent.",
        "target": "bluetooth_pairing",
        "forced_visibility": True,
        "external_request": False,
        "audit_export_request": False,
        "update_request": False,
        "admin_request": False,
        "credential_valid": False,
        "identity_valid": False,
        "context_valid": False,
        "scope_valid": False,
        "timing_valid": True,
        "proximity_valid": False,
    },
    "log_exfiltration": {
        "description": "Access logs are requested for export without admissible audit scope.",
        "target": "access_logs",
        "forced_visibility": True,
        "external_request": True,
        "audit_export_request": True,
        "update_request": False,
        "admin_request": False,
        "credential_valid": True,
        "identity_valid": True,
        "context_valid": False,
        "scope_valid": False,
        "timing_valid": True,
        "proximity_valid": True,
    },
}


SCENARIO_ORDER = ("local_lock", "local_unlock", "remote_unlock", "guest_unlock", "pair_device", "maintenance", "firmware_update", "emergency_override", "unsafe_remote")
PROFILE_ORDER = ("minimal", "balanced", "connected", "maintenance", "strict")
REQUEST_ORDER = ("forged_remote_unlock", "credential_replay", "guest_access_escalation", "maintenance_bypass", "forced_update", "bluetooth_probe", "log_exfiltration")


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
    )
    consistency_checks = [
        not (request["audit_export_request"] and not request["scope_valid"]),
        not (request["update_request"] and not request["timing_valid"]),
        not (request["admin_request"] and not request["identity_valid"]),
        not (request["external_request"] and not request["identity_valid"]),
        not request["forced_visibility"],
    ]
    consistent = all(consistency_checks)
    return complete, consistent, complete and consistent


def scenario_profile_consistent(scenario: dict, profile: dict) -> bool:
    checks = [
        not (scenario["allow_external"] and not scenario["authenticated_remote"]),
        not (scenario["allow_external"] and not profile["allow_isolated_external"]),
        not (scenario["allow_audit_export"] and not profile["allow_audit_export"] and scenario["maintenance_window"]),
        not (scenario["maintenance_window"] and not profile["allow_ota"] and not profile["allow_admin"]),
        not (scenario["emergency_context"] and not profile["allow_emergency_override"]),
    ]
    return all(checks)


def request_profile_consistent(request: dict, profile: dict) -> bool:
    checks = [
        not (request["audit_export_request"] and not profile["allow_audit_export"]),
        not (request["update_request"] and not profile["allow_ota"]),
        not (request["admin_request"] and not profile["allow_admin"]),
        not (request["external_request"] and not profile["allow_isolated_external"]),
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

    if capability_key == "access_logs":
        if scenario["allow_audit_export"] and profile["allow_audit_export"]:
            return ISOLATED, "Access log visibility is permitted only inside audit-admissible structure."
        return FORBIDDEN, "Access logs exist, but audit export is not admitted by the selected structure."

    if capability_key == "remote_unlock_api":
        if required and profile["allow_isolated_external"] and scenario["allow_external"] and scenario["authenticated_remote"]:
            return ISOLATED, "Remote unlock is required and admitted only through isolated visibility."
        if required:
            return BLOCKED, "Remote unlock was requested but remote authentication or profile isolation is insufficient."
        return FORBIDDEN, "Remote unlock API is not required for this scenario."

    if capability_key == "guest_access_manager":
        if required and profile["allow_guest_access"] and scenario["authenticated_remote"] and scenario["time_window_required"]:
            return ISOLATED, "Guest access is required and admitted only inside bounded guest structure."
        if required:
            return BLOCKED, "Guest access was requested but guest, timing, or authentication structure is insufficient."
        return FORBIDDEN, "Guest access manager is not required for this scenario."

    if capability_key == "admin_console":
        if required and profile["allow_admin"] and scenario["maintenance_window"] and scenario["authenticated_remote"]:
            return ISOLATED, "Admin console is required and admitted only inside authenticated maintenance posture."
        if required:
            return BLOCKED, "Admin console was requested but maintenance or authentication structure is insufficient."
        return FORBIDDEN, "Admin console is not required for this scenario."

    if capability_key == "firmware_update":
        if required and profile["allow_ota"] and scenario["maintenance_window"] and scenario["authenticated_remote"]:
            return ISOLATED, "Firmware update is required and admitted inside authenticated update posture."
        if required:
            return BLOCKED, "Firmware update was requested but maintenance or authentication structure is insufficient."
        return FORBIDDEN, "Firmware update is not required for this scenario."

    if capability_key == "wifi":
        if required and scenario["allow_external"] and profile["allow_isolated_external"]:
            return ISOLATED, "Network participation is required and admitted only through isolated visibility."
        if profile["allow_dormant_network"]:
            return DORMANT, "Network capability exists but is not currently required."
        return FORBIDDEN, "Network capability is not allowed by the selected profile."

    if capability_key == "bluetooth_pairing":
        if required and profile["allow_isolated_external"] and scenario["proximity_required"]:
            return ISOLATED, "Bluetooth pairing is required and isolated by proximity structure."
        if profile["allow_dormant_network"]:
            return DORMANT, "Bluetooth pairing exists but is not currently required."
        return FORBIDDEN, "Bluetooth pairing is not admitted by the selected profile."

    if capability_key == "credential_store":
        if required and scenario["credential_required"]:
            if capability.exposure <= profile["max_exposure_visible"]:
                return VISIBLE, "Credential structure is required and exposure is within visible limit."
            return ISOLATED, "Credential structure is required but constrained into isolated visibility."
        return FORBIDDEN, "Credential store is not required for this scenario."

    if capability_key == "tamper_sensor":
        if required:
            if capability.exposure <= profile["max_exposure_visible"]:
                return VISIBLE, "Tamper sensor supports the scenario and exposure is within visible limit."
            return ISOLATED, "Tamper sensor supports the scenario but is constrained into isolated visibility."
        if capability.exposure <= profile["max_exposure_visible"]:
            return DORMANT, "Tamper sensor exists but is not required for this scenario."
        return FORBIDDEN, "Tamper sensor is not admitted by the selected profile."

    if required:
        if capability.exposure <= profile["max_exposure_visible"]:
            return VISIBLE, "Capability is required and exposure is within the visible limit of the selected profile."
        return BLOCKED, "Capability is required but exposure exceeds the visible limit of the selected profile."

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
        "version": "v0.3",
        "definition": "Capability Admissibility Protection System",
        "scenario": scenario_key,
        "intent": scenario["intent"],
        "profile": profile_key,
        "profile_description": profile["description"],
        "request": request_key,
        "request_description": request["description"],
        "principle": "capability_visible iff protection_structure_complete AND protection_structure_consistent AND request_structure_complete AND request_structure_consistent",
        "formula": "capability_visible = resolve(capability, scenario, protection_profile, request_structure)",
        "capability": "physical_access_infrastructure",
        "visibility": "admissibility",
        "protection": "structure",
        "request_structure": "provenance",
        "global_admissibility_gate": "if protection or request structure is incomplete or inconsistent, visible and isolated capabilities collapse to BLOCKED",
        "access_log_resolution_basis": ACCESS_LOG_RESOLUTION_BASIS,
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
    print("capability = physical_access_infrastructure")
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
        if item["raw_state"] != item["state"] and item["state"] != BLOCKED:
            transition = f"candidate={item['raw_state']} -> final={item['state']}"
        else:
            transition = item["state"]
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
        print(f"{key:<12} {PROFILES[key]['description']}")


def print_requests() -> None:
    print(PROJECT_NAME)
    print("Available Request Structures")
    print("-" * 72)
    for key in ("normal",) + REQUEST_ORDER:
        print(f"{key:<24} {REQUESTS[key]['description']}")


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
        resolve_caps("local_lock", "balanced", "normal"),
        resolve_caps("local_unlock", "balanced", "normal"),
        resolve_caps("remote_unlock", "connected", "normal"),
        resolve_caps("guest_unlock", "connected", "normal"),
        resolve_caps("firmware_update", "maintenance", "normal"),
        resolve_caps("remote_unlock", "connected", "forged_remote_unlock"),
        resolve_caps("guest_unlock", "connected", "guest_access_escalation"),
        resolve_caps("maintenance", "maintenance", "maintenance_bypass"),
    ]


def print_compare(results: list, profile_key: str, request_key: str) -> None:
    print(PROJECT_NAME)
    print(f"Comparison Mode: profile={profile_key}, request={request_key}")
    print("-" * 124)
    print(f"{'scenario':<18} {'admissible':<10} {'visible':>7} {'isolated':>9} {'dormant':>8} {'forbidden':>10} {'blocked':>8} {'ratio':>8} {'certificate':<16}")
    print("-" * 124)
    for result in results:
        s = result["summary"]
        print(f"{result['scenario']:<18} {str(result['caps_admissible']):<10} {s[VISIBLE]:>7} {s[ISOLATED]:>9} {s[DORMANT]:>8} {s[FORBIDDEN]:>10} {s[BLOCKED]:>8} {str(result['visibility_ratio_percent']) + '%':>8} {result['certificate']:<16}")
    print("-" * 124)
    print("Formula: capability_visible = resolve(capability, scenario, protection_profile, request_structure)")


def print_request_compare(results: list, scenario_key: str, profile_key: str) -> None:
    print(PROJECT_NAME)
    print(f"Request Comparison Mode: scenario={scenario_key}, profile={profile_key}")
    print("-" * 138)
    print(f"{'request':<24} {'prot_ok':<8} {'req_ok':<8} {'admissible':<10} {'visible':>7} {'isolated':>9} {'blocked':>8} {'target_result':<22} {'certificate':<16}")
    print("-" * 138)
    for result in results:
        s = result["summary"]
        request = REQUESTS[result["request"]]
        target = request["target"]
        if target is None:
            target_result = "none"
        else:
            raw_state = result["states"][target]["raw_state"]
            final_state = result["states"][target]["state"]
            if raw_state != final_state and final_state != BLOCKED:
                target_result = f"{raw_state}->{final_state}"
            else:
                target_result = final_state
        prot_ok = result["protection_admissible"]
        req_ok = result["request_structure_complete"] and result["request_structure_consistent"]
        print(f"{result['request']:<24} {str(prot_ok):<8} {str(req_ok):<8} {str(result['caps_admissible']):<10} {s[VISIBLE]:>7} {s[ISOLATED]:>9} {s[BLOCKED]:>8} {target_result:<22} {result['certificate']:<16}")
    print("-" * 138)
    print("Principle: unsafe request provenance blocks visibility even when door access capability exists.")
    print("Formula: capability_visible = resolve(capability, scenario, protection_profile, request_structure)")


def print_matrix(results: list) -> None:
    print(PROJECT_NAME)
    print("Profile Matrix Mode")
    print("-" * 132)
    print(f"{'profile':<12} {'scenario':<18} {'admissible':<10} {'visible':>7} {'isolated':>9} {'dormant':>8} {'forbidden':>10} {'blocked':>8} {'ratio':>8} {'certificate':<16}")
    print("-" * 132)
    for result in results:
        s = result["summary"]
        print(f"{result['profile']:<12} {result['scenario']:<18} {str(result['caps_admissible']):<10} {s[VISIBLE]:>7} {s[ISOLATED]:>9} {s[DORMANT]:>8} {s[FORBIDDEN]:>10} {s[BLOCKED]:>8} {str(result['visibility_ratio_percent']) + '%':>8} {result['certificate']:<16}")
    print("-" * 132)
    print("Principle: same door-lock capability surface, different profile, different admitted visibility.")


def print_surface(results: list) -> None:
    print(PROJECT_NAME)
    print("Capability Surface Mode")
    print("-" * 126)
    print("Principle: capabilities may grow, but admitted visibility can remain bounded by structure.")
    print("-" * 126)
    print(f"{'scenario':<18} {'profile':<12} {'request':<24} {'admissible':<10} {'admitted':>8} {'total':>6} {'ratio':>8} {'certificate':<16}")
    print("-" * 126)
    for result in results:
        print(f"{result['scenario']:<18} {result['profile']:<12} {result['request']:<24} {str(result['caps_admissible']):<10} {result['admitted_visibility_count']:>8} {result['total_capabilities']:>6} {str(result['visibility_ratio_percent']) + '%':>8} {result['certificate']:<16}")
    print("-" * 126)
    print("Formula: capability_visible = resolve(capability, scenario, protection_profile, request_structure)")


def invariant_results() -> list:
    cases = [
        ("strict_remote_refusal", "remote_unlock", "strict", "normal", False, 0),
        ("forged_remote_refusal", "remote_unlock", "connected", "forged_remote_unlock", False, 0),
        ("credential_replay_refusal", "local_unlock", "balanced", "credential_replay", False, 0),
        ("log_exfiltration_refusal", "local_unlock", "balanced", "log_exfiltration", False, 0),
        ("remote_normal_admission", "remote_unlock", "connected", "normal", True, None),
        ("firmware_maintenance_admission", "firmware_update", "maintenance", "normal", True, None),
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
    print("-" * 132)
    print("Principle: unsafe or disallowed visibility must collapse while admissible structure remains reproducible.")
    print("-" * 132)
    print(f"{'invariant':<32} {'scenario':<18} {'profile':<12} {'request':<24} {'pass':<6} {'admitted':>8} {'ratio':>8} {'certificate':<16}")
    print("-" * 132)
    for row in rows:
        print(f"{row['invariant']:<32} {row['scenario']:<18} {row['profile']:<12} {row['request']:<24} {str(row['pass']):<6} {row['admitted_visibility_count']:>8} {str(row['visibility_ratio_percent']) + '%':>8} {row['certificate']:<16}")
    print("-" * 132)
    final = "PASS" if all(row["pass"] for row in rows) else "FAIL"
    print(f"Invariant Result: {final}")


VERIFY_CASE_GROUPS = {
    "baseline_local": (("local_unlock", "balanced", "normal"),),
    "unsafe_request_refusal": (
        ("remote_unlock", "connected", "forged_remote_unlock"),
        ("local_unlock", "balanced", "credential_replay"),
        ("guest_unlock", "connected", "guest_access_escalation"),
        ("maintenance", "maintenance", "maintenance_bypass"),
        ("firmware_update", "maintenance", "forced_update"),
        ("local_unlock", "balanced", "log_exfiltration"),
    ),
    "isolated_admission": (
        ("remote_unlock", "connected", "normal"),
        ("guest_unlock", "connected", "normal"),
        ("firmware_update", "maintenance", "normal"),
    ),
    "strict_profile_refusal": (("remote_unlock", "strict", "normal"),),
    "inconsistent_scenario_refusal": (("unsafe_remote", "balanced", "normal"),),
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
    print("-" * 138)
    print("Principle: same structure -> same output -> same certificate")
    print("-" * 138)
    print(f"{'scenario':<18} {'profile':<12} {'request':<24} {'same':<6} {'admissible':<10} {'visible_output':<32} {'ratio':>8} {'certificate':<16}")
    print("-" * 138)
    for case in report["cases"]:
        visible_output = ", ".join(case["final_visible_output"]) if case["final_visible_output"] else "none"
        if len(visible_output) > 31:
            visible_output = visible_output[:28] + "..."
        print(
            f"{case['scenario']:<18} "
            f"{case['profile']:<12} "
            f"{case['request']:<24} "
            f"{str(case['same_replay']):<6} "
            f"{str(case['caps_admissible']):<10} "
            f"{visible_output:<32} "
            f"{str(case['visibility_ratio_percent']) + '%':>8} "
            f"{case['certificate']:<16}"
        )
    print("-" * 138)
    print(f"Verification Result: {report['result']}")
    print(f"Verification Certificate: {report['verification_certificate']}")
    print("Verification Certificate Meaning: deterministic fingerprint of all verification case results")
    print()
    if report["result"] == "PASS":
        print("Deterministic replay confirmed.")
    else:
        print("Deterministic replay failed.")


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
        "--scenario local_unlock --profile balanced --request normal --explain",
        "--scenario remote_unlock --profile connected --request normal --explain",
        "--scenario remote_unlock --profile connected --request forged_remote_unlock --explain",
        "--scenario guest_unlock --profile connected --request guest_access_escalation --explain",
        "--scenario firmware_update --profile maintenance --request normal --explain",
        "--scenario firmware_update --profile maintenance --request forced_update --explain",
        "--request-compare --scenario remote_unlock --profile connected",
        "--surface",
        "--matrix",
        "--invariants",
        "--verify",
        "--verify --json",
    ]
    print("Recommended Commands:")
    for command in commands:
        print(f"python {script} {command}")
    print()
    print("Expected Verification Result:")
    print("Verification Result: PASS")
    print()
    print("Release Meaning:")
    print("Door access capability may exist, but unlock visibility is admitted only by complete and consistent protection and request structure.")


def main() -> None:
    parser = argparse.ArgumentParser(description="CAPS-DoorLock v0.3 structural protection demo")
    parser.add_argument("--scenario", default="local_unlock", choices=sorted(SCENARIOS.keys()), help="Scenario to resolve")
    parser.add_argument("--profile", default="balanced", choices=sorted(PROFILES.keys()), help="Protection profile to apply")
    parser.add_argument("--request", default="normal", choices=sorted(REQUESTS.keys()), help="Request structure to test")
    parser.add_argument("--profiles", action="store_true", help="List available protection profiles")
    parser.add_argument("--requests", action="store_true", help="List available request structures")
    parser.add_argument("--compare", action="store_true", help="Print all scenarios under one profile and request structure")
    parser.add_argument("--request-compare", "--request_compare", dest="request_compare", action="store_true", help="Print all request structures under one scenario and profile")
    parser.add_argument("--matrix", action="store_true", help="Print all scenarios across all protection profiles with normal requests")
    parser.add_argument("--surface", action="store_true", help="Print capability surface admission comparison")
    parser.add_argument("--invariants", action="store_true", help="Run focused structural invariant checks")
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
