#!/usr/bin/env python3
"""
CAPS-SmartBulb
Capability Admissibility Protection System

A structural demonstration showing that capability may exist
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

PROJECT_NAME = "CAPS-SmartBulb"

TELEMETRY_RESOLUTION_BASIS = "Telemetry is event-admitted by data export structure, not scenario required_for membership."


def command_name() -> str:
    return Path(sys.argv[0]).name


@dataclass(frozen=True)
class Capability:
    name: str
    purpose: str
    exposure: int
    required_for: Tuple[str, ...]


CAPABILITIES: Dict[str, Capability] = {
    "light_engine": Capability("Light Engine", "Physical light output", 1, ("local_on", "local_off", "dim", "timer", "remote_on")),
    "local_switch": Capability("Local Switch", "Physical local control", 1, ("local_on", "local_off", "dim")),
    "dimmer": Capability("Dimmer", "Brightness control", 2, ("dim",)),
    "timer": Capability("Timer", "Scheduled local activation", 2, ("timer",)),
    "wifi": Capability("WiFi", "Network participation", 6, ("remote_on", "ota_update")),
    "cloud_api": Capability("Cloud API", "External remote access", 9, ("remote_on",)),
    "voice_assistant": Capability("Voice Assistant", "Third-party voice integration", 8, ("voice_on",)),
    "telemetry": Capability("Telemetry", "Usage data export", 7, ()),
    "ota_update": Capability("OTA Update", "Firmware update channel", 8, ("ota_update",)),
    "bluetooth_pairing": Capability("Bluetooth Pairing", "Nearby pairing interface", 5, ("pair",)),
}


SCENARIOS = {
    "local_on": {"intent": "Turn light on using local switch", "allow_external": False, "allow_data_export": False, "maintenance_window": False, "authenticated_remote": False},
    "dim": {"intent": "Adjust brightness locally", "allow_external": False, "allow_data_export": False, "maintenance_window": False, "authenticated_remote": False},
    "timer": {"intent": "Use a local timer", "allow_external": False, "allow_data_export": False, "maintenance_window": False, "authenticated_remote": False},
    "remote_on": {"intent": "Turn light on remotely", "allow_external": True, "allow_data_export": False, "maintenance_window": False, "authenticated_remote": True},
    "ota_update": {"intent": "Perform firmware update", "allow_external": True, "allow_data_export": False, "maintenance_window": True, "authenticated_remote": True},
    "voice_on": {"intent": "Authenticated voice assistant requests light on", "allow_external": True, "allow_data_export": False, "maintenance_window": False, "authenticated_remote": True},
    "pair": {"intent": "Authenticated nearby pairing request", "allow_external": False, "allow_data_export": False, "maintenance_window": False, "authenticated_remote": True},
    "unsafe_cloud": {"intent": "Cloud requests full access without admissible structure", "allow_external": True, "allow_data_export": True, "maintenance_window": False, "authenticated_remote": False},
}


PROFILES = {
    "minimal": {
        "description": "Only the smallest necessary capability becomes visible.",
        "max_exposure_visible": 2,
        "allow_isolated_external": False,
        "allow_dormant_network": False,
        "allow_telemetry": False,
        "allow_voice": False,
        "allow_ota": False,
    },
    "balanced": {
        "description": "Local features remain available; external exposure requires isolation.",
        "max_exposure_visible": 2,
        "allow_isolated_external": True,
        "allow_dormant_network": True,
        "allow_telemetry": False,
        "allow_voice": False,
        "allow_ota": True,
    },
    "connected": {
        "description": "Remote access is allowed only through isolated capability visibility.",
        "max_exposure_visible": 2,
        "allow_isolated_external": True,
        "allow_dormant_network": True,
        "allow_telemetry": False,
        "allow_voice": True,
        "allow_ota": True,
    },
    "maintenance": {
        "description": "Firmware maintenance is allowed; normal user capabilities are minimized.",
        "max_exposure_visible": 1,
        "allow_isolated_external": True,
        "allow_dormant_network": True,
        "allow_telemetry": False,
        "allow_voice": False,
        "allow_ota": True,
    },
    "strict": {
        "description": "Maximum protection posture; external, voice, telemetry, and update surfaces are refused.",
        "max_exposure_visible": 1,
        "allow_isolated_external": False,
        "allow_dormant_network": False,
        "allow_telemetry": False,
        "allow_voice": False,
        "allow_ota": False,
    },
}


REQUESTS = {
    "normal": {
        "description": "Normal request aligned with the selected scenario.",
        "target": None,
        "forced_visibility": False,
        "external_request": False,
        "data_export_request": False,
        "update_request": False,
        "identity_valid": True,
        "context_valid": True,
        "scope_valid": True,
        "timing_valid": True,
    },
    "telemetry_leak": {
        "description": "Unauthorized request attempts to expose usage telemetry.",
        "target": "telemetry",
        "forced_visibility": True,
        "external_request": True,
        "data_export_request": True,
        "update_request": False,
        "identity_valid": True,
        "context_valid": False,
        "scope_valid": False,
        "timing_valid": True,
    },
    "cloud_takeover": {
        "description": "Cloud path attempts to expose remote access without admissible protection.",
        "target": "cloud_api",
        "forced_visibility": True,
        "external_request": True,
        "data_export_request": False,
        "update_request": False,
        "identity_valid": False,
        "context_valid": False,
        "scope_valid": False,
        "timing_valid": True,
    },
    "forced_update": {
        "description": "External request attempts firmware update without valid request provenance.",
        "target": "ota_update",
        "forced_visibility": True,
        "external_request": True,
        "data_export_request": False,
        "update_request": True,
        "identity_valid": False,
        "context_valid": False,
        "scope_valid": False,
        "timing_valid": False,
    },
    "voice_spoof": {
        "description": "Voice path attempts to activate control without authenticated structure.",
        "target": "voice_assistant",
        "forced_visibility": True,
        "external_request": True,
        "data_export_request": False,
        "update_request": False,
        "identity_valid": False,
        "context_valid": False,
        "scope_valid": False,
        "timing_valid": True,
    },
    "bluetooth_probe": {
        "description": "Nearby pairing interface is probed without pairing intent.",
        "target": "bluetooth_pairing",
        "forced_visibility": True,
        "external_request": False,
        "data_export_request": False,
        "update_request": False,
        "identity_valid": False,
        "context_valid": False,
        "scope_valid": False,
        "timing_valid": True,
    },
}


SCENARIO_ORDER = ("local_on", "dim", "timer", "remote_on", "ota_update", "voice_on", "pair", "unsafe_cloud")
PROFILE_ORDER = ("minimal", "balanced", "connected", "maintenance", "strict")
REQUEST_ORDER = ("telemetry_leak", "cloud_takeover", "forced_update", "voice_spoof", "bluetooth_probe")


def protection_certificate_full(payload: dict) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def protection_certificate(payload: dict) -> str:
    return protection_certificate_full(payload)[:16]


def request_structure_status(request: dict) -> Tuple[bool, bool, bool]:
    complete = request["identity_valid"] and request["context_valid"] and request["scope_valid"] and request["timing_valid"]
    consistency_checks = [
        not (request["data_export_request"] and not request["scope_valid"]),
        not (request["update_request"] and not request["timing_valid"]),
        not request["forced_visibility"],
    ]
    consistent = all(consistency_checks)

    return complete, consistent, complete and consistent


def scenario_profile_consistent(scenario: dict, profile: dict) -> bool:
    checks = [
        not (scenario["allow_data_export"] and not scenario["authenticated_remote"]),
        not (scenario["allow_data_export"] and not profile["allow_telemetry"]),
        not (scenario["maintenance_window"] and not profile["allow_ota"]),
    ]
    return all(checks)


def request_profile_consistent(request: dict, profile: dict) -> bool:
    checks = [
        not (request["data_export_request"] and not profile["allow_telemetry"]),
        not (request["update_request"] and not profile["allow_ota"]),
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

    if capability_key == "telemetry":
        if scenario["allow_data_export"] and profile["allow_telemetry"]:
            return VISIBLE, "Telemetry export is permitted by scenario and profile."
        return FORBIDDEN, "Telemetry is not required or not permitted by the selected profile."

    if capability_key == "voice_assistant":
        if required and profile["allow_voice"] and scenario["allow_external"] and scenario["authenticated_remote"]:
            return ISOLATED, "Voice path is required and allowed only through isolated visibility."
        if required:
            return BLOCKED, "Voice path was requested but lacks admissible authenticated structure."
        return FORBIDDEN, "Voice assistant is not required for this scenario."

    if capability_key == "cloud_api":
        if required and profile["allow_isolated_external"] and scenario["allow_external"] and scenario["authenticated_remote"]:
            return ISOLATED, "Remote cloud path is required and allowed only through isolated visibility."
        if required:
            return BLOCKED, "Remote cloud path is required but not admissible under this profile or authentication state."
        return FORBIDDEN, "Cloud API is not required for this scenario."

    if capability_key == "wifi":
        if required and scenario["allow_external"] and profile["allow_isolated_external"]:
            return ISOLATED, "Network participation is required and allowed only through isolated visibility."
        if profile["allow_dormant_network"]:
            return DORMANT, "Network capability exists but is not currently required."
        return FORBIDDEN, "Network capability is not allowed by the selected profile."

    if capability_key == "ota_update":
        if required and profile["allow_ota"] and scenario["allow_external"] and scenario["maintenance_window"] and scenario["authenticated_remote"]:
            return ISOLATED, "Firmware update is required and allowed inside authenticated maintenance posture."
        if required:
            return BLOCKED, "Firmware update was requested but maintenance or authentication structure is insufficient."
        return FORBIDDEN, "Firmware update is not required for this scenario."

    if capability_key == "bluetooth_pairing":
        if required and profile["allow_isolated_external"]:
            return ISOLATED, "Bluetooth pairing is required and isolated by profile."
        if profile["allow_dormant_network"]:
            return DORMANT, "Bluetooth pairing exists but is not currently required."
        return FORBIDDEN, "Bluetooth pairing is not allowed by the selected profile."

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

    result = {
        "project": "CAPS-SmartBulb",
        "definition": "Capability Admissibility Protection System",
        "scenario": scenario_key,
        "intent": scenario["intent"],
        "profile": profile_key,
        "profile_description": profile["description"],
        "request": request_key,
        "request_description": request["description"],
        "principle": "capability_visible iff protection_structure_complete AND protection_structure_consistent AND request_structure_complete AND request_structure_consistent",
        "formula": "capability_visible = resolve(capability, scenario, protection_profile, request_structure)",
        "capability": "infrastructure",
        "visibility": "admissibility",
        "protection": "structure",
        "request_structure": "provenance",
        "global_admissibility_gate": "if protection or request structure is incomplete or inconsistent, visible and isolated capabilities collapse to BLOCKED",
        "telemetry_resolution_basis": TELEMETRY_RESOLUTION_BASIS,
        "protection_structure_complete": protection_complete,
        "protection_structure_consistent": protection_consistent,
        "protection_admissible": protection_admissible,
        "request_structure_complete": request_complete,
        "request_structure_consistent": request_consistent,
        "caps_admissible": caps_admissible,
        "states": states,
        "summary": summary,
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
    print("capability = infrastructure")
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
        print(f"- {item['name']:<18} -> {transition:<27} exposure={item['exposure']}  {item['purpose']}")
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
        print(f"{key:<18} {REQUESTS[key]['description']}")


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


def print_compare(results: list, profile_key: str, request_key: str) -> None:
    print(PROJECT_NAME)
    print(f"Comparison Mode: profile={profile_key}, request={request_key}")
    print("-" * 112)
    print(f"{'scenario':<14} {'admissible':<10} {'visible':>7} {'isolated':>9} {'dormant':>8} {'forbidden':>10} {'blocked':>8} {'certificate':<16}")
    print("-" * 112)
    for result in results:
        s = result["summary"]
        print(f"{result['scenario']:<14} {str(result['caps_admissible']):<10} {s[VISIBLE]:>7} {s[ISOLATED]:>9} {s[DORMANT]:>8} {s[FORBIDDEN]:>10} {s[BLOCKED]:>8} {result['certificate']:<16}")
    print("-" * 112)
    print("Formula: capability_visible = resolve(capability, scenario, protection_profile, request_structure)")


def print_request_compare(results: list, scenario_key: str, profile_key: str) -> None:
    print(PROJECT_NAME)
    print(f"Request Comparison Mode: scenario={scenario_key}, profile={profile_key}")
    print("-" * 128)
    print(f"{'request':<18} {'prot_ok':<8} {'req_ok':<8} {'admissible':<10} {'visible':>7} {'isolated':>9} {'blocked':>8} {'target_result':<22} {'certificate':<16}")
    print("-" * 128)
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
        print(f"{result['request']:<18} {str(prot_ok):<8} {str(req_ok):<8} {str(result['caps_admissible']):<10} {s[VISIBLE]:>7} {s[ISOLATED]:>9} {s[BLOCKED]:>8} {target_result:<22} {result['certificate']:<16}")
    print("-" * 128)
    print("Principle: unsafe request provenance blocks visibility even when capability exists.")
    print("Formula: capability_visible = resolve(capability, scenario, protection_profile, request_structure)")


def print_matrix(results: list) -> None:
    print(PROJECT_NAME)
    print("Profile Matrix Mode")
    print("-" * 122)
    print(f"{'profile':<12} {'scenario':<14} {'admissible':<10} {'visible':>7} {'isolated':>9} {'dormant':>8} {'forbidden':>10} {'blocked':>8} {'certificate':<16}")
    print("-" * 122)
    for result in results:
        s = result["summary"]
        print(f"{result['profile']:<12} {result['scenario']:<14} {str(result['caps_admissible']):<10} {s[VISIBLE]:>7} {s[ISOLATED]:>9} {s[DORMANT]:>8} {s[FORBIDDEN]:>10} {s[BLOCKED]:>8} {result['certificate']:<16}")
    print("-" * 122)
    print("Principle: same capability surface, different profile, different admitted visibility.")



VERIFY_CASE_GROUPS = {
    "baseline_local": (("local_on", "balanced", "normal"),),
    "unsafe_request_refusal": (
        ("local_on", "balanced", "telemetry_leak"),
        ("remote_on", "connected", "cloud_takeover"),
        ("ota_update", "maintenance", "forced_update"),
    ),
    "isolated_admission": (
        ("remote_on", "connected", "normal"),
        ("ota_update", "maintenance", "normal"),
    ),
    "strict_profile_refusal": (("local_on", "strict", "normal"),),
    "inconsistent_scenario_refusal": (("unsafe_cloud", "balanced", "normal"),),
}

VERIFY_CASES = tuple(
    case
    for group in VERIFY_CASE_GROUPS.values()
    for case in group
)


def verification_signature(result: dict) -> dict:
    return {
        "scenario": result["scenario"],
        "profile": result["profile"],
        "request": result["request"],
        "caps_admissible": result["caps_admissible"],
        "summary": result["summary"],
        "final_visible_output": result["final_visible_output"],
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
            "certificate": first["certificate"],
        })

    verification_payload = {
        "project": "CAPS-SmartBulb",
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
    print("-" * 128)
    print("Principle: same structure -> same output -> same certificate")
    print("-" * 128)
    print(f"{'scenario':<14} {'profile':<12} {'request':<18} {'same':<6} {'admissible':<10} {'visible_output':<30} {'certificate':<16}")
    print("-" * 128)
    for case in report["cases"]:
        visible_output = ", ".join(case["final_visible_output"]) if case["final_visible_output"] else "none"
        if len(visible_output) > 29:
            visible_output = visible_output[:26] + "..."
        print(
            f"{case['scenario']:<14} "
            f"{case['profile']:<12} "
            f"{case['request']:<18} "
            f"{str(case['same_replay']):<6} "
            f"{str(case['caps_admissible']):<10} "
            f"{visible_output:<30} "
            f"{case['certificate']:<16}"
        )
    print("-" * 128)
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
        "--scenario local_on --profile balanced --request normal --explain",
        "--scenario local_on --profile balanced --request telemetry_leak --explain",
        "--scenario ota_update --profile maintenance --request normal --explain",
        "--scenario ota_update --profile maintenance --request forced_update --explain",
        "--request-compare --scenario local_on --profile balanced",
        "--matrix",
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
    print("Capability may exist, but visibility is admitted only by complete and consistent protection and request structure.")


def main() -> None:
    parser = argparse.ArgumentParser(description="CAPS-SmartBulb structural protection demo")
    parser.add_argument("--scenario", default="local_on", choices=sorted(SCENARIOS.keys()), help="Scenario to resolve")
    parser.add_argument("--profile", default="balanced", choices=sorted(PROFILES.keys()), help="Protection profile to apply")
    parser.add_argument("--request", default="normal", choices=sorted(REQUESTS.keys()), help="Request structure to test")
    parser.add_argument("--profiles", action="store_true", help="List available protection profiles")
    parser.add_argument("--requests", action="store_true", help="List available request structures")
    parser.add_argument("--compare", action="store_true", help="Print all scenarios under one profile and request structure")
    parser.add_argument("--request-compare", "--request_compare", dest="request_compare", action="store_true", help="Print all request structures under one scenario and profile")
    parser.add_argument("--matrix", action="store_true", help="Print all scenarios across all protection profiles with normal requests")
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
