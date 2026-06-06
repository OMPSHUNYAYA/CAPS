#!/usr/bin/env python3
"""
CAPS-Printer v1.8
Capability Admissibility Protection System

Structural visibility demonstration for the printer and document-output domain.

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
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Tuple, List, Any

VISIBLE = "VISIBLE"
ISOLATED = "ISOLATED"
DORMANT = "DORMANT"
FORBIDDEN = "FORBIDDEN"
BLOCKED = "BLOCKED"
DEFERRED = "DEFERRED"

PROJECT_NAME = "CAPS-Printer"
VERSION = "1.8"

DOCUMENT_CACHE_RESOLUTION_BASIS = "Document cache is event-admitted by job and audit structure, not automatic printer capability visibility."
SCAN_EXPORT_RESOLUTION_BASIS = "Scan export is admitted only by bounded destination, identity, and scope structure."
REMOTE_PRINT_RESOLUTION_BASIS = "Remote print capability may exist while remote visibility remains structurally refused."


def command_name() -> str:
    return Path(sys.argv[0]).name


@dataclass(frozen=True)
class Capability:
    name: str
    purpose: str
    exposure: int
    required_for: Tuple[str, ...]


CAPABILITIES: Dict[str, Capability] = {
    "print_engine": Capability("Print Engine", "Physical page marking structure", 1, ("local_print", "secure_print", "remote_print", "guest_print", "copy_document")),
    "paper_feed": Capability("Paper Feed", "Paper movement and tray handling", 1, ("local_print", "secure_print", "remote_print", "guest_print", "copy_document")),
    "ink_toner_system": Capability("Ink Toner System", "Consumable marking material system", 2, ("local_print", "secure_print", "remote_print", "guest_print", "copy_document")),
    "local_panel": Capability("Local Panel", "Local user interaction surface", 2, ("local_print", "secure_print", "copy_document", "scan_to_local")),
    "usb_print": Capability("USB Print", "Local wired print input", 3, ("local_print", "secure_print")),
    "lan_print": Capability("LAN Print", "Local network print input", 4, ("local_print", "secure_print", "guest_print")),
    "wifi_print": Capability("WiFi Print", "Wireless local print input", 5, ("local_print", "secure_print", "guest_print", "mobile_pair")),
    "mobile_pairing": Capability("Mobile Pairing", "Nearby mobile print pairing surface", 6, ("mobile_pair", "guest_print")),
    "cloud_print": Capability("Cloud Print", "Vendor or cloud-mediated print path", 8, ("remote_print", "managed_service")),
    "remote_print_api": Capability("Remote Print API", "External print command surface", 9, ("remote_print", "managed_service")),
    "scan_engine": Capability("Scan Engine", "Document capture structure", 5, ("scan_to_local", "scan_to_email", "copy_document")),
    "scan_to_email": Capability("Scan To Email", "Outbound scanned document export", 8, ("scan_to_email", "managed_service")),
    "fax_module": Capability("Fax Module", "Legacy external document transmission", 8, ("fax_send",)),
    "job_queue": Capability("Job Queue", "Pending document job management", 6, ("local_print", "secure_print", "remote_print", "guest_print")),
    "document_cache": Capability("Document Cache", "Temporary document storage and spool residue", 9, ()),
    "credential_store": Capability("Credential Store", "Stored identities, PINs, and release tokens", 7, ("secure_print", "remote_print", "maintenance", "managed_service")),
    "secure_release": Capability("Secure Release", "PIN or identity-gated print release", 7, ("secure_print",)),
    "admin_console": Capability("Admin Console", "Administrative configuration surface", 8, ("maintenance", "managed_service", "firmware_update", "maintenance_with_jobs", "maintenance_after_jobs_clear")),
    "firmware_update": Capability("Firmware Update", "Printer firmware update channel", 8, ("firmware_update", "managed_service", "maintenance_with_jobs", "maintenance_after_jobs_clear")),
    "telemetry_export": Capability("Telemetry Export", "Diagnostic and usage statistics export", 8, ("managed_service",)),
    "audit_logs": Capability("Audit Logs", "Job and access audit visibility", 7, ("maintenance", "managed_service")),
    "supply_monitor": Capability("Supply Monitor", "Consumable and device-health observation", 4, ("local_print", "secure_print", "remote_print", "guest_print", "maintenance", "managed_service")),
}


SCENARIOS = {
    "local_print": {
        "intent": "Local trusted user prints through local printer structure",
        "allow_external": False,
        "allow_document_export": False,
        "allow_audit_export": False,
        "maintenance_window": False,
        "authenticated_remote": False,
        "credential_required": False,
        "secure_release_required": False,
        "segmentation_required": False,
        "admin_required": False,
        "scan_required": False,
        "fax_required": False,
        "cloud_required": False,
        "timing_window_required": False,
        "proximity_required": True,
    },
    "secure_print": {
        "intent": "Sensitive job prints only after local secure release",
        "allow_external": False,
        "allow_document_export": False,
        "allow_audit_export": True,
        "maintenance_window": False,
        "authenticated_remote": False,
        "credential_required": True,
        "secure_release_required": True,
        "segmentation_required": False,
        "admin_required": False,
        "scan_required": False,
        "fax_required": False,
        "cloud_required": False,
        "timing_window_required": True,
        "proximity_required": True,
    },
    "guest_print": {
        "intent": "Guest prints through segmented temporary print structure",
        "allow_external": False,
        "allow_document_export": False,
        "allow_audit_export": False,
        "maintenance_window": False,
        "authenticated_remote": False,
        "credential_required": True,
        "secure_release_required": False,
        "segmentation_required": True,
        "admin_required": False,
        "scan_required": False,
        "fax_required": False,
        "cloud_required": False,
        "timing_window_required": True,
        "proximity_required": True,
    },
    "remote_print": {
        "intent": "Authenticated remote user submits bounded print job",
        "allow_external": True,
        "allow_document_export": False,
        "allow_audit_export": True,
        "maintenance_window": False,
        "authenticated_remote": True,
        "credential_required": True,
        "secure_release_required": True,
        "segmentation_required": True,
        "admin_required": False,
        "scan_required": False,
        "fax_required": False,
        "cloud_required": True,
        "timing_window_required": True,
        "proximity_required": False,
    },
    "scan_to_local": {
        "intent": "Local user scans document to local destination",
        "allow_external": False,
        "allow_document_export": False,
        "allow_audit_export": True,
        "maintenance_window": False,
        "authenticated_remote": False,
        "credential_required": True,
        "secure_release_required": False,
        "segmentation_required": False,
        "admin_required": False,
        "scan_required": True,
        "fax_required": False,
        "cloud_required": False,
        "timing_window_required": True,
        "proximity_required": True,
    },
    "scan_to_email": {
        "intent": "Authenticated user exports scan to bounded email destination",
        "allow_external": True,
        "allow_document_export": True,
        "allow_audit_export": True,
        "maintenance_window": False,
        "authenticated_remote": True,
        "credential_required": True,
        "secure_release_required": False,
        "segmentation_required": True,
        "admin_required": False,
        "scan_required": True,
        "fax_required": False,
        "cloud_required": False,
        "timing_window_required": True,
        "proximity_required": True,
    },
    "copy_document": {
        "intent": "Local copy operation without document export",
        "allow_external": False,
        "allow_document_export": False,
        "allow_audit_export": False,
        "maintenance_window": False,
        "authenticated_remote": False,
        "credential_required": False,
        "secure_release_required": False,
        "segmentation_required": False,
        "admin_required": False,
        "scan_required": True,
        "fax_required": False,
        "cloud_required": False,
        "timing_window_required": False,
        "proximity_required": True,
    },
    "fax_send": {
        "intent": "Bounded fax transmission using explicit destination structure",
        "allow_external": True,
        "allow_document_export": True,
        "allow_audit_export": True,
        "maintenance_window": False,
        "authenticated_remote": False,
        "credential_required": True,
        "secure_release_required": False,
        "segmentation_required": True,
        "admin_required": False,
        "scan_required": True,
        "fax_required": True,
        "cloud_required": False,
        "timing_window_required": True,
        "proximity_required": True,
    },
    "mobile_pair": {
        "intent": "Nearby mobile device pairs through bounded proximity structure",
        "allow_external": False,
        "allow_document_export": False,
        "allow_audit_export": False,
        "maintenance_window": False,
        "authenticated_remote": False,
        "credential_required": True,
        "secure_release_required": False,
        "segmentation_required": True,
        "admin_required": False,
        "scan_required": False,
        "fax_required": False,
        "cloud_required": False,
        "timing_window_required": True,
        "proximity_required": True,
    },
    "maintenance": {
        "intent": "Authenticated maintenance with bounded administrative visibility",
        "allow_external": True,
        "allow_document_export": False,
        "allow_audit_export": True,
        "maintenance_window": True,
        "authenticated_remote": True,
        "credential_required": True,
        "secure_release_required": False,
        "segmentation_required": True,
        "admin_required": True,
        "scan_required": False,
        "fax_required": False,
        "cloud_required": True,
        "timing_window_required": True,
        "proximity_required": False,
    },
    "firmware_update": {
        "intent": "Authenticated firmware update during maintenance posture",
        "allow_external": True,
        "allow_document_export": False,
        "allow_audit_export": True,
        "maintenance_window": True,
        "authenticated_remote": True,
        "credential_required": True,
        "secure_release_required": False,
        "segmentation_required": True,
        "admin_required": True,
        "scan_required": False,
        "fax_required": False,
        "cloud_required": True,
        "timing_window_required": True,
        "proximity_required": False,
    },

    "maintenance_with_jobs": {
        "intent": "Firmware maintenance requested while document jobs are still active",
        "allow_external": True,
        "allow_document_export": False,
        "allow_audit_export": True,
        "maintenance_window": True,
        "authenticated_remote": True,
        "credential_required": True,
        "secure_release_required": False,
        "segmentation_required": True,
        "admin_required": True,
        "scan_required": False,
        "fax_required": False,
        "cloud_required": True,
        "timing_window_required": True,
        "proximity_required": False,
    },
    "maintenance_after_jobs_clear": {
        "intent": "Firmware maintenance resumes after active document jobs are structurally cleared",
        "allow_external": True,
        "allow_document_export": False,
        "allow_audit_export": True,
        "maintenance_window": True,
        "authenticated_remote": True,
        "credential_required": True,
        "secure_release_required": False,
        "segmentation_required": True,
        "admin_required": True,
        "scan_required": False,
        "fax_required": False,
        "cloud_required": True,
        "timing_window_required": True,
        "proximity_required": False,
    },
    "managed_service": {
        "intent": "Managed service performs bounded diagnostics without document exposure",
        "allow_external": True,
        "allow_document_export": False,
        "allow_audit_export": True,
        "maintenance_window": True,
        "authenticated_remote": True,
        "credential_required": True,
        "secure_release_required": False,
        "segmentation_required": True,
        "admin_required": True,
        "scan_required": False,
        "fax_required": False,
        "cloud_required": True,
        "timing_window_required": True,
        "proximity_required": False,
    },
    "unsafe_remote_print": {
        "intent": "Remote print requested without admissible provenance",
        "allow_external": True,
        "allow_document_export": True,
        "allow_audit_export": True,
        "maintenance_window": False,
        "authenticated_remote": False,
        "credential_required": True,
        "secure_release_required": False,
        "segmentation_required": False,
        "admin_required": False,
        "scan_required": False,
        "fax_required": False,
        "cloud_required": True,
        "timing_window_required": True,
        "proximity_required": False,
    },
}


PROFILES = {
    "minimal": {
        "description": "Only local printing and local physical output are admitted; network, cloud, scan export, fax, telemetry, admin, and cache visibility are refused.",
        "max_exposure_visible": 3,
        "allow_isolated_external": False,
        "allow_dormant_network": False,
        "allow_guest_print": False,
        "allow_secure_release": True,
        "allow_scan": False,
        "allow_document_export": False,
        "allow_fax": False,
        "allow_cloud": False,
        "allow_admin": False,
        "allow_ota": False,
        "allow_telemetry": False,
        "allow_audit_export": False,
        "allow_mobile_pairing": False,
        "allow_cache_visibility": False,
    },
    "balanced": {
        "description": "Local and secure print are admitted; network print, guest print, local scan, and mobile pairing are bounded; cloud and telemetry remain refused.",
        "max_exposure_visible": 4,
        "allow_isolated_external": False,
        "allow_dormant_network": True,
        "allow_guest_print": True,
        "allow_secure_release": True,
        "allow_scan": True,
        "allow_document_export": False,
        "allow_fax": False,
        "allow_cloud": False,
        "allow_admin": False,
        "allow_ota": False,
        "allow_telemetry": False,
        "allow_audit_export": True,
        "allow_mobile_pairing": True,
        "allow_cache_visibility": False,
    },
    "connected": {
        "description": "Remote print and scan export may be admitted only through isolated visibility; document cache remains refused.",
        "max_exposure_visible": 4,
        "allow_isolated_external": True,
        "allow_dormant_network": True,
        "allow_guest_print": True,
        "allow_secure_release": True,
        "allow_scan": True,
        "allow_document_export": True,
        "allow_fax": False,
        "allow_cloud": True,
        "allow_admin": False,
        "allow_ota": False,
        "allow_telemetry": False,
        "allow_audit_export": True,
        "allow_mobile_pairing": True,
        "allow_cache_visibility": False,
    },
    "maintenance": {
        "description": "Firmware, admin, audit, and diagnostics may be admitted only under authenticated maintenance posture; document export remains refused.",
        "max_exposure_visible": 2,
        "allow_isolated_external": True,
        "allow_dormant_network": True,
        "allow_guest_print": False,
        "allow_secure_release": False,
        "allow_scan": False,
        "allow_document_export": False,
        "allow_fax": False,
        "allow_cloud": True,
        "allow_admin": True,
        "allow_ota": True,
        "allow_telemetry": True,
        "allow_audit_export": True,
        "allow_mobile_pairing": False,
        "allow_cache_visibility": True,
    },
    "records": {
        "description": "Audit-oriented posture admits logs and bounded cache inspection during authenticated review; print and export surfaces remain narrow.",
        "max_exposure_visible": 2,
        "allow_isolated_external": False,
        "allow_dormant_network": False,
        "allow_guest_print": False,
        "allow_secure_release": True,
        "allow_scan": False,
        "allow_document_export": False,
        "allow_fax": False,
        "allow_cloud": False,
        "allow_admin": True,
        "allow_ota": False,
        "allow_telemetry": False,
        "allow_audit_export": True,
        "allow_mobile_pairing": False,
        "allow_cache_visibility": True,
    },
    "strict": {
        "description": "Maximum protection posture; only essential physical output structure is visible.",
        "max_exposure_visible": 2,
        "allow_isolated_external": False,
        "allow_dormant_network": False,
        "allow_guest_print": False,
        "allow_secure_release": False,
        "allow_scan": False,
        "allow_document_export": False,
        "allow_fax": False,
        "allow_cloud": False,
        "allow_admin": False,
        "allow_ota": False,
        "allow_telemetry": False,
        "allow_audit_export": False,
        "allow_mobile_pairing": False,
        "allow_cache_visibility": False,
    },
}


REQUESTS = {
    "normal": {
        "description": "Normal request aligned with the selected scenario.",
        "target": None,
        "forced_visibility": False,
        "external_request": False,
        "document_export_request": False,
        "audit_export_request": False,
        "update_request": False,
        "admin_request": False,
        "print_request": True,
        "scan_request": False,
        "fax_request": False,
        "cloud_request": False,
        "cache_request": False,
        "credential_valid": True,
        "identity_valid": True,
        "context_valid": True,
        "scope_valid": True,
        "timing_valid": True,
        "proximity_valid": True,
        "segmentation_valid": True,
        "destination_valid": True,
        "release_valid": True,
    },
    "remote_job_spoof": {
        "description": "Remote print path attempts visibility without valid identity, scope, destination, or release.",
        "target": "remote_print_api",
        "forced_visibility": True,
        "external_request": True,
        "document_export_request": False,
        "audit_export_request": False,
        "update_request": False,
        "admin_request": False,
        "print_request": True,
        "scan_request": False,
        "fax_request": False,
        "cloud_request": True,
        "cache_request": False,
        "credential_valid": False,
        "identity_valid": False,
        "context_valid": False,
        "scope_valid": False,
        "timing_valid": False,
        "proximity_valid": True,
        "segmentation_valid": False,
        "destination_valid": False,
        "release_valid": False,
    },
    "cache_exfiltration": {
        "description": "Document cache is requested without admissible records, audit, or maintenance structure.",
        "target": "document_cache",
        "forced_visibility": True,
        "external_request": True,
        "document_export_request": True,
        "audit_export_request": True,
        "update_request": False,
        "admin_request": True,
        "print_request": False,
        "scan_request": False,
        "fax_request": False,
        "cloud_request": True,
        "cache_request": True,
        "credential_valid": True,
        "identity_valid": False,
        "context_valid": False,
        "scope_valid": False,
        "timing_valid": True,
        "proximity_valid": True,
        "segmentation_valid": False,
        "destination_valid": False,
        "release_valid": False,
    },
    "scan_leak": {
        "description": "Scan export is requested without valid destination or scope.",
        "target": "scan_to_email",
        "forced_visibility": True,
        "external_request": True,
        "document_export_request": True,
        "audit_export_request": False,
        "update_request": False,
        "admin_request": False,
        "print_request": False,
        "scan_request": True,
        "fax_request": False,
        "cloud_request": False,
        "cache_request": False,
        "credential_valid": True,
        "identity_valid": True,
        "context_valid": False,
        "scope_valid": False,
        "timing_valid": True,
        "proximity_valid": True,
        "segmentation_valid": False,
        "destination_valid": False,
        "release_valid": True,
    },
    "fax_abuse": {
        "description": "Fax transmission is forced without valid destination, scope, or segmentation.",
        "target": "fax_module",
        "forced_visibility": True,
        "external_request": True,
        "document_export_request": True,
        "audit_export_request": False,
        "update_request": False,
        "admin_request": False,
        "print_request": False,
        "scan_request": True,
        "fax_request": True,
        "cloud_request": False,
        "cache_request": False,
        "credential_valid": True,
        "identity_valid": True,
        "context_valid": False,
        "scope_valid": False,
        "timing_valid": True,
        "proximity_valid": True,
        "segmentation_valid": False,
        "destination_valid": False,
        "release_valid": True,
    },
    "firmware_push": {
        "description": "Firmware update path is requested without valid identity, timing, or maintenance context.",
        "target": "firmware_update",
        "forced_visibility": True,
        "external_request": True,
        "document_export_request": False,
        "audit_export_request": False,
        "update_request": True,
        "admin_request": True,
        "print_request": False,
        "scan_request": False,
        "fax_request": False,
        "cloud_request": True,
        "cache_request": False,
        "credential_valid": False,
        "identity_valid": False,
        "context_valid": False,
        "scope_valid": False,
        "timing_valid": False,
        "proximity_valid": True,
        "segmentation_valid": False,
        "destination_valid": True,
        "release_valid": True,
    },
    "admin_probe": {
        "description": "Administrative surface is probed without admissible maintenance authority.",
        "target": "admin_console",
        "forced_visibility": True,
        "external_request": True,
        "document_export_request": False,
        "audit_export_request": True,
        "update_request": False,
        "admin_request": True,
        "print_request": False,
        "scan_request": False,
        "fax_request": False,
        "cloud_request": True,
        "cache_request": False,
        "credential_valid": False,
        "identity_valid": False,
        "context_valid": False,
        "scope_valid": False,
        "timing_valid": False,
        "proximity_valid": True,
        "segmentation_valid": False,
        "destination_valid": True,
        "release_valid": True,
    },
    "telemetry_leak": {
        "description": "Telemetry export is requested without valid observability scope.",
        "target": "telemetry_export",
        "forced_visibility": True,
        "external_request": True,
        "document_export_request": False,
        "audit_export_request": True,
        "update_request": False,
        "admin_request": False,
        "print_request": False,
        "scan_request": False,
        "fax_request": False,
        "cloud_request": True,
        "cache_request": False,
        "credential_valid": True,
        "identity_valid": True,
        "context_valid": False,
        "scope_valid": False,
        "timing_valid": True,
        "proximity_valid": True,
        "segmentation_valid": False,
        "destination_valid": True,
        "release_valid": True,
    },
    "guest_escape": {
        "description": "Guest print structure attempts visibility into admin, queue, or document surfaces.",
        "target": "job_queue",
        "forced_visibility": True,
        "external_request": False,
        "document_export_request": True,
        "audit_export_request": False,
        "update_request": False,
        "admin_request": True,
        "print_request": True,
        "scan_request": False,
        "fax_request": False,
        "cloud_request": False,
        "cache_request": True,
        "credential_valid": True,
        "identity_valid": True,
        "context_valid": False,
        "scope_valid": False,
        "timing_valid": True,
        "proximity_valid": True,
        "segmentation_valid": False,
        "destination_valid": False,
        "release_valid": False,
    },
    "mobile_pair_spoof": {
        "description": "Nearby mobile pairing path is probed without valid proximity and pairing scope.",
        "target": "mobile_pairing",
        "forced_visibility": True,
        "external_request": False,
        "document_export_request": False,
        "audit_export_request": False,
        "update_request": False,
        "admin_request": False,
        "print_request": True,
        "scan_request": False,
        "fax_request": False,
        "cloud_request": False,
        "cache_request": False,
        "credential_valid": False,
        "identity_valid": False,
        "context_valid": False,
        "scope_valid": False,
        "timing_valid": True,
        "proximity_valid": False,
        "segmentation_valid": False,
        "destination_valid": True,
        "release_valid": True,
    },
}


SCENARIO_ORDER = (
    "local_print",
    "secure_print",
    "guest_print",
    "remote_print",
    "scan_to_local",
    "scan_to_email",
    "copy_document",
    "fax_send",
    "mobile_pair",
    "maintenance",
    "firmware_update",
    "maintenance_with_jobs",
    "maintenance_after_jobs_clear",
    "managed_service",
    "unsafe_remote_print",
)

PROFILE_ORDER = ("minimal", "balanced", "connected", "maintenance", "records", "strict")

REQUEST_ORDER = (
    "remote_job_spoof",
    "cache_exfiltration",
    "scan_leak",
    "fax_abuse",
    "firmware_push",
    "admin_probe",
    "telemetry_leak",
    "guest_escape",
    "mobile_pair_spoof",
)



STRUCTURAL_POSTURE = {
    "local_print": {"active_print_jobs": True, "active_scan_jobs": False, "active_cache_export": False, "maintenance_active": False, "queue_overloaded": False},
    "secure_print": {"active_print_jobs": True, "active_scan_jobs": False, "active_cache_export": False, "maintenance_active": False, "queue_overloaded": False},
    "guest_print": {"active_print_jobs": True, "active_scan_jobs": False, "active_cache_export": False, "maintenance_active": False, "queue_overloaded": False},
    "remote_print": {"active_print_jobs": True, "active_scan_jobs": False, "active_cache_export": False, "maintenance_active": False, "queue_overloaded": False},
    "scan_to_local": {"active_print_jobs": False, "active_scan_jobs": True, "active_cache_export": False, "maintenance_active": False, "queue_overloaded": False},
    "scan_to_email": {"active_print_jobs": False, "active_scan_jobs": True, "active_cache_export": True, "maintenance_active": False, "queue_overloaded": False},
    "copy_document": {"active_print_jobs": True, "active_scan_jobs": True, "active_cache_export": False, "maintenance_active": False, "queue_overloaded": False},
    "fax_send": {"active_print_jobs": False, "active_scan_jobs": True, "active_cache_export": True, "maintenance_active": False, "queue_overloaded": False},
    "mobile_pair": {"active_print_jobs": False, "active_scan_jobs": False, "active_cache_export": False, "maintenance_active": False, "queue_overloaded": False},
    "maintenance": {"active_print_jobs": False, "active_scan_jobs": False, "active_cache_export": False, "maintenance_active": True, "queue_overloaded": False},
    "firmware_update": {"active_print_jobs": False, "active_scan_jobs": False, "active_cache_export": False, "maintenance_active": True, "queue_overloaded": False},
    "maintenance_with_jobs": {"active_print_jobs": True, "active_scan_jobs": True, "active_cache_export": False, "maintenance_active": True, "queue_overloaded": False},
    "maintenance_after_jobs_clear": {"active_print_jobs": False, "active_scan_jobs": False, "active_cache_export": False, "maintenance_active": True, "queue_overloaded": False},
    "managed_service": {"active_print_jobs": False, "active_scan_jobs": False, "active_cache_export": False, "maintenance_active": True, "queue_overloaded": False},
    "unsafe_remote_print": {"active_print_jobs": False, "active_scan_jobs": False, "active_cache_export": True, "maintenance_active": False, "queue_overloaded": False},
}

DEPENDENCY_GRAPH = {
    "remote_print_api": ("cloud_print", "credential_store", "secure_release", "job_queue"),
    "cloud_print": ("credential_store", "job_queue"),
    "scan_to_email": ("scan_engine", "credential_store", "audit_logs"),
    "fax_module": ("scan_engine", "credential_store", "audit_logs"),
    "secure_release": ("credential_store",),
    "firmware_update": ("admin_console",),
    "document_cache": ("audit_logs",),
    "telemetry_export": ("admin_console", "audit_logs"),
}

CONFLICT_GRAPH = {
    "firmware_update": ("active_print_jobs", "active_scan_jobs", "active_cache_export", "queue_overloaded"),
    "admin_console": ("queue_overloaded",),
    "document_cache": ("active_print_jobs", "active_scan_jobs"),
    "scan_to_email": ("maintenance_active", "queue_overloaded"),
    "fax_module": ("maintenance_active", "queue_overloaded"),
    "remote_print_api": ("maintenance_active", "queue_overloaded"),
    "cloud_print": ("maintenance_active", "queue_overloaded"),
}

ADMITTED_STATES = (VISIBLE, ISOLATED)

# ==============================================================================
# SECTION: STRUCTURAL GOVERNANCE ENGINE
# ==============================================================================

# ==============================================================================
# SECTION: GOVERNANCE LAYERS — POLICY, ROLE, CONTEXT, APPROVAL, RELEASE
# ==============================================================================

POLICY_PROFILES = {
    "standard": {
        "description": "Default policy; structural resolution is used without additional policy restriction.",
        "allow_remote_print": True,
        "allow_scan_export": True,
        "allow_firmware_update": True,
        "allow_document_cache": False,
        "admin_approval": True,
        "emergency_patch": False,
        "require_after_hours_for_update": False,
    },
    "business_hours": {
        "description": "Business-hours policy admits productive print work but defers firmware update until approved maintenance timing.",
        "allow_remote_print": True,
        "allow_scan_export": True,
        "allow_firmware_update": False,
        "allow_document_cache": False,
        "admin_approval": True,
        "emergency_patch": False,
        "require_after_hours_for_update": True,
    },
    "after_hours": {
        "description": "After-hours policy admits approved maintenance update after workload clearance while keeping document exposure refused.",
        "allow_remote_print": False,
        "allow_scan_export": False,
        "allow_firmware_update": True,
        "allow_document_cache": False,
        "admin_approval": True,
        "emergency_patch": False,
        "require_after_hours_for_update": False,
    },
    "emergency_patch": {
        "description": "Emergency patch policy admits firmware update after structural workload clearance but does not bypass active workload conflicts.",
        "allow_remote_print": False,
        "allow_scan_export": False,
        "allow_firmware_update": True,
        "allow_document_cache": False,
        "admin_approval": True,
        "emergency_patch": True,
        "require_after_hours_for_update": False,
    },
    "records_lockdown": {
        "description": "Records lockdown refuses remote document movement and cache visibility while preserving local non-export behavior.",
        "allow_remote_print": False,
        "allow_scan_export": False,
        "allow_firmware_update": False,
        "allow_document_cache": False,
        "admin_approval": False,
        "emergency_patch": False,
        "require_after_hours_for_update": True,
    },
}

POLICY_ORDER = tuple(POLICY_PROFILES.keys())


DOCUMENT_CLASSES = {
    "public_document": {
        "description": "Public document class; ordinary print and approved export visibility may be admitted by existing structure.",
        "allow_remote_print": True,
        "allow_scan_export": True,
        "allow_fax_export": True,
        "allow_document_cache": False,
        "require_secure_release": False,
        "require_audit": False,
        "regulated": False,
    },
    "internal_document": {
        "description": "Internal document class; remote print remains possible, but outbound document export is deferred unless separately admitted.",
        "allow_remote_print": True,
        "allow_scan_export": False,
        "allow_fax_export": False,
        "allow_document_cache": False,
        "require_secure_release": True,
        "require_audit": True,
        "regulated": False,
    },
    "confidential_document": {
        "description": "Confidential document class; remote document movement is deferred and local secure release is required.",
        "allow_remote_print": False,
        "allow_scan_export": False,
        "allow_fax_export": False,
        "allow_document_cache": False,
        "require_secure_release": True,
        "require_audit": True,
        "regulated": False,
    },
    "regulated_record": {
        "description": "Regulated record class; remote movement, scan export, fax export, and cache visibility are refused or deferred under records-grade restrictions.",
        "allow_remote_print": False,
        "allow_scan_export": False,
        "allow_fax_export": False,
        "allow_document_cache": False,
        "require_secure_release": True,
        "require_audit": True,
        "regulated": True,
    },
}

DOCUMENT_CLASS_ORDER = tuple(DOCUMENT_CLASSES.keys())


ROLE_PROFILES = {
    "walkup_user": {
        "description": "Walk-up user; local print and local release may be admitted, while remote movement and administrative visibility are deferred.",
        "allow_remote_print": False,
        "allow_scan_export": False,
        "allow_fax_export": False,
        "allow_document_cache": False,
        "allow_admin_console": False,
        "allow_firmware_update": False,
        "allow_secure_release": True,
        "allow_audit_logs": False,
    },
    "employee": {
        "description": "Employee role; ordinary authenticated print visibility may be admitted, while administrative and records-grade surfaces remain refused or deferred.",
        "allow_remote_print": True,
        "allow_scan_export": False,
        "allow_fax_export": False,
        "allow_document_cache": False,
        "allow_admin_console": False,
        "allow_firmware_update": False,
        "allow_secure_release": True,
        "allow_audit_logs": False,
    },
    "department_admin": {
        "description": "Department administrator; department print operations and limited audit visibility may be admitted, while firmware update remains outside role scope.",
        "allow_remote_print": True,
        "allow_scan_export": True,
        "allow_fax_export": False,
        "allow_document_cache": False,
        "allow_admin_console": False,
        "allow_firmware_update": False,
        "allow_secure_release": True,
        "allow_audit_logs": True,
    },
    "it_admin": {
        "description": "IT administrator; maintenance and firmware visibility may be admitted, while document movement remains structurally minimized.",
        "allow_remote_print": False,
        "allow_scan_export": False,
        "allow_fax_export": False,
        "allow_document_cache": False,
        "allow_admin_console": True,
        "allow_firmware_update": True,
        "allow_secure_release": False,
        "allow_audit_logs": True,
    },
    "records_officer": {
        "description": "Records officer; regulated release and audit visibility may be admitted, while remote movement, fax export, and cache visibility remain refused or deferred.",
        "allow_remote_print": False,
        "allow_scan_export": False,
        "allow_fax_export": False,
        "allow_document_cache": False,
        "allow_admin_console": False,
        "allow_firmware_update": False,
        "allow_secure_release": True,
        "allow_audit_logs": True,
    },
}

ROLE_ORDER = tuple(ROLE_PROFILES.keys())


CONTEXT_PROFILES = {
    "trusted_office_device": {
        "description": "Trusted office device on managed office network; ordinary employee print visibility may be admitted while sensitive surfaces remain governed.",
        "allow_remote_print": True,
        "allow_scan_export": True,
        "allow_fax_export": False,
        "allow_admin_console": False,
        "allow_firmware_update": False,
        "allow_telemetry_export": False,
        "allow_document_cache": False,
        "allow_local_network": True,
        "allow_mobile_pairing": True,
    },
    "shared_floor_terminal": {
        "description": "Shared floor terminal; local output and secure release may be admitted, while remote movement and administrative surfaces are deferred.",
        "allow_remote_print": False,
        "allow_scan_export": False,
        "allow_fax_export": False,
        "allow_admin_console": False,
        "allow_firmware_update": False,
        "allow_telemetry_export": False,
        "allow_document_cache": False,
        "allow_local_network": True,
        "allow_mobile_pairing": False,
    },
    "remote_employee_laptop": {
        "description": "Remote employee laptop; bounded remote print may be admitted, while scan export, fax, admin, firmware, telemetry, and cache visibility remain deferred or refused.",
        "allow_remote_print": True,
        "allow_scan_export": False,
        "allow_fax_export": False,
        "allow_admin_console": False,
        "allow_firmware_update": False,
        "allow_telemetry_export": False,
        "allow_document_cache": False,
        "allow_local_network": False,
        "allow_mobile_pairing": False,
    },
    "untrusted_network": {
        "description": "Untrusted network; external, administrative, export, telemetry, cache, and pairing visibility are not admitted.",
        "allow_remote_print": False,
        "allow_scan_export": False,
        "allow_fax_export": False,
        "allow_admin_console": False,
        "allow_firmware_update": False,
        "allow_telemetry_export": False,
        "allow_document_cache": False,
        "allow_local_network": False,
        "allow_mobile_pairing": False,
    },
    "service_vendor_network": {
        "description": "Service vendor network; maintenance observability may be admitted, while document movement and document cache visibility remain structurally minimized.",
        "allow_remote_print": False,
        "allow_scan_export": False,
        "allow_fax_export": False,
        "allow_admin_console": True,
        "allow_firmware_update": True,
        "allow_telemetry_export": True,
        "allow_document_cache": False,
        "allow_local_network": False,
        "allow_mobile_pairing": False,
    },
}

CONTEXT_ORDER = tuple(CONTEXT_PROFILES.keys())


APPROVAL_PROFILES = {
    "no_approval": {
        "description": "No approval attached; remote movement, export, administrative, firmware, telemetry, and cache visibility are deferred or refused.",
        "allow_remote_print": False,
        "allow_scan_export": False,
        "allow_fax_export": False,
        "allow_admin_console": False,
        "allow_firmware_update": False,
        "allow_telemetry_export": False,
        "allow_document_cache": False,
        "allow_secure_release": True,
        "allow_audit_logs": False,
    },
    "manager_approved": {
        "description": "Manager approval admits ordinary bounded remote print visibility but does not admit export, firmware, telemetry, or cache visibility.",
        "allow_remote_print": True,
        "allow_scan_export": False,
        "allow_fax_export": False,
        "allow_admin_console": False,
        "allow_firmware_update": False,
        "allow_telemetry_export": False,
        "allow_document_cache": False,
        "allow_secure_release": True,
        "allow_audit_logs": True,
    },
    "records_approved": {
        "description": "Records approval admits audit and records-grade release visibility while keeping remote movement, fax, export, firmware, and cache visibility narrow.",
        "allow_remote_print": False,
        "allow_scan_export": False,
        "allow_fax_export": False,
        "allow_admin_console": False,
        "allow_firmware_update": False,
        "allow_telemetry_export": False,
        "allow_document_cache": False,
        "allow_secure_release": True,
        "allow_audit_logs": True,
    },
    "security_approved": {
        "description": "Security approval admits bounded remote print and scan export visibility under already valid role, document, policy, and context structure.",
        "allow_remote_print": True,
        "allow_scan_export": True,
        "allow_fax_export": False,
        "allow_admin_console": True,
        "allow_firmware_update": False,
        "allow_telemetry_export": True,
        "allow_document_cache": False,
        "allow_secure_release": True,
        "allow_audit_logs": True,
    },
    "emergency_override_approved": {
        "description": "Emergency override approval admits maintenance and firmware visibility after structural readiness, without admitting document movement or cache exposure.",
        "allow_remote_print": False,
        "allow_scan_export": False,
        "allow_fax_export": False,
        "allow_admin_console": True,
        "allow_firmware_update": True,
        "allow_telemetry_export": True,
        "allow_document_cache": False,
        "allow_secure_release": False,
        "allow_audit_logs": True,
    },
}

APPROVAL_ORDER = tuple(APPROVAL_PROFILES.keys())


RELEASE_MODES = {
    "immediate_print": {
        "description": "Immediate print release admits ordinary physical output after approved submission, but does not add secure pull, badge, records, or quarantine release structure.",
        "allow_remote_print": True,
        "allow_physical_output": True,
        "allow_secure_release": False,
        "allow_audit_logs": False,
        "allow_records_release": False,
        "quarantine_output": False,
    },
    "secure_pull_release": {
        "description": "Secure pull release admits remote submission only when final physical output remains locally released through secure release structure.",
        "allow_remote_print": True,
        "allow_physical_output": True,
        "allow_secure_release": True,
        "allow_audit_logs": True,
        "allow_records_release": False,
        "quarantine_output": False,
    },
    "badge_release": {
        "description": "Badge release admits remote submission and local physical release through badge-bound identity confirmation.",
        "allow_remote_print": True,
        "allow_physical_output": True,
        "allow_secure_release": True,
        "allow_audit_logs": True,
        "allow_records_release": False,
        "quarantine_output": False,
    },
    "records_release": {
        "description": "Records release admits records-grade local release and audit visibility while deferring remote movement and ordinary immediate output paths.",
        "allow_remote_print": False,
        "allow_physical_output": True,
        "allow_secure_release": True,
        "allow_audit_logs": True,
        "allow_records_release": True,
        "quarantine_output": False,
    },
    "quarantine_release": {
        "description": "Quarantine release defers physical output and remote movement until the document job is separately cleared.",
        "allow_remote_print": False,
        "allow_physical_output": False,
        "allow_secure_release": False,
        "allow_audit_logs": True,
        "allow_records_release": False,
        "quarantine_output": True,
    },
}

RELEASE_MODE_ORDER = tuple(RELEASE_MODES.keys())


ACTOR_PROFILES = {
    "requester": {
        "description": "Requester submits document jobs but does not perform final release, records review, maintenance, or audit inspection.",
        "allow_submit": True,
        "allow_release": False,
        "allow_audit_review": False,
        "allow_records_release": False,
        "allow_service_operations": False,
        "allow_admin_console": False,
        "allow_firmware_update": False,
        "allow_document_cache": False,
    },
    "approver": {
        "description": "Approver admits bounded job movement and approval visibility but does not perform final physical release or device maintenance.",
        "allow_submit": False,
        "allow_release": False,
        "allow_audit_review": True,
        "allow_records_release": False,
        "allow_service_operations": False,
        "allow_admin_console": False,
        "allow_firmware_update": False,
        "allow_document_cache": False,
    },
    "release_operator": {
        "description": "Release operator performs local release of already admitted jobs but does not submit remote jobs, inspect records, or perform maintenance.",
        "allow_submit": False,
        "allow_release": True,
        "allow_audit_review": False,
        "allow_records_release": False,
        "allow_service_operations": False,
        "allow_admin_console": False,
        "allow_firmware_update": False,
        "allow_document_cache": False,
    },
    "auditor": {
        "description": "Auditor inspects audit visibility without admitting document movement, physical output, firmware update, or cache exposure.",
        "allow_submit": False,
        "allow_release": False,
        "allow_audit_review": True,
        "allow_records_release": False,
        "allow_service_operations": False,
        "allow_admin_console": False,
        "allow_firmware_update": False,
        "allow_document_cache": False,
    },
    "records_operator": {
        "description": "Records operator performs records-grade local release and audit review while keeping ordinary remote movement and maintenance separate.",
        "allow_submit": False,
        "allow_release": True,
        "allow_audit_review": True,
        "allow_records_release": True,
        "allow_service_operations": False,
        "allow_admin_console": False,
        "allow_firmware_update": False,
        "allow_document_cache": False,
    },
    "service_operator": {
        "description": "Service operator performs device service visibility while document movement, release, and cache exposure remain governed separately.",
        "allow_submit": False,
        "allow_release": False,
        "allow_audit_review": True,
        "allow_records_release": False,
        "allow_service_operations": True,
        "allow_admin_console": True,
        "allow_firmware_update": True,
        "allow_document_cache": False,
    },
}

ACTOR_ORDER = tuple(ACTOR_PROFILES.keys())


JOB_STATES = {
    "draft_job": {
        "description": "Draft job exists before admissible submission; remote movement, physical output, release, and audit visibility remain deferred or refused.",
    },
    "submitted_job": {
        "description": "Submitted job has entered the job queue; submission visibility may remain admitted while final physical output remains pending.",
    },
    "held_job": {
        "description": "Held job is waiting for local release or review; queue and identity visibility may remain admitted while physical output is deferred.",
    },
    "released_job": {
        "description": "Released job has satisfied local release structure; physical output visibility may be admitted for the release operator.",
    },
    "completed_job": {
        "description": "Completed job has finished output; ordinary movement and active release visibility are closed while bounded audit visibility may remain.",
    },
    "cancelled_job": {
        "description": "Cancelled job closes submission and output paths while retaining bounded queue or audit evidence.",
    },
    "quarantined_job": {
        "description": "Quarantined job holds submission evidence while remote movement, release, and physical output are deferred pending clearance.",
    },
}

JOB_STATE_ORDER = tuple(JOB_STATES.keys())


RETENTION_STATES = {
    "no_retention": {
        "description": "No retention keeps active output and cache evidence closed after immediate processing.",
    },
    "short_spool_retention": {
        "description": "Short spool retention keeps bounded queue evidence for active job handling while cache visibility remains refused.",
    },
    "audit_retention": {
        "description": "Audit retention admits bounded audit evidence while document cache visibility remains refused.",
    },
    "records_retention": {
        "description": "Records retention admits records-grade queue and audit evidence while document cache remains governed.",
    },
    "legal_hold_retention": {
        "description": "Legal hold retention preserves queue, audit, and cache evidence in isolated form while document movement and output remain closed.",
    },
}

RETENTION_STATE_ORDER = tuple(RETENTION_STATES.keys())


DATA_DESTINATIONS = {
    "local_printer_only": {
        "description": "Local printer only keeps document movement bound to the local output device and refuses external routing visibility.",
    },
    "department_queue": {
        "description": "Department queue admits bounded departmental routing while keeping external export, vendor cloud, and unrestricted destination visibility deferred or refused.",
    },
    "approved_email_domain": {
        "description": "Approved email domain admits bounded scan export visibility when export structure is otherwise valid.",
    },
    "external_email_domain": {
        "description": "External email domain defers document export visibility unless additional destination controls are satisfied.",
    },
    "vendor_cloud_queue": {
        "description": "Vendor cloud queue admits bounded cloud routing while keeping cache, unrestricted export, and administrative surfaces governed separately.",
    },
    "blocked_destination": {
        "description": "Blocked destination refuses document movement visibility and keeps only bounded evidence surfaces available.",
    },
}

DATA_DESTINATION_ORDER = tuple(DATA_DESTINATIONS.keys())


DEVICE_HEALTHS = {
    "healthy_device": {
        "description": "Healthy device admits normal routing and output visibility according to the existing governance structure.",
    },
    "low_toner": {
        "description": "Low toner preserves submission and queue visibility while marking physical output as dependent on consumable readiness.",
    },
    "paper_jam": {
        "description": "Paper jam preserves job evidence and local service visibility while deferring physical output.",
    },
    "offline_device": {
        "description": "Offline device defers live routing, release, and physical output while retaining bounded job and audit evidence.",
    },
    "compromised_device": {
        "description": "Compromised device refuses or defers movement, output, release, and administrative visibility while preserving bounded evidence.",
    },
    "maintenance_required": {
        "description": "Maintenance required state defers ordinary output and movement while admitting bounded service and audit visibility.",
    },
}

DEVICE_HEALTH_ORDER = tuple(DEVICE_HEALTHS.keys())


RISK_POSTURES = {
    "normal_risk": {
        "description": "Normal risk posture preserves visibility according to the existing governance and device-health structure.",
    },
    "elevated_risk": {
        "description": "Elevated risk posture defers broad movement and output while preserving bounded queue and audit evidence.",
    },
    "data_loss_risk": {
        "description": "Data loss risk posture defers export and remote movement while preserving audit evidence and refusing cache exposure unless separately held.",
    },
    "malware_risk": {
        "description": "Malware risk posture defers execution-like device movement, remote routing, service change, and output while preserving bounded evidence.",
    },
    "insider_risk": {
        "description": "Insider risk posture narrows release, remote movement, and cache visibility while preserving audit evidence for review.",
    },
    "regulatory_risk": {
        "description": "Regulatory risk posture defers document movement and ordinary release while preserving records-grade audit evidence.",
    },
}

RISK_POSTURE_ORDER = tuple(RISK_POSTURES.keys())


COMPLIANCE_MODES = {
    "ordinary_mode": {
        "description": "Ordinary mode preserves visibility according to the current governance, device, and risk structure.",
    },
    "confidential_mode": {
        "description": "Confidential mode narrows document movement and release visibility while preserving bounded evidence.",
    },
    "regulated_mode": {
        "description": "Regulated mode defers document movement and ordinary output while preserving audit evidence.",
    },
    "records_mode": {
        "description": "Records mode preserves records-grade queue, release, and audit visibility while keeping remote movement narrow.",
    },
    "legal_hold_mode": {
        "description": "Legal hold mode preserves queue, audit, and cache evidence while deferring output and document movement.",
    },
    "incident_mode": {
        "description": "Incident mode defers movement, output, service change, and release visibility while preserving bounded evidence.",
    },
}

COMPLIANCE_MODE_ORDER = tuple(COMPLIANCE_MODES.keys())


TRUST_ZONES = {
    "local_trusted_zone": {
        "description": "Local trusted zone preserves visibility according to the current governance and compliance structure.",
    },
    "department_zone": {
        "description": "Department zone admits bounded departmental routing and local release while narrowing external movement.",
    },
    "enterprise_zone": {
        "description": "Enterprise zone admits bounded internal routing and audit visibility while keeping cache and external export governed.",
    },
    "guest_zone": {
        "description": "Guest zone defers document movement, output, release, administrative, firmware, telemetry, and cache visibility while preserving bounded evidence.",
    },
    "vendor_zone": {
        "description": "Vendor zone admits bounded service visibility while deferring document movement, output, release, and cache exposure.",
    },
    "external_zone": {
        "description": "External zone defers document movement, output, release, service change, telemetry, and cache visibility while preserving bounded evidence.",
    },
}

TRUST_ZONE_ORDER = tuple(TRUST_ZONES.keys())

EVIDENCE_VIEWS = {
    "no_evidence_view": {
        "description": "No evidence view keeps ordinary evidence surfaces closed unless another structure separately admits them.",
    },
    "operator_evidence_view": {
        "description": "Operator evidence view admits bounded queue visibility for operational handling without opening audit or cache evidence.",
    },
    "audit_evidence_view": {
        "description": "Audit evidence view admits bounded audit visibility while keeping cache and document movement governed separately.",
    },
    "records_evidence_view": {
        "description": "Records evidence view admits queue and audit evidence for records review while keeping cache visibility narrow.",
    },
    "incident_evidence_view": {
        "description": "Incident evidence view preserves queue, audit, and cache evidence while deferring movement, release, and physical output.",
    },
    "legal_evidence_view": {
        "description": "Legal evidence view preserves queue, audit, and cache evidence while deferring movement, release, and physical output.",
    },
}

EVIDENCE_VIEW_ORDER = tuple(EVIDENCE_VIEWS.keys())

RECOVERY_ACTIONS = {
    "no_recovery_action": {
        "description": "No recovery action preserves the current visibility outcome without opening additional recovery surfaces.",
    },
    "retry_job": {
        "description": "Retry job preserves queue visibility and permits output retry only when the job remains output-admissible.",
    },
    "requeue_job": {
        "description": "Requeue job admits bounded queue handling while deferring physical output until the job is released again.",
    },
    "purge_job": {
        "description": "Purge job closes output, movement, release, and cache visibility while preserving bounded audit evidence.",
    },
    "restore_job": {
        "description": "Restore job admits bounded queue restoration from retained evidence while keeping physical output pending.",
    },
    "escalate_review": {
        "description": "Escalate review preserves queue, audit, and cache evidence while deferring movement, release, and physical output.",
    },
}

RECOVERY_ACTION_ORDER = tuple(RECOVERY_ACTIONS.keys())

TRANSFER_BOUNDARIES = {
    "no_transfer": {
        "description": "No transfer keeps document and job movement closed while preserving only locally admitted visibility.",
    },
    "same_device_transfer": {
        "description": "Same device transfer keeps movement within the current printer boundary and admits only local queue or release visibility.",
    },
    "same_department_transfer": {
        "description": "Same department transfer admits bounded department queue movement while keeping external movement and cache visibility governed.",
    },
    "enterprise_transfer": {
        "description": "Enterprise transfer admits bounded internal enterprise routing and audit evidence while keeping external export governed.",
    },
    "vendor_transfer": {
        "description": "Vendor transfer admits bounded service routing and service visibility while deferring document output and ordinary release.",
    },
    "external_transfer": {
        "description": "External transfer defers or refuses document movement, output, release, and cache visibility while preserving bounded evidence.",
    },
}

TRANSFER_BOUNDARY_ORDER = tuple(TRANSFER_BOUNDARIES.keys())


CUSTODY_STATES = {
    "no_custody": {
        "description": "No custody keeps job, release, cache, and evidence visibility limited to structures already admitted elsewhere.",
    },
    "operator_custody": {
        "description": "Operator custody admits bounded local job handling and release responsibility while keeping audit and cache governed separately.",
    },
    "department_custody": {
        "description": "Department custody admits bounded department queue and audit responsibility while keeping external movement governed.",
    },
    "records_custody": {
        "description": "Records custody admits records-grade queue, release, and audit responsibility while keeping document movement narrow.",
    },
    "incident_custody": {
        "description": "Incident custody preserves queue, audit, and cache evidence while deferring movement, release, and physical output.",
    },
    "legal_custody": {
        "description": "Legal custody preserves queue, audit, and cache evidence while holding movement, release, and physical output closed.",
    },
}

CUSTODY_STATE_ORDER = tuple(CUSTODY_STATES.keys())


FINAL_DECISIONS = {
    "allow_output": {
        "description": "Allow output admits physical output and local release when the preceding structure is compatible with output."
    },
    "hold_output": {
        "description": "Hold output defers physical output and release while preserving bounded queue and evidence visibility."
    },
    "deny_output": {
        "description": "Deny output closes physical output and release while preserving bounded audit evidence."
    },
    "allow_evidence_only": {
        "description": "Allow evidence only preserves queue, audit, and cache evidence while keeping output and movement closed."
    },
    "allow_service_only": {
        "description": "Allow service only admits bounded service visibility while keeping document output and movement closed."
    },
    "escalate_decision": {
        "description": "Escalate decision preserves review evidence while deferring output, movement, release, and broad service change."
    },
}

FINAL_DECISION_ORDER = tuple(FINAL_DECISIONS.keys())


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
        and request["destination_valid"]
        and request["release_valid"]
    )
    consistency_checks = [
        not request["forced_visibility"],
        not (request["external_request"] and not request["identity_valid"]),
        not (request["document_export_request"] and not request["destination_valid"]),
        not (request["document_export_request"] and not request["scope_valid"]),
        not (request["audit_export_request"] and not request["scope_valid"]),
        not (request["update_request"] and not request["timing_valid"]),
        not (request["admin_request"] and not request["identity_valid"]),
        not (request["scan_request"] and not request["destination_valid"] and request["document_export_request"]),
        not (request["fax_request"] and not request["destination_valid"]),
        not (request["cloud_request"] and not request["identity_valid"]),
        not (request["cache_request"] and not request["scope_valid"]),
    ]
    consistent = all(consistency_checks)
    return complete, consistent, complete and consistent


def scenario_profile_consistent(scenario: dict, profile: dict) -> bool:
    checks = [
        not (scenario["allow_external"] and not scenario["authenticated_remote"] and not scenario["fax_required"]),
        not (scenario["allow_external"] and not profile["allow_isolated_external"]),
        not (scenario["allow_document_export"] and not profile["allow_document_export"]),
        not (scenario["allow_audit_export"] and not profile["allow_audit_export"] and (scenario["maintenance_window"] or scenario["allow_document_export"])),
        not (scenario["maintenance_window"] and not profile["allow_admin"] and not profile["allow_ota"]),
        not (scenario["cloud_required"] and not profile["allow_cloud"]),
        not (scenario["scan_required"] and not profile["allow_scan"] and scenario["allow_document_export"]),
        not (scenario["fax_required"] and not profile["allow_fax"]),
        not (scenario["secure_release_required"] and not profile["allow_secure_release"]),
        not (scenario["admin_required"] and not profile["allow_admin"]),
    ]
    return all(checks)


def request_profile_consistent(request: dict, profile: dict) -> bool:
    checks = [
        not (request["external_request"] and not profile["allow_isolated_external"]),
        not (request["document_export_request"] and not profile["allow_document_export"]),
        not (request["audit_export_request"] and not profile["allow_audit_export"]),
        not (request["update_request"] and not profile["allow_ota"]),
        not (request["admin_request"] and not profile["allow_admin"]),
        not (request["scan_request"] and not profile["allow_scan"] and request["document_export_request"]),
        not (request["fax_request"] and not profile["allow_fax"]),
        not (request["cloud_request"] and not profile["allow_cloud"]),
        not (request["cache_request"] and not profile["allow_cache_visibility"]),
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

    if capability_key == "document_cache":
        if profile["allow_cache_visibility"] and scenario["allow_audit_export"] and scenario_key in ("maintenance", "managed_service"):
            return ISOLATED, DOCUMENT_CACHE_RESOLUTION_BASIS
        return FORBIDDEN, "Document cache exists, but cache visibility is not admitted by the selected structure."

    if capability_key == "scan_to_email":
        if required and profile["allow_document_export"] and scenario["allow_document_export"] and scenario["scan_required"]:
            return ISOLATED, SCAN_EXPORT_RESOLUTION_BASIS
        if required:
            return BLOCKED, "Scan export was requested but destination, export, or scan structure is insufficient."
        return FORBIDDEN, "Scan-to-email capability is not required for this scenario."

    if capability_key == "remote_print_api":
        if required and profile["allow_isolated_external"] and scenario["allow_external"] and scenario["authenticated_remote"]:
            return ISOLATED, REMOTE_PRINT_RESOLUTION_BASIS
        if required:
            return BLOCKED, "Remote print was requested but remote authentication or profile isolation is insufficient."
        return FORBIDDEN, "Remote print API is not required for this scenario."

    if capability_key == "cloud_print":
        if required and profile["allow_cloud"] and scenario["cloud_required"]:
            return ISOLATED, "Cloud print is admitted only inside bounded cloud print structure."
        if required:
            return BLOCKED, "Cloud print was requested but cloud structure is insufficient."
        if profile["allow_dormant_network"]:
            return DORMANT, "Cloud print capability exists but is not currently required."
        return FORBIDDEN, "Cloud print is not admitted by the selected profile."

    if capability_key == "fax_module":
        if required and profile["allow_fax"] and scenario["fax_required"] and scenario["allow_document_export"]:
            return ISOLATED, "Fax capability is admitted only for explicit destination-bound document transmission."
        if required:
            return BLOCKED, "Fax was requested but fax or destination export structure is insufficient."
        return FORBIDDEN, "Fax module is not required for this scenario."

    if capability_key == "admin_console":
        if required and profile["allow_admin"] and scenario["admin_required"] and scenario["maintenance_window"]:
            return ISOLATED, "Admin console is admitted only inside authenticated maintenance posture."
        if required:
            return BLOCKED, "Admin console was requested but administrative or maintenance structure is insufficient."
        return FORBIDDEN, "Admin console is not required for this scenario."

    if capability_key == "firmware_update":
        if required and profile["allow_ota"] and scenario["maintenance_window"] and scenario["authenticated_remote"]:
            return ISOLATED, "Firmware update is admitted inside authenticated update posture."
        if required:
            return BLOCKED, "Firmware update was requested but update structure is insufficient."
        return FORBIDDEN, "Firmware update is not required for this scenario."

    if capability_key == "telemetry_export":
        if required and profile["allow_telemetry"] and scenario_key == "managed_service":
            return ISOLATED, "Telemetry export is admitted only inside managed diagnostic structure."
        if required:
            return BLOCKED, "Telemetry export was requested but observability structure is insufficient."
        return FORBIDDEN, "Telemetry export is not required for this scenario."

    if capability_key == "audit_logs":
        if required and profile["allow_audit_export"] and scenario["allow_audit_export"]:
            return ISOLATED, "Audit logs are admitted only inside audit-admissible structure."
        if required:
            return BLOCKED, "Audit logs were requested but audit structure is insufficient."
        return FORBIDDEN, "Audit logs are not required for this scenario."

    if capability_key == "credential_store":
        if required and scenario["credential_required"]:
            if capability.exposure <= profile["max_exposure_visible"]:
                return VISIBLE, "Credential structure is required and exposure is within visible limit."
            return ISOLATED, "Credential structure is required but constrained into isolated visibility."
        return FORBIDDEN, "Credential store is not required for this scenario."

    if capability_key == "secure_release":
        if required and profile["allow_secure_release"] and scenario["secure_release_required"]:
            return ISOLATED, "Secure release is required and admitted through local release structure."
        if required:
            return BLOCKED, "Secure release was requested but release structure is insufficient."
        return FORBIDDEN, "Secure release is not required for this scenario."

    if capability_key == "mobile_pairing":
        if required and profile["allow_mobile_pairing"] and scenario["proximity_required"] and scenario["segmentation_required"]:
            return ISOLATED, "Mobile pairing is admitted through proximity and segmentation structure."
        if required:
            return BLOCKED, "Mobile pairing was requested but proximity or segmentation structure is insufficient."
        if profile["allow_dormant_network"]:
            return DORMANT, "Mobile pairing exists but is not currently required."
        return FORBIDDEN, "Mobile pairing is not admitted by the selected profile."

    if capability_key in ("lan_print", "wifi_print"):
        if required:
            if capability.exposure <= profile["max_exposure_visible"]:
                return VISIBLE, "Network print path is required and exposure is within visible limit."
            if profile["allow_dormant_network"] or profile["allow_isolated_external"]:
                return ISOLATED, "Network print path is required but constrained into isolated visibility."
            return BLOCKED, "Network print path was requested but network visibility is not admitted."
        if profile["allow_dormant_network"]:
            return DORMANT, "Network print path exists but is not currently required."
        return FORBIDDEN, "Network print path is not admitted by the selected profile."

    if capability_key == "scan_engine":
        if required and scenario["scan_required"]:
            if profile["allow_scan"] or scenario_key == "copy_document":
                if capability.exposure <= profile["max_exposure_visible"]:
                    return VISIBLE, "Scan engine is required and exposure is within visible limit."
                return ISOLATED, "Scan engine is required but constrained into isolated visibility."
            return BLOCKED, "Scan engine was requested but scan structure is not admitted."
        return FORBIDDEN, "Scan engine is not required for this scenario."

    if capability_key == "job_queue":
        if required:
            if capability.exposure <= profile["max_exposure_visible"]:
                return VISIBLE, "Job queue is required and exposure is within visible limit."
            return ISOLATED, "Job queue is required but constrained into isolated visibility."
        return FORBIDDEN, "Job queue is not required for this scenario."

    if capability_key == "supply_monitor":
        if required:
            if capability.exposure <= profile["max_exposure_visible"]:
                return VISIBLE, "Supply monitor supports the scenario and exposure is within visible limit."
            return ISOLATED, "Supply monitor supports the scenario but is constrained into isolated visibility."
        if profile["allow_dormant_network"]:
            return DORMANT, "Supply monitor exists but is not currently required."
        return FORBIDDEN, "Supply monitor is not admitted by the selected profile."

    if required:
        if capability.exposure <= profile["max_exposure_visible"]:
            return VISIBLE, "Capability is required and exposure is within visible limit."
        return ISOLATED, "Capability is required but constrained into isolated visibility."

    return DORMANT, "Capability exists but is not currently required."


def resolve_capability(capability_key: str, scenario_key: str, profile_key: str, request_key: str) -> dict:
    capability = CAPABILITIES[capability_key]
    scenario = SCENARIOS[scenario_key]
    profile = PROFILES[profile_key]
    request = REQUESTS[request_key]
    protection_complete, protection_consistent, protection_admissible, request_complete, request_consistent, caps_admissible = protection_status(scenario, profile, request)
    raw_state, raw_reason = raw_state_and_reason(capability_key, capability, scenario_key, scenario, profile, request)
    final_state = raw_state if caps_admissible else BLOCKED
    final_reason = raw_reason if caps_admissible else "Global admissibility gate closed; capability visibility collapses to BLOCKED."
    payload = {
        "project": PROJECT_NAME,
        "version": VERSION,
        "capability_key": capability_key,
        "capability": capability.name,
        "scenario": scenario_key,
        "profile": profile_key,
        "request": request_key,
        "raw_state": raw_state,
        "final_state": final_state,
        "reason": final_reason,
        "protection_complete": protection_complete,
        "protection_consistent": protection_consistent,
        "protection_admissible": protection_admissible,
        "request_complete": request_complete,
        "request_consistent": request_consistent,
        "caps_admissible": caps_admissible,
    }
    payload["certificate"] = protection_certificate(payload)
    return payload


def apply_dependency_layer(items: List[dict], scenario_key: str) -> List[dict]:
    state_by_key = {item["capability_key"]: item["final_state"] for item in items}
    posture = STRUCTURAL_POSTURE.get(scenario_key, {})
    updated = []
    for item in items:
        capability_key = item["capability_key"]
        final_state = item["final_state"]
        dependencies = DEPENDENCY_GRAPH.get(capability_key, ())
        conflicts = CONFLICT_GRAPH.get(capability_key, ())
        missing_dependencies = [key for key in dependencies if state_by_key.get(key) not in ADMITTED_STATES]
        active_conflicts = [key for key in conflicts if posture.get(key, False)]
        dependency_ready = not missing_dependencies
        conflict_free = not active_conflicts
        if final_state in ADMITTED_STATES and (not dependency_ready or not conflict_free):
            item = dict(item)
            item["final_state"] = DEFERRED
            if missing_dependencies and active_conflicts:
                item["reason"] = "Capability is structurally admissible, but dependency and conflict graph are not satisfied."
            elif missing_dependencies:
                item["reason"] = "Capability is structurally admissible, but required capability dependencies are not admitted."
            else:
                item["reason"] = "Capability is structurally admissible, but active workload conflict requires safe deferral."
        item = dict(item)
        item["dependencies"] = list(dependencies)
        item["conflicts"] = list(conflicts)
        item["missing_dependencies"] = missing_dependencies
        item["active_conflicts"] = active_conflicts
        item["dependency_ready"] = dependency_ready
        item["conflict_free"] = conflict_free
        item["certificate"] = protection_certificate(item)
        updated.append(item)
    return updated



def apply_document_class_layer(surface: dict, document_class_key: str) -> dict:
    document_class = DOCUMENT_CLASSES[document_class_key]
    items = []
    for source_item in surface["items"]:
        item = dict(source_item)
        capability_key = item["capability_key"]
        state = item["final_state"]
        document_reason = None
        if state in ADMITTED_STATES:
            if capability_key in ("cloud_print", "remote_print_api") and not document_class["allow_remote_print"]:
                item["final_state"] = DEFERRED
                document_reason = "Document class requires local or separately admitted release before remote print visibility."
            elif capability_key == "scan_to_email" and not document_class["allow_scan_export"]:
                item["final_state"] = DEFERRED
                document_reason = "Document class defers scan export visibility until destination and release controls are separately admitted."
            elif capability_key == "fax_module" and not document_class["allow_fax_export"]:
                item["final_state"] = DEFERRED
                document_reason = "Document class defers fax export visibility under document movement restrictions."
            elif capability_key == "document_cache" and not document_class["allow_document_cache"]:
                item["final_state"] = FORBIDDEN
                document_reason = "Document cache visibility is refused by document class."
            elif capability_key == "secure_release" and document_class["require_secure_release"]:
                item["final_state"] = ISOLATED
                document_reason = "Document class requires secure release visibility to remain isolated."
            elif capability_key == "audit_logs" and document_class["require_audit"]:
                item["final_state"] = ISOLATED
                document_reason = "Document class requires audit visibility to remain isolated."
        if document_class["regulated"] and capability_key in ("cloud_print", "remote_print_api", "scan_to_email", "fax_module", "document_cache"):
            if item["final_state"] in ADMITTED_STATES:
                item["final_state"] = DEFERRED
                document_reason = "Regulated record class defers document movement visibility under records-grade restrictions."
        item["document_class"] = document_class_key
        item["document_class_description"] = document_class["description"]
        item["document_class_applied"] = document_reason is not None
        if document_reason is not None:
            item["reason"] = document_reason
        item["certificate"] = protection_certificate(item)
        items.append(item)
    states = (VISIBLE, ISOLATED, DORMANT, FORBIDDEN, BLOCKED, DEFERRED)
    updated = dict(surface)
    updated["document_class"] = document_class_key
    updated["document_class_description"] = document_class["description"]
    updated["items"] = items
    updated["counts"] = {state: sum(1 for item in items if item["final_state"] == state) for state in states}
    updated["visible_surface"] = [item["capability_key"] for item in items if item["final_state"] in ADMITTED_STATES]
    updated["deferred_surface"] = [item["capability_key"] for item in items if item["final_state"] == DEFERRED]
    updated["surface_certificate"] = protection_certificate(updated)
    return updated


def resolve_document_surface(scenario_key: str, profile_key: str, request_key: str, policy_key: str, document_class_key: str) -> dict:
    surface = resolve_policy_surface(scenario_key, profile_key, request_key, policy_key)
    if document_class_key == "public_document":
        surface["document_class"] = document_class_key
        surface["document_class_description"] = DOCUMENT_CLASSES[document_class_key]["description"]
        surface["surface_certificate"] = protection_certificate(surface)
        return surface
    return apply_document_class_layer(surface, document_class_key)


def apply_role_layer(surface: dict, role_key: str) -> dict:
    role = ROLE_PROFILES[role_key]
    items = []
    for source_item in surface["items"]:
        item = dict(source_item)
        capability_key = item["capability_key"]
        state = item["final_state"]
        role_reason = None
        if state in ADMITTED_STATES:
            if capability_key in ("cloud_print", "remote_print_api") and not role["allow_remote_print"]:
                item["final_state"] = DEFERRED
                role_reason = "Role does not admit remote document movement visibility."
            elif capability_key == "scan_to_email" and not role["allow_scan_export"]:
                item["final_state"] = DEFERRED
                role_reason = "Role does not admit outbound scan export visibility."
            elif capability_key == "fax_module" and not role["allow_fax_export"]:
                item["final_state"] = DEFERRED
                role_reason = "Role does not admit fax export visibility."
            elif capability_key == "document_cache" and not role["allow_document_cache"]:
                item["final_state"] = FORBIDDEN
                role_reason = "Role refuses document cache visibility."
            elif capability_key == "admin_console" and not role["allow_admin_console"]:
                item["final_state"] = DEFERRED
                role_reason = "Role does not admit administrative console visibility."
            elif capability_key == "firmware_update" and not role["allow_firmware_update"]:
                item["final_state"] = DEFERRED
                role_reason = "Role does not admit firmware update visibility."
            elif capability_key == "secure_release" and not role["allow_secure_release"]:
                item["final_state"] = DEFERRED
                role_reason = "Role does not admit secure release visibility."
            elif capability_key == "audit_logs" and not role["allow_audit_logs"]:
                item["final_state"] = DEFERRED
                role_reason = "Role does not admit audit log visibility."
        item["role"] = role_key
        item["role_description"] = role["description"]
        item["role_applied"] = role_reason is not None
        if role_reason is not None:
            item["reason"] = role_reason
        item["certificate"] = protection_certificate(item)
        items.append(item)
    states = (VISIBLE, ISOLATED, DORMANT, FORBIDDEN, BLOCKED, DEFERRED)
    updated = dict(surface)
    updated["role"] = role_key
    updated["role_description"] = role["description"]
    updated["items"] = items
    updated["counts"] = {state: sum(1 for item in items if item["final_state"] == state) for state in states}
    updated["visible_surface"] = [item["capability_key"] for item in items if item["final_state"] in ADMITTED_STATES]
    updated["deferred_surface"] = [item["capability_key"] for item in items if item["final_state"] == DEFERRED]
    updated["surface_certificate"] = protection_certificate(updated)
    return updated


def resolve_role_surface(scenario_key: str, profile_key: str, request_key: str, policy_key: str, document_class_key: str, role_key: str) -> dict:
    surface = resolve_document_surface(scenario_key, profile_key, request_key, policy_key, document_class_key)
    return apply_role_layer(surface, role_key)


def apply_context_layer(surface: dict, context_key: str) -> dict:
    context = CONTEXT_PROFILES[context_key]
    items = []
    for source_item in surface["items"]:
        item = dict(source_item)
        capability_key = item["capability_key"]
        state = item["final_state"]
        context_reason = None
        if state in ADMITTED_STATES:
            if capability_key in ("cloud_print", "remote_print_api") and not context["allow_remote_print"]:
                item["final_state"] = DEFERRED
                context_reason = "Context does not admit remote print visibility."
            elif capability_key == "scan_to_email" and not context["allow_scan_export"]:
                item["final_state"] = DEFERRED
                context_reason = "Context does not admit outbound scan export visibility."
            elif capability_key == "fax_module" and not context["allow_fax_export"]:
                item["final_state"] = DEFERRED
                context_reason = "Context does not admit fax export visibility."
            elif capability_key == "admin_console" and not context["allow_admin_console"]:
                item["final_state"] = DEFERRED
                context_reason = "Context does not admit administrative console visibility."
            elif capability_key == "firmware_update" and not context["allow_firmware_update"]:
                item["final_state"] = DEFERRED
                context_reason = "Context does not admit firmware update visibility."
            elif capability_key == "telemetry_export" and not context["allow_telemetry_export"]:
                item["final_state"] = DEFERRED
                context_reason = "Context does not admit telemetry export visibility."
            elif capability_key == "document_cache" and not context["allow_document_cache"]:
                item["final_state"] = FORBIDDEN
                context_reason = "Context refuses document cache visibility."
            elif capability_key in ("lan_print", "wifi_print") and not context["allow_local_network"]:
                item["final_state"] = DEFERRED
                context_reason = "Context does not admit local network print visibility."
            elif capability_key == "mobile_pairing" and not context["allow_mobile_pairing"]:
                item["final_state"] = DEFERRED
                context_reason = "Context does not admit mobile pairing visibility."
        item["context"] = context_key
        item["context_description"] = context["description"]
        item["context_applied"] = context_reason is not None
        if context_reason is not None:
            item["reason"] = context_reason
        item["certificate"] = protection_certificate(item)
        items.append(item)
    states = (VISIBLE, ISOLATED, DORMANT, FORBIDDEN, BLOCKED, DEFERRED)
    updated = dict(surface)
    updated["context"] = context_key
    updated["context_description"] = context["description"]
    updated["items"] = items
    updated["counts"] = {state: sum(1 for item in items if item["final_state"] == state) for state in states}
    updated["visible_surface"] = [item["capability_key"] for item in items if item["final_state"] in ADMITTED_STATES]
    updated["deferred_surface"] = [item["capability_key"] for item in items if item["final_state"] == DEFERRED]
    updated["surface_certificate"] = protection_certificate(updated)
    return updated


def resolve_context_surface(scenario_key: str, profile_key: str, request_key: str, policy_key: str, document_class_key: str, role_key: str, context_key: str) -> dict:
    surface = resolve_role_surface(scenario_key, profile_key, request_key, policy_key, document_class_key, role_key)
    return apply_context_layer(surface, context_key)


def context_audit(policy_key: str = "standard", document_class_key: str = "public_document", role_key: str = "employee", scenario_key: str = "remote_print", profile_key: str = "connected", request_key: str = "normal") -> dict:
    blocks = []
    for context_key in CONTEXT_ORDER:
        surface = resolve_context_surface(scenario_key, profile_key, request_key, policy_key, document_class_key, role_key, context_key)
        cloud_state = next(item for item in surface["items"] if item["capability_key"] == "cloud_print")["final_state"]
        remote_state = next(item for item in surface["items"] if item["capability_key"] == "remote_print_api")["final_state"]
        admin_state = next(item for item in surface["items"] if item["capability_key"] == "admin_console")["final_state"]
        firmware_state = next(item for item in surface["items"] if item["capability_key"] == "firmware_update")["final_state"]
        block = {
            "context": context_key,
            "description": CONTEXT_PROFILES[context_key]["description"],
            "surface_certificate": surface["surface_certificate"],
            "visible_surface": surface["visible_surface"],
            "deferred_surface": surface["deferred_surface"],
            "cloud_print": cloud_state,
            "remote_print_api": remote_state,
            "admin_console": admin_state,
            "firmware_update": firmware_state,
        }
        block["context_certificate"] = protection_certificate(block)
        blocks.append(block)
    signatures = {block["context"]: (tuple(block["visible_surface"]), tuple(block["deferred_surface"])) for block in blocks}
    states = {block["context"]: (block["cloud_print"], block["remote_print_api"]) for block in blocks}
    checks = {
        "context_changes_visibility_outcome": len(set(signatures.values())) > 1,
        "trusted_office_admits_cloud_print": states["trusted_office_device"][0] == ISOLATED,
        "remote_employee_admits_cloud_print": states["remote_employee_laptop"][0] == ISOLATED,
        "untrusted_network_defers_cloud_print": states["untrusted_network"][0] == DEFERRED,
        "shared_floor_defers_cloud_print": states["shared_floor_terminal"][0] == DEFERRED,
    }
    payload = {
        "project": PROJECT_NAME,
        "version": VERSION,
        "result": "PASS" if all(checks.values()) else "FAIL",
        "scenario": scenario_key,
        "profile": profile_key,
        "request": request_key,
        "policy": policy_key,
        "document_class": document_class_key,
        "role": role_key,
        "context_count": len(CONTEXT_ORDER),
        "checks": checks,
        "blocks": blocks,
    }
    payload["context_audit_certificate"] = protection_certificate(payload)
    return payload



def apply_approval_layer(surface: dict, approval_key: str) -> dict:
    approval = APPROVAL_PROFILES[approval_key]
    items = []
    for source_item in surface["items"]:
        item = dict(source_item)
        capability_key = item["capability_key"]
        state = item["final_state"]
        approval_reason = None
        if state in ADMITTED_STATES:
            if capability_key in ("cloud_print", "remote_print_api") and not approval["allow_remote_print"]:
                item["final_state"] = DEFERRED
                approval_reason = "Approval chain does not admit remote print visibility."
            elif capability_key == "scan_to_email" and not approval["allow_scan_export"]:
                item["final_state"] = DEFERRED
                approval_reason = "Approval chain does not admit outbound scan export visibility."
            elif capability_key == "fax_module" and not approval["allow_fax_export"]:
                item["final_state"] = DEFERRED
                approval_reason = "Approval chain does not admit fax export visibility."
            elif capability_key == "admin_console" and not approval["allow_admin_console"]:
                item["final_state"] = DEFERRED
                approval_reason = "Approval chain does not admit administrative console visibility."
            elif capability_key == "firmware_update" and not approval["allow_firmware_update"]:
                item["final_state"] = DEFERRED
                approval_reason = "Approval chain does not admit firmware update visibility."
            elif capability_key == "telemetry_export" and not approval["allow_telemetry_export"]:
                item["final_state"] = DEFERRED
                approval_reason = "Approval chain does not admit telemetry export visibility."
            elif capability_key == "document_cache" and not approval["allow_document_cache"]:
                item["final_state"] = FORBIDDEN
                approval_reason = "Approval chain refuses document cache visibility."
            elif capability_key == "secure_release" and not approval["allow_secure_release"]:
                item["final_state"] = DEFERRED
                approval_reason = "Approval chain does not admit secure release visibility."
            elif capability_key == "audit_logs" and not approval["allow_audit_logs"]:
                item["final_state"] = DEFERRED
                approval_reason = "Approval chain does not admit audit log visibility."
        item["approval"] = approval_key
        item["approval_description"] = approval["description"]
        item["approval_applied"] = approval_reason is not None
        if approval_reason is not None:
            item["reason"] = approval_reason
        item["certificate"] = protection_certificate(item)
        items.append(item)
    states = (VISIBLE, ISOLATED, DORMANT, FORBIDDEN, BLOCKED, DEFERRED)
    updated = dict(surface)
    updated["approval"] = approval_key
    updated["approval_description"] = approval["description"]
    updated["items"] = items
    updated["counts"] = {state: sum(1 for item in items if item["final_state"] == state) for state in states}
    updated["visible_surface"] = [item["capability_key"] for item in items if item["final_state"] in ADMITTED_STATES]
    updated["deferred_surface"] = [item["capability_key"] for item in items if item["final_state"] == DEFERRED]
    updated["surface_certificate"] = protection_certificate(updated)
    return updated


def resolve_approval_surface(scenario_key: str, profile_key: str, request_key: str, policy_key: str, document_class_key: str, role_key: str, context_key: str, approval_key: str) -> dict:
    surface = resolve_context_surface(scenario_key, profile_key, request_key, policy_key, document_class_key, role_key, context_key)
    return apply_approval_layer(surface, approval_key)


def approval_audit(policy_key: str = "standard", document_class_key: str = "public_document", role_key: str = "employee", context_key: str = "trusted_office_device", scenario_key: str = "remote_print", profile_key: str = "connected", request_key: str = "normal") -> dict:
    blocks = []
    for approval_key in APPROVAL_ORDER:
        surface = resolve_approval_surface(scenario_key, profile_key, request_key, policy_key, document_class_key, role_key, context_key, approval_key)
        cloud_state = next(item for item in surface["items"] if item["capability_key"] == "cloud_print")["final_state"]
        remote_state = next(item for item in surface["items"] if item["capability_key"] == "remote_print_api")["final_state"]
        admin_state = next(item for item in surface["items"] if item["capability_key"] == "admin_console")["final_state"]
        firmware_state = next(item for item in surface["items"] if item["capability_key"] == "firmware_update")["final_state"]
        block = {
            "approval": approval_key,
            "description": APPROVAL_PROFILES[approval_key]["description"],
            "surface_certificate": surface["surface_certificate"],
            "visible_surface": surface["visible_surface"],
            "deferred_surface": surface["deferred_surface"],
            "cloud_print": cloud_state,
            "remote_print_api": remote_state,
            "admin_console": admin_state,
            "firmware_update": firmware_state,
        }
        block["approval_certificate"] = protection_certificate(block)
        blocks.append(block)
    signatures = {block["approval"]: (tuple(block["visible_surface"]), tuple(block["deferred_surface"])) for block in blocks}
    states = {block["approval"]: (block["cloud_print"], block["remote_print_api"], block["firmware_update"]) for block in blocks}
    checks = {
        "approval_changes_visibility_outcome": len(set(signatures.values())) > 1,
        "no_approval_defers_cloud_print": states["no_approval"][0] == DEFERRED,
        "manager_approval_admits_cloud_print": states["manager_approved"][0] == ISOLATED,
        "security_approval_admits_cloud_print": states["security_approved"][0] == ISOLATED,
        "records_approval_defers_cloud_print": states["records_approved"][0] == DEFERRED,
    }
    payload = {
        "project": PROJECT_NAME,
        "version": VERSION,
        "result": "PASS" if all(checks.values()) else "FAIL",
        "scenario": scenario_key,
        "profile": profile_key,
        "request": request_key,
        "policy": policy_key,
        "document_class": document_class_key,
        "role": role_key,
        "context": context_key,
        "approval_count": len(APPROVAL_ORDER),
        "checks": checks,
        "blocks": blocks,
    }
    payload["approval_audit_certificate"] = protection_certificate(payload)
    return payload

def apply_release_mode_layer(surface: dict, release_mode_key: str, scenario_key: str) -> dict:
    release_mode = RELEASE_MODES[release_mode_key]
    items = []
    for source_item in surface["items"]:
        item = dict(source_item)
        capability_key = item["capability_key"]
        state = item["final_state"]
        release_reason = None
        if state in ADMITTED_STATES:
            if capability_key in ("cloud_print", "remote_print_api") and not release_mode["allow_remote_print"]:
                item["final_state"] = DEFERRED
                release_reason = "Release mode does not admit remote document movement visibility."
            elif capability_key in ("print_engine", "paper_feed", "ink_toner_system") and not release_mode["allow_physical_output"]:
                item["final_state"] = DEFERRED
                release_reason = "Release mode quarantines physical output until separate clearance."
            elif capability_key == "secure_release" and not release_mode["allow_secure_release"] and scenario_key in ("secure_print", "remote_print"):
                item["final_state"] = DEFERRED
                release_reason = "Release mode does not admit secure local release visibility."
            elif capability_key == "audit_logs" and not release_mode["allow_audit_logs"]:
                item["final_state"] = DEFERRED
                release_reason = "Release mode does not admit release audit visibility."
        if capability_key == "secure_release" and release_mode["allow_secure_release"] and scenario_key in ("remote_print", "secure_print"):
            if item["final_state"] in (FORBIDDEN, DEFERRED, DORMANT, BLOCKED):
                item["final_state"] = ISOLATED
                release_reason = "Release mode admits secure local release visibility for final document output."
        item["release_mode"] = release_mode_key
        item["release_mode_description"] = release_mode["description"]
        item["release_mode_applied"] = release_reason is not None
        if release_reason is not None:
            item["reason"] = release_reason
        item["certificate"] = protection_certificate(item)
        items.append(item)
    state_by_key = {item["capability_key"]: item["final_state"] for item in items}
    posture = STRUCTURAL_POSTURE.get(scenario_key, {})
    final_items = []
    for source_item in items:
        item = dict(source_item)
        capability_key = item["capability_key"]
        if capability_key == "remote_print_api" and release_mode["allow_remote_print"]:
            dependencies = DEPENDENCY_GRAPH.get(capability_key, ())
            conflicts = CONFLICT_GRAPH.get(capability_key, ())
            missing_dependencies = [key for key in dependencies if state_by_key.get(key) not in ADMITTED_STATES]
            active_conflicts = [key for key in conflicts if posture.get(key, False)]
            if item.get("raw_state") in ADMITTED_STATES and not missing_dependencies and not active_conflicts:
                item["final_state"] = ISOLATED
                item["reason"] = "Release mode admits remote print API after required release dependencies are satisfied."
                item["missing_dependencies"] = []
                item["active_conflicts"] = []
                item["dependency_ready"] = True
                item["conflict_free"] = True
        item["certificate"] = protection_certificate(item)
        final_items.append(item)
    states = (VISIBLE, ISOLATED, DORMANT, FORBIDDEN, BLOCKED, DEFERRED)
    updated = dict(surface)
    updated["release_mode"] = release_mode_key
    updated["release_mode_description"] = release_mode["description"]
    updated["items"] = final_items
    updated["counts"] = {state: sum(1 for item in final_items if item["final_state"] == state) for state in states}
    updated["visible_surface"] = [item["capability_key"] for item in final_items if item["final_state"] in ADMITTED_STATES]
    updated["deferred_surface"] = [item["capability_key"] for item in final_items if item["final_state"] == DEFERRED]
    updated["surface_certificate"] = protection_certificate(updated)
    return updated


def resolve_release_surface(scenario_key: str, profile_key: str, request_key: str, policy_key: str, document_class_key: str, role_key: str, context_key: str, approval_key: str, release_mode_key: str) -> dict:
    surface = resolve_approval_surface(scenario_key, profile_key, request_key, policy_key, document_class_key, role_key, context_key, approval_key)
    return apply_release_mode_layer(surface, release_mode_key, scenario_key)


def release_mode_audit(policy_key: str = "standard", document_class_key: str = "public_document", role_key: str = "employee", context_key: str = "trusted_office_device", approval_key: str = "manager_approved", scenario_key: str = "remote_print", profile_key: str = "connected", request_key: str = "normal") -> dict:
    blocks = []
    for release_mode_key in RELEASE_MODE_ORDER:
        surface = resolve_release_surface(scenario_key, profile_key, request_key, policy_key, document_class_key, role_key, context_key, approval_key, release_mode_key)
        cloud_state = next(item for item in surface["items"] if item["capability_key"] == "cloud_print")["final_state"]
        remote_state = next(item for item in surface["items"] if item["capability_key"] == "remote_print_api")["final_state"]
        secure_state = next(item for item in surface["items"] if item["capability_key"] == "secure_release")["final_state"]
        print_state = next(item for item in surface["items"] if item["capability_key"] == "print_engine")["final_state"]
        block = {
            "release_mode": release_mode_key,
            "description": RELEASE_MODES[release_mode_key]["description"],
            "surface_certificate": surface["surface_certificate"],
            "visible_surface": surface["visible_surface"],
            "deferred_surface": surface["deferred_surface"],
            "cloud_print": cloud_state,
            "remote_print_api": remote_state,
            "secure_release": secure_state,
            "print_engine": print_state,
        }
        block["release_mode_certificate"] = protection_certificate(block)
        blocks.append(block)
    signatures = {block["release_mode"]: (tuple(block["visible_surface"]), tuple(block["deferred_surface"])) for block in blocks}
    states = {block["release_mode"]: (block["cloud_print"], block["remote_print_api"], block["secure_release"], block["print_engine"]) for block in blocks}
    checks = {
        "release_mode_changes_visibility_outcome": len(set(signatures.values())) > 1,
        "immediate_print_does_not_admit_secure_release": states["immediate_print"][2] != ISOLATED,
        "secure_pull_release_admits_secure_release": states["secure_pull_release"][2] == ISOLATED,
        "badge_release_admits_remote_api_after_release": states["badge_release"][1] == ISOLATED,
        "records_release_defers_remote_movement": states["records_release"][0] == DEFERRED,
        "quarantine_release_defers_physical_output": states["quarantine_release"][3] == DEFERRED,
    }
    payload = {
        "project": PROJECT_NAME,
        "version": VERSION,
        "result": "PASS" if all(checks.values()) else "FAIL",
        "scenario": scenario_key,
        "profile": profile_key,
        "request": request_key,
        "policy": policy_key,
        "document_class": document_class_key,
        "role": role_key,
        "context": context_key,
        "approval": approval_key,
        "release_mode_count": len(RELEASE_MODE_ORDER),
        "checks": checks,
        "blocks": blocks,
    }
    payload["release_mode_audit_certificate"] = protection_certificate(payload)
    return payload



def apply_actor_layer(surface: dict, actor_key: str, scenario_key: str, release_mode_key: str) -> dict:
    actor = ACTOR_PROFILES[actor_key]
    items = []
    for source_item in surface["items"]:
        item = dict(source_item)
        capability_key = item["capability_key"]
        state = item["final_state"]
        actor_reason = None
        if state in ADMITTED_STATES:
            if capability_key in ("cloud_print", "remote_print_api") and not actor["allow_submit"]:
                item["final_state"] = DEFERRED
                actor_reason = "Actor responsibility does not admit job submission or remote movement visibility."
            elif capability_key in ("print_engine", "paper_feed", "ink_toner_system") and not actor["allow_release"] and release_mode_key in ("secure_pull_release", "badge_release", "records_release"):
                item["final_state"] = DEFERRED
                actor_reason = "Actor responsibility does not admit final physical output visibility."
            elif capability_key == "secure_release" and not actor["allow_release"]:
                item["final_state"] = DEFERRED
                actor_reason = "Actor responsibility does not admit secure release visibility."
            elif capability_key == "audit_logs" and not actor["allow_audit_review"]:
                item["final_state"] = DEFERRED
                actor_reason = "Actor responsibility does not admit audit review visibility."
            elif capability_key == "document_cache" and not actor["allow_document_cache"]:
                item["final_state"] = FORBIDDEN
                actor_reason = "Actor responsibility refuses document cache visibility."
            elif capability_key == "admin_console" and not actor["allow_admin_console"]:
                item["final_state"] = DEFERRED
                actor_reason = "Actor responsibility does not admit administrative console visibility."
            elif capability_key == "firmware_update" and not actor["allow_firmware_update"]:
                item["final_state"] = DEFERRED
                actor_reason = "Actor responsibility does not admit firmware update visibility."
        if capability_key == "audit_logs" and actor["allow_audit_review"] and scenario_key in ("remote_print", "secure_print", "maintenance", "managed_service"):
            if item["final_state"] in (FORBIDDEN, DORMANT, DEFERRED, BLOCKED):
                item["final_state"] = ISOLATED
                actor_reason = "Actor responsibility admits bounded audit review visibility."
        if capability_key == "secure_release" and actor["allow_release"] and release_mode_key in ("secure_pull_release", "badge_release", "records_release"):
            if item["final_state"] in (FORBIDDEN, DORMANT, DEFERRED, BLOCKED):
                item["final_state"] = ISOLATED
                actor_reason = "Actor responsibility admits local release visibility for already admitted jobs."
        if capability_key in ("admin_console", "firmware_update") and actor["allow_service_operations"] and scenario_key in ("maintenance", "firmware_update", "maintenance_with_jobs", "maintenance_after_jobs_clear", "managed_service"):
            if item["final_state"] in (FORBIDDEN, DORMANT, DEFERRED, BLOCKED):
                item["final_state"] = ISOLATED
                actor_reason = "Actor responsibility admits bounded service operation visibility."
        item["actor"] = actor_key
        item["actor_description"] = actor["description"]
        item["actor_applied"] = actor_reason is not None
        if actor_reason is not None:
            item["reason"] = actor_reason
        item["certificate"] = protection_certificate(item)
        items.append(item)
    states = (VISIBLE, ISOLATED, DORMANT, FORBIDDEN, BLOCKED, DEFERRED)
    updated = dict(surface)
    updated["actor"] = actor_key
    updated["actor_description"] = actor["description"]
    updated["items"] = items
    updated["counts"] = {state: sum(1 for item in items if item["final_state"] == state) for state in states}
    updated["visible_surface"] = [item["capability_key"] for item in items if item["final_state"] in ADMITTED_STATES]
    updated["deferred_surface"] = [item["capability_key"] for item in items if item["final_state"] == DEFERRED]
    updated["surface_certificate"] = protection_certificate(updated)
    return updated


def resolve_actor_surface(scenario_key: str, profile_key: str, request_key: str, policy_key: str, document_class_key: str, role_key: str, context_key: str, approval_key: str, release_mode_key: str, actor_key: str) -> dict:
    surface = resolve_release_surface(scenario_key, profile_key, request_key, policy_key, document_class_key, role_key, context_key, approval_key, release_mode_key)
    return apply_actor_layer(surface, actor_key, scenario_key, release_mode_key)


def actor_audit(policy_key: str = "standard", document_class_key: str = "public_document", role_key: str = "employee", context_key: str = "trusted_office_device", approval_key: str = "manager_approved", release_mode_key: str = "secure_pull_release", scenario_key: str = "remote_print", profile_key: str = "connected", request_key: str = "normal") -> dict:
    blocks = []
    for actor_key in ACTOR_ORDER:
        surface = resolve_actor_surface(scenario_key, profile_key, request_key, policy_key, document_class_key, role_key, context_key, approval_key, release_mode_key, actor_key)
        cloud_state = next(item for item in surface["items"] if item["capability_key"] == "cloud_print")["final_state"]
        remote_state = next(item for item in surface["items"] if item["capability_key"] == "remote_print_api")["final_state"]
        secure_state = next(item for item in surface["items"] if item["capability_key"] == "secure_release")["final_state"]
        print_state = next(item for item in surface["items"] if item["capability_key"] == "print_engine")["final_state"]
        audit_state = next(item for item in surface["items"] if item["capability_key"] == "audit_logs")["final_state"]
        block = {
            "actor": actor_key,
            "description": ACTOR_PROFILES[actor_key]["description"],
            "surface_certificate": surface["surface_certificate"],
            "visible_surface": surface["visible_surface"],
            "deferred_surface": surface["deferred_surface"],
            "cloud_print": cloud_state,
            "remote_print_api": remote_state,
            "secure_release": secure_state,
            "print_engine": print_state,
            "audit_logs": audit_state,
        }
        block["actor_certificate"] = protection_certificate(block)
        blocks.append(block)
    signatures = {block["actor"]: (tuple(block["visible_surface"]), tuple(block["deferred_surface"])) for block in blocks}
    states = {block["actor"]: (block["cloud_print"], block["remote_print_api"], block["secure_release"], block["print_engine"], block["audit_logs"]) for block in blocks}
    checks = {
        "actor_changes_visibility_outcome": len(set(signatures.values())) > 1,
        "requester_admits_submission": states["requester"][0] == ISOLATED,
        "requester_defers_release": states["requester"][2] == DEFERRED,
        "release_operator_admits_secure_release": states["release_operator"][2] == ISOLATED,
        "release_operator_defers_remote_api": states["release_operator"][1] == DEFERRED,
        "auditor_admits_audit_logs": states["auditor"][4] == ISOLATED,
    }
    payload = {
        "project": PROJECT_NAME,
        "version": VERSION,
        "result": "PASS" if all(checks.values()) else "FAIL",
        "scenario": scenario_key,
        "profile": profile_key,
        "request": request_key,
        "policy": policy_key,
        "document_class": document_class_key,
        "role": role_key,
        "context": context_key,
        "approval": approval_key,
        "release_mode": release_mode_key,
        "actor_count": len(ACTOR_ORDER),
        "checks": checks,
        "blocks": blocks,
    }
    payload["actor_audit_certificate"] = protection_certificate(payload)
    return payload


def apply_job_state_layer(surface: dict, job_state_key: str, actor_key: str) -> dict:
    job_state = JOB_STATES[job_state_key]
    items = []
    for source_item in surface["items"]:
        item = dict(source_item)
        capability_key = item["capability_key"]
        state = item["final_state"]
        job_reason = None
        if capability_key in ("cloud_print", "remote_print_api"):
            if job_state_key in ("draft_job", "held_job", "released_job", "completed_job", "cancelled_job", "quarantined_job") and state in ADMITTED_STATES:
                item["final_state"] = DEFERRED if job_state_key not in ("completed_job", "cancelled_job") else FORBIDDEN
                job_reason = "Job state does not admit active remote movement visibility."
        if capability_key in ("print_engine", "paper_feed", "ink_toner_system"):
            if job_state_key in ("draft_job", "submitted_job", "held_job", "quarantined_job") and state in ADMITTED_STATES:
                item["final_state"] = DEFERRED
                job_reason = "Job state does not admit final physical output visibility."
            elif job_state_key == "released_job" and state in (DEFERRED, DORMANT, FORBIDDEN, BLOCKED) and actor_key in ("release_operator", "records_operator"):
                item["final_state"] = VISIBLE
                job_reason = "Job state admits physical output visibility after release structure is satisfied."
            elif job_state_key == "completed_job" and state in ADMITTED_STATES:
                item["final_state"] = DORMANT
                job_reason = "Job is completed; active physical output visibility is closed."
            elif job_state_key == "cancelled_job" and state in ADMITTED_STATES:
                item["final_state"] = FORBIDDEN
                job_reason = "Job is cancelled; physical output visibility is not admitted."
        if capability_key == "secure_release":
            if job_state_key in ("draft_job", "submitted_job", "completed_job", "cancelled_job", "quarantined_job") and state in ADMITTED_STATES:
                item["final_state"] = DEFERRED if job_state_key not in ("completed_job", "cancelled_job") else FORBIDDEN
                job_reason = "Job state does not admit active release visibility."
            elif job_state_key in ("held_job", "released_job") and state in (DEFERRED, DORMANT, FORBIDDEN, BLOCKED) and actor_key in ("release_operator", "records_operator"):
                item["final_state"] = ISOLATED
                job_reason = "Job state admits local release visibility."
        if capability_key == "job_queue":
            if job_state_key in ("draft_job", "completed_job", "cancelled_job") and state in ADMITTED_STATES:
                item["final_state"] = ISOLATED
                job_reason = "Job state admits bounded queue evidence visibility."
            elif job_state_key == "quarantined_job" and state in (VISIBLE, ISOLATED, DORMANT, FORBIDDEN, BLOCKED, DEFERRED):
                item["final_state"] = ISOLATED
                job_reason = "Quarantined job keeps bounded queue evidence visible."
        if capability_key == "audit_logs":
            if job_state_key in ("completed_job", "cancelled_job", "quarantined_job") and state in (FORBIDDEN, DORMANT, DEFERRED, BLOCKED):
                item["final_state"] = ISOLATED
                job_reason = "Job state admits bounded audit evidence visibility."
        item["job_state"] = job_state_key
        item["job_state_description"] = job_state["description"]
        item["job_state_applied"] = job_reason is not None
        if job_reason is not None:
            item["reason"] = job_reason
        item["certificate"] = protection_certificate(item)
        items.append(item)
    states = (VISIBLE, ISOLATED, DORMANT, FORBIDDEN, BLOCKED, DEFERRED)
    updated = dict(surface)
    updated["job_state"] = job_state_key
    updated["job_state_description"] = job_state["description"]
    updated["items"] = items
    updated["counts"] = {state: sum(1 for item in items if item["final_state"] == state) for state in states}
    updated["visible_surface"] = [item["capability_key"] for item in items if item["final_state"] in ADMITTED_STATES]
    updated["deferred_surface"] = [item["capability_key"] for item in items if item["final_state"] == DEFERRED]
    updated["surface_certificate"] = protection_certificate(updated)
    return updated


def resolve_job_state_surface(scenario_key: str, profile_key: str, request_key: str, policy_key: str, document_class_key: str, role_key: str, context_key: str, approval_key: str, release_mode_key: str, actor_key: str, job_state_key: str) -> dict:
    surface = resolve_actor_surface(scenario_key, profile_key, request_key, policy_key, document_class_key, role_key, context_key, approval_key, release_mode_key, actor_key)
    return apply_job_state_layer(surface, job_state_key, actor_key)


def job_state_audit(policy_key: str = "standard", document_class_key: str = "public_document", role_key: str = "employee", context_key: str = "trusted_office_device", approval_key: str = "manager_approved", release_mode_key: str = "secure_pull_release", actor_key: str = "release_operator", scenario_key: str = "remote_print", profile_key: str = "connected", request_key: str = "normal") -> dict:
    blocks = []
    for job_state_key in JOB_STATE_ORDER:
        surface = resolve_job_state_surface(scenario_key, profile_key, request_key, policy_key, document_class_key, role_key, context_key, approval_key, release_mode_key, actor_key, job_state_key)
        cloud_state = next(item for item in surface["items"] if item["capability_key"] == "cloud_print")["final_state"]
        remote_state = next(item for item in surface["items"] if item["capability_key"] == "remote_print_api")["final_state"]
        secure_state = next(item for item in surface["items"] if item["capability_key"] == "secure_release")["final_state"]
        print_state = next(item for item in surface["items"] if item["capability_key"] == "print_engine")["final_state"]
        queue_state = next(item for item in surface["items"] if item["capability_key"] == "job_queue")["final_state"]
        audit_state = next(item for item in surface["items"] if item["capability_key"] == "audit_logs")["final_state"]
        block = {
            "job_state": job_state_key,
            "description": JOB_STATES[job_state_key]["description"],
            "surface_certificate": surface["surface_certificate"],
            "visible_surface": surface["visible_surface"],
            "deferred_surface": surface["deferred_surface"],
            "cloud_print": cloud_state,
            "remote_print_api": remote_state,
            "secure_release": secure_state,
            "print_engine": print_state,
            "job_queue": queue_state,
            "audit_logs": audit_state,
        }
        block["job_state_certificate"] = protection_certificate(block)
        blocks.append(block)
    signatures = {block["job_state"]: (tuple(block["visible_surface"]), tuple(block["deferred_surface"])) for block in blocks}
    states = {block["job_state"]: (block["cloud_print"], block["remote_print_api"], block["secure_release"], block["print_engine"], block["job_queue"], block["audit_logs"]) for block in blocks}
    checks = {
        "job_state_changes_visibility_outcome": len(set(signatures.values())) > 1,
        "draft_job_defers_output": states["draft_job"][3] == DEFERRED,
        "held_job_admits_release_control": states["held_job"][2] == ISOLATED,
        "released_job_admits_physical_output": states["released_job"][3] == VISIBLE,
        "completed_job_closes_active_output": states["completed_job"][3] == DORMANT,
        "cancelled_job_refuses_physical_output": states["cancelled_job"][3] == FORBIDDEN,
        "quarantined_job_admits_audit_evidence": states["quarantined_job"][5] == ISOLATED,
    }
    payload = {
        "project": PROJECT_NAME,
        "version": VERSION,
        "result": "PASS" if all(checks.values()) else "FAIL",
        "scenario": scenario_key,
        "profile": profile_key,
        "request": request_key,
        "policy": policy_key,
        "document_class": document_class_key,
        "role": role_key,
        "context": context_key,
        "approval": approval_key,
        "release_mode": release_mode_key,
        "actor": actor_key,
        "job_state_count": len(JOB_STATE_ORDER),
        "checks": checks,
        "blocks": blocks,
    }
    payload["job_state_audit_certificate"] = protection_certificate(payload)
    return payload



def apply_retention_state_layer(surface: dict, retention_state_key: str) -> dict:
    retention_state = RETENTION_STATES[retention_state_key]
    items = []
    for source_item in surface["items"]:
        item = dict(source_item)
        capability_key = item["capability_key"]
        state = item["final_state"]
        retention_reason = None
        if capability_key == "document_cache":
            if retention_state_key == "legal_hold_retention":
                item["final_state"] = ISOLATED
                retention_reason = "Retention state admits isolated document cache evidence under hold structure."
            elif retention_state_key in ("records_retention", "audit_retention", "short_spool_retention", "no_retention"):
                if state in ADMITTED_STATES:
                    item["final_state"] = FORBIDDEN
                    retention_reason = "Retention state does not admit document cache visibility."
        if capability_key == "audit_logs":
            if retention_state_key in ("audit_retention", "records_retention", "legal_hold_retention") and state in (FORBIDDEN, DORMANT, DEFERRED, BLOCKED):
                item["final_state"] = ISOLATED
                retention_reason = "Retention state admits bounded audit evidence visibility."
            elif retention_state_key == "no_retention" and state in ADMITTED_STATES:
                item["final_state"] = FORBIDDEN
                retention_reason = "Retention state closes audit evidence visibility."
        if capability_key == "job_queue":
            if retention_state_key in ("short_spool_retention", "audit_retention", "records_retention", "legal_hold_retention") and state in (VISIBLE, ISOLATED, DORMANT, FORBIDDEN, BLOCKED, DEFERRED):
                item["final_state"] = ISOLATED
                retention_reason = "Retention state admits bounded queue evidence visibility."
            elif retention_state_key == "no_retention" and state in ADMITTED_STATES:
                item["final_state"] = DORMANT
                retention_reason = "Retention state closes active queue evidence visibility."
        if capability_key in ("print_engine", "paper_feed", "ink_toner_system", "cloud_print", "remote_print_api", "scan_to_email", "fax_module"):
            if retention_state_key == "legal_hold_retention" and state in ADMITTED_STATES:
                item["final_state"] = DEFERRED
                retention_reason = "Retention state defers movement and output while hold evidence is preserved."
        item["retention_state"] = retention_state_key
        item["retention_state_description"] = retention_state["description"]
        item["retention_state_applied"] = retention_reason is not None
        if retention_reason is not None:
            item["reason"] = retention_reason
        item["certificate"] = protection_certificate(item)
        items.append(item)
    states = (VISIBLE, ISOLATED, DORMANT, FORBIDDEN, BLOCKED, DEFERRED)
    updated = dict(surface)
    updated["retention_state"] = retention_state_key
    updated["retention_state_description"] = retention_state["description"]
    updated["items"] = items
    updated["counts"] = {state: sum(1 for item in items if item["final_state"] == state) for state in states}
    updated["visible_surface"] = [item["capability_key"] for item in items if item["final_state"] in ADMITTED_STATES]
    updated["deferred_surface"] = [item["capability_key"] for item in items if item["final_state"] == DEFERRED]
    updated["surface_certificate"] = protection_certificate(updated)
    return updated


def resolve_retention_state_surface(scenario_key: str, profile_key: str, request_key: str, policy_key: str, document_class_key: str, role_key: str, context_key: str, approval_key: str, release_mode_key: str, actor_key: str, job_state_key: str, retention_state_key: str) -> dict:
    surface = resolve_job_state_surface(scenario_key, profile_key, request_key, policy_key, document_class_key, role_key, context_key, approval_key, release_mode_key, actor_key, job_state_key)
    return apply_retention_state_layer(surface, retention_state_key)


def retention_state_audit(policy_key: str = "standard", document_class_key: str = "public_document", role_key: str = "employee", context_key: str = "trusted_office_device", approval_key: str = "manager_approved", release_mode_key: str = "secure_pull_release", actor_key: str = "release_operator", job_state_key: str = "completed_job", scenario_key: str = "remote_print", profile_key: str = "connected", request_key: str = "normal") -> dict:
    blocks = []
    for retention_state_key in RETENTION_STATE_ORDER:
        surface = resolve_retention_state_surface(scenario_key, profile_key, request_key, policy_key, document_class_key, role_key, context_key, approval_key, release_mode_key, actor_key, job_state_key, retention_state_key)
        queue_state = next(item for item in surface["items"] if item["capability_key"] == "job_queue")["final_state"]
        audit_state = next(item for item in surface["items"] if item["capability_key"] == "audit_logs")["final_state"]
        cache_state = next(item for item in surface["items"] if item["capability_key"] == "document_cache")["final_state"]
        print_state = next(item for item in surface["items"] if item["capability_key"] == "print_engine")["final_state"]
        cloud_state = next(item for item in surface["items"] if item["capability_key"] == "cloud_print")["final_state"]
        block = {
            "retention_state": retention_state_key,
            "description": RETENTION_STATES[retention_state_key]["description"],
            "surface_certificate": surface["surface_certificate"],
            "visible_surface": surface["visible_surface"],
            "deferred_surface": surface["deferred_surface"],
            "job_queue": queue_state,
            "audit_logs": audit_state,
            "document_cache": cache_state,
            "print_engine": print_state,
            "cloud_print": cloud_state,
        }
        block["retention_state_certificate"] = protection_certificate(block)
        blocks.append(block)
    signatures = {block["retention_state"]: (tuple(block["visible_surface"]), tuple(block["deferred_surface"])) for block in blocks}
    states = {block["retention_state"]: (block["job_queue"], block["audit_logs"], block["document_cache"], block["print_engine"], block["cloud_print"]) for block in blocks}
    checks = {
        "retention_state_changes_visibility_outcome": len(set(signatures.values())) > 1,
        "no_retention_closes_queue_evidence": states["no_retention"][0] == DORMANT,
        "short_spool_retention_admits_queue_evidence": states["short_spool_retention"][0] == ISOLATED,
        "audit_retention_admits_audit_evidence": states["audit_retention"][1] == ISOLATED,
        "records_retention_admits_queue_and_audit_evidence": states["records_retention"][0] == ISOLATED and states["records_retention"][1] == ISOLATED,
        "legal_hold_retention_admits_cache_evidence": states["legal_hold_retention"][2] == ISOLATED,
        "legal_hold_retention_defers_movement": states["legal_hold_retention"][4] == DEFERRED,
    }
    payload = {
        "project": PROJECT_NAME,
        "version": VERSION,
        "result": "PASS" if all(checks.values()) else "FAIL",
        "scenario": scenario_key,
        "profile": profile_key,
        "request": request_key,
        "policy": policy_key,
        "document_class": document_class_key,
        "role": role_key,
        "context": context_key,
        "approval": approval_key,
        "release_mode": release_mode_key,
        "actor": actor_key,
        "job_state": job_state_key,
        "retention_state_count": len(RETENTION_STATE_ORDER),
        "checks": checks,
        "blocks": blocks,
    }
    payload["retention_state_audit_certificate"] = protection_certificate(payload)
    return payload

def apply_data_destination_layer(surface: dict, data_destination_key: str) -> dict:
    data_destination = DATA_DESTINATIONS[data_destination_key]
    items = []
    for source_item in surface["items"]:
        item = dict(source_item)
        capability_key = item["capability_key"]
        state = item["final_state"]
        destination_reason = None
        if data_destination_key == "local_printer_only":
            if capability_key in ("cloud_print", "remote_print_api", "scan_to_email", "fax_module") and state in ADMITTED_STATES:
                item["final_state"] = DEFERRED
                destination_reason = "Destination structure keeps document movement local."
            if capability_key == "secure_release" and state in (FORBIDDEN, DORMANT, DEFERRED, BLOCKED):
                item["final_state"] = ISOLATED
                destination_reason = "Destination structure admits local release visibility."
        elif data_destination_key == "department_queue":
            if capability_key in ("cloud_print", "remote_print_api") and state in ADMITTED_STATES:
                item["final_state"] = ISOLATED
                destination_reason = "Destination structure admits bounded departmental routing visibility."
            if capability_key in ("scan_to_email", "fax_module") and state in ADMITTED_STATES:
                item["final_state"] = DEFERRED
                destination_reason = "Destination structure does not admit outbound document export."
        elif data_destination_key == "approved_email_domain":
            if capability_key == "scan_to_email" and state in (FORBIDDEN, DORMANT, DEFERRED, BLOCKED):
                item["final_state"] = ISOLATED
                destination_reason = "Destination structure admits bounded approved-domain scan export visibility."
            if capability_key == "audit_logs" and state in (FORBIDDEN, DORMANT, DEFERRED, BLOCKED):
                item["final_state"] = ISOLATED
                destination_reason = "Destination structure admits bounded export audit evidence."
        elif data_destination_key == "external_email_domain":
            if capability_key in ("scan_to_email", "fax_module", "cloud_print", "remote_print_api") and state in ADMITTED_STATES:
                item["final_state"] = DEFERRED
                destination_reason = "Destination structure defers external document movement."
            if capability_key == "audit_logs" and state in (FORBIDDEN, DORMANT, DEFERRED, BLOCKED):
                item["final_state"] = ISOLATED
                destination_reason = "Destination structure admits audit evidence for external routing attempt."
        elif data_destination_key == "vendor_cloud_queue":
            if capability_key == "cloud_print" and state in (FORBIDDEN, DORMANT, DEFERRED, BLOCKED):
                item["final_state"] = ISOLATED
                destination_reason = "Destination structure admits bounded vendor cloud queue visibility."
            if capability_key == "remote_print_api" and state in ADMITTED_STATES:
                item["final_state"] = ISOLATED
                destination_reason = "Destination structure keeps remote API visibility bounded to cloud queue routing."
            if capability_key in ("scan_to_email", "fax_module", "document_cache") and state in ADMITTED_STATES:
                item["final_state"] = DEFERRED
                destination_reason = "Destination structure does not add export or cache visibility."
        elif data_destination_key == "blocked_destination":
            if capability_key in ("print_engine", "paper_feed", "ink_toner_system", "cloud_print", "remote_print_api", "scan_to_email", "fax_module", "secure_release") and state in ADMITTED_STATES:
                item["final_state"] = DEFERRED
                destination_reason = "Destination structure blocks movement and output visibility."
            if capability_key == "document_cache" and state in ADMITTED_STATES:
                item["final_state"] = FORBIDDEN
                destination_reason = "Destination structure refuses cache visibility for blocked routing."
            if capability_key == "audit_logs" and state in (FORBIDDEN, DORMANT, DEFERRED, BLOCKED):
                item["final_state"] = ISOLATED
                destination_reason = "Destination structure admits bounded audit evidence for blocked routing."
        item["data_destination"] = data_destination_key
        item["data_destination_description"] = data_destination["description"]
        item["data_destination_applied"] = destination_reason is not None
        if destination_reason is not None:
            item["reason"] = destination_reason
        item["certificate"] = protection_certificate(item)
        items.append(item)
    states = (VISIBLE, ISOLATED, DORMANT, FORBIDDEN, BLOCKED, DEFERRED)
    updated = dict(surface)
    updated["data_destination"] = data_destination_key
    updated["data_destination_description"] = data_destination["description"]
    updated["items"] = items
    updated["counts"] = {state: sum(1 for item in items if item["final_state"] == state) for state in states}
    updated["visible_surface"] = [item["capability_key"] for item in items if item["final_state"] in ADMITTED_STATES]
    updated["deferred_surface"] = [item["capability_key"] for item in items if item["final_state"] == DEFERRED]
    updated["surface_certificate"] = protection_certificate(updated)
    return updated


def resolve_data_destination_surface(scenario_key: str, profile_key: str, request_key: str, policy_key: str, document_class_key: str, role_key: str, context_key: str, approval_key: str, release_mode_key: str, actor_key: str, job_state_key: str, retention_state_key: str, data_destination_key: str) -> dict:
    surface = resolve_retention_state_surface(scenario_key, profile_key, request_key, policy_key, document_class_key, role_key, context_key, approval_key, release_mode_key, actor_key, job_state_key, retention_state_key)
    return apply_data_destination_layer(surface, data_destination_key)


def data_destination_audit(policy_key: str = "standard", document_class_key: str = "public_document", role_key: str = "employee", context_key: str = "trusted_office_device", approval_key: str = "manager_approved", release_mode_key: str = "secure_pull_release", actor_key: str = "requester", job_state_key: str = "submitted_job", retention_state_key: str = "short_spool_retention", scenario_key: str = "remote_print", profile_key: str = "connected", request_key: str = "normal") -> dict:
    blocks = []
    for data_destination_key in DATA_DESTINATION_ORDER:
        surface = resolve_data_destination_surface(scenario_key, profile_key, request_key, policy_key, document_class_key, role_key, context_key, approval_key, release_mode_key, actor_key, job_state_key, retention_state_key, data_destination_key)
        cloud_state = next(item for item in surface["items"] if item["capability_key"] == "cloud_print")["final_state"]
        remote_state = next(item for item in surface["items"] if item["capability_key"] == "remote_print_api")["final_state"]
        scan_state = next(item for item in surface["items"] if item["capability_key"] == "scan_to_email")["final_state"]
        fax_state = next(item for item in surface["items"] if item["capability_key"] == "fax_module")["final_state"]
        cache_state = next(item for item in surface["items"] if item["capability_key"] == "document_cache")["final_state"]
        audit_state = next(item for item in surface["items"] if item["capability_key"] == "audit_logs")["final_state"]
        print_state = next(item for item in surface["items"] if item["capability_key"] == "print_engine")["final_state"]
        block = {
            "data_destination": data_destination_key,
            "description": DATA_DESTINATIONS[data_destination_key]["description"],
            "surface_certificate": surface["surface_certificate"],
            "visible_surface": surface["visible_surface"],
            "deferred_surface": surface["deferred_surface"],
            "cloud_print": cloud_state,
            "remote_print_api": remote_state,
            "scan_to_email": scan_state,
            "fax_module": fax_state,
            "document_cache": cache_state,
            "audit_logs": audit_state,
            "print_engine": print_state,
        }
        block["data_destination_certificate"] = protection_certificate(block)
        blocks.append(block)
    signatures = {block["data_destination"]: (tuple(block["visible_surface"]), tuple(block["deferred_surface"])) for block in blocks}
    states = {block["data_destination"]: (block["cloud_print"], block["remote_print_api"], block["scan_to_email"], block["audit_logs"], block["print_engine"]) for block in blocks}
    checks = {
        "data_destination_changes_visibility_outcome": len(set(signatures.values())) > 1,
        "local_printer_only_defers_remote_movement": states["local_printer_only"][0] == DEFERRED or states["local_printer_only"][1] == DEFERRED,
        "department_queue_preserves_bounded_queue_routing": states["department_queue"][0] in (ISOLATED, DEFERRED) and states["department_queue"][1] in (ISOLATED, DEFERRED),
        "approved_email_domain_admits_scan_export": states["approved_email_domain"][2] == ISOLATED,
        "external_email_domain_admits_audit_evidence": states["external_email_domain"][3] == ISOLATED,
        "vendor_cloud_queue_admits_cloud_visibility": states["vendor_cloud_queue"][0] == ISOLATED,
        "blocked_destination_defers_output_or_movement": states["blocked_destination"][4] == DEFERRED or states["blocked_destination"][0] == DEFERRED,
    }
    payload = {
        "project": PROJECT_NAME,
        "version": VERSION,
        "result": "PASS" if all(checks.values()) else "FAIL",
        "scenario": scenario_key,
        "profile": profile_key,
        "request": request_key,
        "policy": policy_key,
        "document_class": document_class_key,
        "role": role_key,
        "context": context_key,
        "approval": approval_key,
        "release_mode": release_mode_key,
        "actor": actor_key,
        "job_state": job_state_key,
        "retention_state": retention_state_key,
        "data_destination_count": len(DATA_DESTINATION_ORDER),
        "checks": checks,
        "blocks": blocks,
    }
    payload["data_destination_audit_certificate"] = protection_certificate(payload)
    return payload


def apply_device_health_layer(surface: dict, device_health_key: str) -> dict:
    device_health = DEVICE_HEALTHS[device_health_key]
    items = []
    for source_item in surface["items"]:
        item = dict(source_item)
        capability_key = item["capability_key"]
        state = item["final_state"]
        health_reason = None
        if device_health_key == "healthy_device":
            pass
        elif device_health_key == "low_toner":
            if capability_key in ("print_engine", "paper_feed", "ink_toner_system") and state in ADMITTED_STATES:
                item["final_state"] = DEFERRED
                health_reason = "Device health defers physical output until consumable readiness is restored."
            if capability_key == "supply_monitor" and state in (FORBIDDEN, DORMANT, DEFERRED, BLOCKED):
                item["final_state"] = ISOLATED
                health_reason = "Device health admits supply monitoring visibility."
        elif device_health_key == "paper_jam":
            if capability_key in ("print_engine", "paper_feed", "ink_toner_system", "secure_release") and state in ADMITTED_STATES:
                item["final_state"] = DEFERRED
                health_reason = "Device health defers physical output and release until paper path is cleared."
            if capability_key in ("job_queue", "audit_logs", "supply_monitor") and state in (FORBIDDEN, DORMANT, DEFERRED, BLOCKED):
                item["final_state"] = ISOLATED
                health_reason = "Device health admits bounded job, audit, or supply evidence."
        elif device_health_key == "offline_device":
            if capability_key in ("print_engine", "paper_feed", "ink_toner_system", "cloud_print", "remote_print_api", "scan_to_email", "fax_module", "secure_release") and state in ADMITTED_STATES:
                item["final_state"] = DEFERRED
                health_reason = "Device health defers live routing, release, and output while the device is offline."
            if capability_key in ("job_queue", "audit_logs") and state in (FORBIDDEN, DORMANT, DEFERRED, BLOCKED):
                item["final_state"] = ISOLATED
                health_reason = "Device health preserves bounded job or audit evidence while offline."
        elif device_health_key == "compromised_device":
            if capability_key in ("print_engine", "paper_feed", "ink_toner_system", "cloud_print", "remote_print_api", "scan_to_email", "fax_module", "secure_release", "admin_console", "firmware_update", "telemetry_export") and state in ADMITTED_STATES:
                item["final_state"] = DEFERRED
                health_reason = "Device health defers movement, output, release, and service visibility under compromise posture."
            if capability_key == "document_cache" and state in ADMITTED_STATES:
                item["final_state"] = FORBIDDEN
                health_reason = "Device health refuses cache visibility under compromise posture."
            if capability_key in ("job_queue", "audit_logs") and state in (FORBIDDEN, DORMANT, DEFERRED, BLOCKED):
                item["final_state"] = ISOLATED
                health_reason = "Device health preserves bounded evidence under compromise posture."
        elif device_health_key == "maintenance_required":
            if capability_key in ("print_engine", "paper_feed", "ink_toner_system", "cloud_print", "remote_print_api", "scan_to_email", "fax_module", "secure_release") and state in ADMITTED_STATES:
                item["final_state"] = DEFERRED
                health_reason = "Device health defers ordinary movement and output until maintenance is complete."
            if capability_key in ("admin_console", "firmware_update", "audit_logs", "supply_monitor") and state in (FORBIDDEN, DORMANT, DEFERRED, BLOCKED):
                item["final_state"] = ISOLATED
                health_reason = "Device health admits bounded service or audit visibility."
        item["device_health"] = device_health_key
        item["device_health_description"] = device_health["description"]
        item["device_health_applied"] = health_reason is not None
        if health_reason is not None:
            item["reason"] = health_reason
        item["certificate"] = protection_certificate(item)
        items.append(item)
    states = (VISIBLE, ISOLATED, DORMANT, FORBIDDEN, BLOCKED, DEFERRED)
    updated = dict(surface)
    updated["device_health"] = device_health_key
    updated["device_health_description"] = device_health["description"]
    updated["items"] = items
    updated["counts"] = {state: sum(1 for item in items if item["final_state"] == state) for state in states}
    updated["visible_surface"] = [item["capability_key"] for item in items if item["final_state"] in ADMITTED_STATES]
    updated["deferred_surface"] = [item["capability_key"] for item in items if item["final_state"] == DEFERRED]
    updated["surface_certificate"] = protection_certificate(updated)
    return updated


def resolve_device_health_surface(scenario_key: str, profile_key: str, request_key: str, policy_key: str, document_class_key: str, role_key: str, context_key: str, approval_key: str, release_mode_key: str, actor_key: str, job_state_key: str, retention_state_key: str, data_destination_key: str, device_health_key: str) -> dict:
    surface = resolve_data_destination_surface(scenario_key, profile_key, request_key, policy_key, document_class_key, role_key, context_key, approval_key, release_mode_key, actor_key, job_state_key, retention_state_key, data_destination_key)
    return apply_device_health_layer(surface, device_health_key)


def device_health_audit(policy_key: str = "standard", document_class_key: str = "public_document", role_key: str = "employee", context_key: str = "trusted_office_device", approval_key: str = "manager_approved", release_mode_key: str = "secure_pull_release", actor_key: str = "release_operator", job_state_key: str = "released_job", retention_state_key: str = "short_spool_retention", data_destination_key: str = "department_queue", scenario_key: str = "remote_print", profile_key: str = "connected", request_key: str = "normal") -> dict:
    blocks = []
    for device_health_key in DEVICE_HEALTH_ORDER:
        surface = resolve_device_health_surface(scenario_key, profile_key, request_key, policy_key, document_class_key, role_key, context_key, approval_key, release_mode_key, actor_key, job_state_key, retention_state_key, data_destination_key, device_health_key)
        print_state = next(item for item in surface["items"] if item["capability_key"] == "print_engine")["final_state"]
        paper_state = next(item for item in surface["items"] if item["capability_key"] == "paper_feed")["final_state"]
        toner_state = next(item for item in surface["items"] if item["capability_key"] == "ink_toner_system")["final_state"]
        cloud_state = next(item for item in surface["items"] if item["capability_key"] == "cloud_print")["final_state"]
        remote_state = next(item for item in surface["items"] if item["capability_key"] == "remote_print_api")["final_state"]
        admin_state = next(item for item in surface["items"] if item["capability_key"] == "admin_console")["final_state"]
        firmware_state = next(item for item in surface["items"] if item["capability_key"] == "firmware_update")["final_state"]
        audit_state = next(item for item in surface["items"] if item["capability_key"] == "audit_logs")["final_state"]
        block = {
            "device_health": device_health_key,
            "description": DEVICE_HEALTHS[device_health_key]["description"],
            "surface_certificate": surface["surface_certificate"],
            "visible_surface": surface["visible_surface"],
            "deferred_surface": surface["deferred_surface"],
            "print_engine": print_state,
            "paper_feed": paper_state,
            "ink_toner_system": toner_state,
            "cloud_print": cloud_state,
            "remote_print_api": remote_state,
            "admin_console": admin_state,
            "firmware_update": firmware_state,
            "audit_logs": audit_state,
        }
        block["device_health_certificate"] = protection_certificate(block)
        blocks.append(block)
    signatures = {block["device_health"]: (tuple(block["visible_surface"]), tuple(block["deferred_surface"])) for block in blocks}
    states = {block["device_health"]: (block["print_engine"], block["paper_feed"], block["ink_toner_system"], block["cloud_print"], block["remote_print_api"], block["admin_console"], block["firmware_update"], block["audit_logs"]) for block in blocks}
    checks = {
        "device_health_changes_visibility_outcome": len(set(signatures.values())) > 1,
        "healthy_device_preserves_output": states["healthy_device"][0] in ADMITTED_STATES,
        "low_toner_defers_output_readiness": states["low_toner"][2] == DEFERRED or states["low_toner"][0] == DEFERRED,
        "paper_jam_defers_paper_path": states["paper_jam"][1] == DEFERRED or states["paper_jam"][0] == DEFERRED,
        "offline_device_defers_live_movement": states["offline_device"][3] == DEFERRED or states["offline_device"][4] == DEFERRED,
        "compromised_device_preserves_audit_evidence": states["compromised_device"][7] == ISOLATED,
        "maintenance_required_admits_service_or_audit_visibility": states["maintenance_required"][5] == ISOLATED or states["maintenance_required"][6] == ISOLATED or states["maintenance_required"][7] == ISOLATED,
    }
    payload = {
        "project": PROJECT_NAME,
        "version": VERSION,
        "result": "PASS" if all(checks.values()) else "FAIL",
        "scenario": scenario_key,
        "profile": profile_key,
        "request": request_key,
        "policy": policy_key,
        "document_class": document_class_key,
        "role": role_key,
        "context": context_key,
        "approval": approval_key,
        "release_mode": release_mode_key,
        "actor": actor_key,
        "job_state": job_state_key,
        "retention_state": retention_state_key,
        "data_destination": data_destination_key,
        "device_health_count": len(DEVICE_HEALTH_ORDER),
        "checks": checks,
        "blocks": blocks,
    }
    payload["device_health_audit_certificate"] = protection_certificate(payload)
    return payload


def apply_risk_posture_layer(surface: dict, risk_posture_key: str) -> dict:
    risk_posture = RISK_POSTURES[risk_posture_key]
    items = []
    for source_item in surface["items"]:
        item = dict(source_item)
        capability_key = item["capability_key"]
        state = item["final_state"]
        risk_reason = None
        if risk_posture_key == "normal_risk":
            pass
        elif risk_posture_key == "elevated_risk":
            if capability_key in ("cloud_print", "remote_print_api", "scan_to_email", "fax_module", "print_engine", "paper_feed", "ink_toner_system", "secure_release") and state in ADMITTED_STATES:
                item["final_state"] = DEFERRED
                risk_reason = "Risk posture defers movement, release, and output visibility."
            if capability_key in ("job_queue", "audit_logs") and state in (FORBIDDEN, DORMANT, DEFERRED, BLOCKED):
                item["final_state"] = ISOLATED
                risk_reason = "Risk posture preserves bounded queue or audit evidence."
        elif risk_posture_key == "data_loss_risk":
            if capability_key in ("cloud_print", "remote_print_api", "scan_to_email", "fax_module", "document_cache") and state in ADMITTED_STATES:
                item["final_state"] = DEFERRED if capability_key != "document_cache" else FORBIDDEN
                risk_reason = "Risk posture narrows document movement and cache visibility."
            if capability_key == "audit_logs" and state in (FORBIDDEN, DORMANT, DEFERRED, BLOCKED):
                item["final_state"] = ISOLATED
                risk_reason = "Risk posture admits audit evidence for data movement review."
        elif risk_posture_key == "malware_risk":
            if capability_key in ("print_engine", "paper_feed", "ink_toner_system", "cloud_print", "remote_print_api", "scan_to_email", "fax_module", "secure_release", "admin_console", "firmware_update", "telemetry_export") and state in ADMITTED_STATES:
                item["final_state"] = DEFERRED
                risk_reason = "Risk posture defers movement, output, service change, and telemetry visibility."
            if capability_key == "document_cache" and state in ADMITTED_STATES:
                item["final_state"] = FORBIDDEN
                risk_reason = "Risk posture refuses cache visibility during malware review."
            if capability_key in ("job_queue", "audit_logs") and state in (FORBIDDEN, DORMANT, DEFERRED, BLOCKED):
                item["final_state"] = ISOLATED
                risk_reason = "Risk posture preserves bounded evidence during malware review."
        elif risk_posture_key == "insider_risk":
            if capability_key in ("cloud_print", "remote_print_api", "scan_to_email", "fax_module", "secure_release", "document_cache") and state in ADMITTED_STATES:
                item["final_state"] = DEFERRED if capability_key != "document_cache" else FORBIDDEN
                risk_reason = "Risk posture narrows movement, release, and cache visibility under insider-risk review."
            if capability_key == "audit_logs" and state in (FORBIDDEN, DORMANT, DEFERRED, BLOCKED):
                item["final_state"] = ISOLATED
                risk_reason = "Risk posture admits audit evidence under insider-risk review."
        elif risk_posture_key == "regulatory_risk":
            if capability_key in ("cloud_print", "remote_print_api", "scan_to_email", "fax_module", "print_engine", "paper_feed", "ink_toner_system", "secure_release") and state in ADMITTED_STATES:
                item["final_state"] = DEFERRED
                risk_reason = "Risk posture defers document movement and ordinary release under regulatory review."
            if capability_key in ("job_queue", "audit_logs") and state in (FORBIDDEN, DORMANT, DEFERRED, BLOCKED):
                item["final_state"] = ISOLATED
                risk_reason = "Risk posture preserves records-grade evidence."
            if capability_key == "document_cache" and state in ADMITTED_STATES:
                item["final_state"] = ISOLATED
                risk_reason = "Risk posture keeps cache evidence isolated under regulatory review."
        item["risk_posture"] = risk_posture_key
        item["risk_posture_description"] = risk_posture["description"]
        item["risk_posture_applied"] = risk_reason is not None
        if risk_reason is not None:
            item["reason"] = risk_reason
        item["certificate"] = protection_certificate(item)
        items.append(item)
    states = (VISIBLE, ISOLATED, DORMANT, FORBIDDEN, BLOCKED, DEFERRED)
    updated = dict(surface)
    updated["risk_posture"] = risk_posture_key
    updated["risk_posture_description"] = risk_posture["description"]
    updated["items"] = items
    updated["counts"] = {state: sum(1 for item in items if item["final_state"] == state) for state in states}
    updated["visible_surface"] = [item["capability_key"] for item in items if item["final_state"] in ADMITTED_STATES]
    updated["deferred_surface"] = [item["capability_key"] for item in items if item["final_state"] == DEFERRED]
    updated["surface_certificate"] = protection_certificate(updated)
    return updated


def resolve_risk_posture_surface(scenario_key: str, profile_key: str, request_key: str, policy_key: str, document_class_key: str, role_key: str, context_key: str, approval_key: str, release_mode_key: str, actor_key: str, job_state_key: str, retention_state_key: str, data_destination_key: str, device_health_key: str, risk_posture_key: str) -> dict:
    surface = resolve_device_health_surface(scenario_key, profile_key, request_key, policy_key, document_class_key, role_key, context_key, approval_key, release_mode_key, actor_key, job_state_key, retention_state_key, data_destination_key, device_health_key)
    return apply_risk_posture_layer(surface, risk_posture_key)


def risk_posture_audit(policy_key: str = "standard", document_class_key: str = "public_document", role_key: str = "employee", context_key: str = "trusted_office_device", approval_key: str = "manager_approved", release_mode_key: str = "secure_pull_release", actor_key: str = "release_operator", job_state_key: str = "released_job", retention_state_key: str = "short_spool_retention", data_destination_key: str = "department_queue", device_health_key: str = "healthy_device", scenario_key: str = "remote_print", profile_key: str = "connected", request_key: str = "normal") -> dict:
    blocks = []
    for risk_posture_key in RISK_POSTURE_ORDER:
        surface = resolve_risk_posture_surface(scenario_key, profile_key, request_key, policy_key, document_class_key, role_key, context_key, approval_key, release_mode_key, actor_key, job_state_key, retention_state_key, data_destination_key, device_health_key, risk_posture_key)
        print_state = next(item for item in surface["items"] if item["capability_key"] == "print_engine")["final_state"]
        cloud_state = next(item for item in surface["items"] if item["capability_key"] == "cloud_print")["final_state"]
        remote_state = next(item for item in surface["items"] if item["capability_key"] == "remote_print_api")["final_state"]
        scan_state = next(item for item in surface["items"] if item["capability_key"] == "scan_to_email")["final_state"]
        cache_state = next(item for item in surface["items"] if item["capability_key"] == "document_cache")["final_state"]
        admin_state = next(item for item in surface["items"] if item["capability_key"] == "admin_console")["final_state"]
        firmware_state = next(item for item in surface["items"] if item["capability_key"] == "firmware_update")["final_state"]
        audit_state = next(item for item in surface["items"] if item["capability_key"] == "audit_logs")["final_state"]
        block = {
            "risk_posture": risk_posture_key,
            "description": RISK_POSTURES[risk_posture_key]["description"],
            "surface_certificate": surface["surface_certificate"],
            "visible_surface": surface["visible_surface"],
            "deferred_surface": surface["deferred_surface"],
            "print_engine": print_state,
            "cloud_print": cloud_state,
            "remote_print_api": remote_state,
            "scan_to_email": scan_state,
            "document_cache": cache_state,
            "admin_console": admin_state,
            "firmware_update": firmware_state,
            "audit_logs": audit_state,
        }
        block["risk_posture_certificate"] = protection_certificate(block)
        blocks.append(block)
    signatures = {block["risk_posture"]: (tuple(block["visible_surface"]), tuple(block["deferred_surface"])) for block in blocks}
    states = {block["risk_posture"]: (block["print_engine"], block["cloud_print"], block["remote_print_api"], block["scan_to_email"], block["document_cache"], block["admin_console"], block["firmware_update"], block["audit_logs"]) for block in blocks}
    checks = {
        "risk_posture_changes_visibility_outcome": len(set(signatures.values())) > 1,
        "normal_risk_preserves_output": states["normal_risk"][0] in ADMITTED_STATES,
        "elevated_risk_defers_output_or_movement": states["elevated_risk"][0] == DEFERRED or states["elevated_risk"][1] == DEFERRED or states["elevated_risk"][2] == DEFERRED,
        "data_loss_risk_preserves_audit": states["data_loss_risk"][7] == ISOLATED,
        "malware_risk_defers_service_change_or_movement": states["malware_risk"][5] == DEFERRED or states["malware_risk"][6] == DEFERRED or states["malware_risk"][1] == DEFERRED,
        "insider_risk_preserves_audit": states["insider_risk"][7] == ISOLATED,
        "regulatory_risk_preserves_records_evidence": states["regulatory_risk"][7] == ISOLATED,
    }
    payload = {
        "project": PROJECT_NAME,
        "version": VERSION,
        "result": "PASS" if all(checks.values()) else "FAIL",
        "scenario": scenario_key,
        "profile": profile_key,
        "request": request_key,
        "policy": policy_key,
        "document_class": document_class_key,
        "role": role_key,
        "context": context_key,
        "approval": approval_key,
        "release_mode": release_mode_key,
        "actor": actor_key,
        "job_state": job_state_key,
        "retention_state": retention_state_key,
        "data_destination": data_destination_key,
        "device_health": device_health_key,
        "risk_posture_count": len(RISK_POSTURE_ORDER),
        "checks": checks,
        "blocks": blocks,
    }
    payload["risk_posture_audit_certificate"] = protection_certificate(payload)
    return payload


def apply_compliance_mode_layer(surface: dict, compliance_mode_key: str) -> dict:
    compliance_mode = COMPLIANCE_MODES[compliance_mode_key]
    items = []
    for source_item in surface["items"]:
        item = dict(source_item)
        capability_key = item["capability_key"]
        state = item["final_state"]
        compliance_reason = None
        if compliance_mode_key == "ordinary_mode":
            pass
        elif compliance_mode_key == "confidential_mode":
            if capability_key in ("cloud_print", "remote_print_api", "scan_to_email", "fax_module", "secure_release", "document_cache") and state in ADMITTED_STATES:
                item["final_state"] = FORBIDDEN if capability_key == "document_cache" else DEFERRED
                compliance_reason = "Compliance mode narrows document movement, release, and cache visibility."
            if capability_key == "audit_logs" and state in (FORBIDDEN, DORMANT, DEFERRED, BLOCKED):
                item["final_state"] = ISOLATED
                compliance_reason = "Compliance mode preserves bounded audit evidence."
        elif compliance_mode_key == "regulated_mode":
            if capability_key in ("cloud_print", "remote_print_api", "scan_to_email", "fax_module", "print_engine", "paper_feed", "ink_toner_system", "secure_release") and state in ADMITTED_STATES:
                item["final_state"] = DEFERRED
                compliance_reason = "Compliance mode defers document movement, ordinary output, and release visibility."
            if capability_key in ("job_queue", "audit_logs") and state in (FORBIDDEN, DORMANT, DEFERRED, BLOCKED):
                item["final_state"] = ISOLATED
                compliance_reason = "Compliance mode preserves regulated queue or audit evidence."
            if capability_key == "document_cache" and state in ADMITTED_STATES:
                item["final_state"] = FORBIDDEN
                compliance_reason = "Compliance mode refuses document cache visibility unless separately held."
        elif compliance_mode_key == "records_mode":
            if capability_key in ("cloud_print", "remote_print_api", "scan_to_email", "fax_module") and state in ADMITTED_STATES:
                item["final_state"] = DEFERRED
                compliance_reason = "Compliance mode narrows remote movement and export visibility."
            if capability_key in ("job_queue", "secure_release", "audit_logs") and state in (FORBIDDEN, DORMANT, DEFERRED, BLOCKED):
                item["final_state"] = ISOLATED
                compliance_reason = "Compliance mode preserves records-grade queue, release, or audit visibility."
            if capability_key == "document_cache" and state in ADMITTED_STATES:
                item["final_state"] = FORBIDDEN
                compliance_reason = "Compliance mode keeps document cache visibility refused unless held."
        elif compliance_mode_key == "legal_hold_mode":
            if capability_key in ("print_engine", "paper_feed", "ink_toner_system", "cloud_print", "remote_print_api", "scan_to_email", "fax_module", "secure_release") and state in ADMITTED_STATES:
                item["final_state"] = DEFERRED
                compliance_reason = "Compliance mode defers output, release, and document movement while hold is active."
            if capability_key in ("job_queue", "document_cache", "audit_logs") and state in (FORBIDDEN, DORMANT, DEFERRED, BLOCKED):
                item["final_state"] = ISOLATED
                compliance_reason = "Compliance mode preserves isolated hold evidence."
        elif compliance_mode_key == "incident_mode":
            if capability_key in ("print_engine", "paper_feed", "ink_toner_system", "cloud_print", "remote_print_api", "scan_to_email", "fax_module", "secure_release", "admin_console", "firmware_update", "telemetry_export") and state in ADMITTED_STATES:
                item["final_state"] = DEFERRED
                compliance_reason = "Compliance mode defers movement, output, service change, release, and telemetry visibility."
            if capability_key in ("job_queue", "document_cache", "audit_logs") and state in (FORBIDDEN, DORMANT, DEFERRED, BLOCKED):
                item["final_state"] = ISOLATED
                compliance_reason = "Compliance mode preserves bounded incident evidence."
        item["compliance_mode"] = compliance_mode_key
        item["compliance_mode_description"] = compliance_mode["description"]
        item["compliance_mode_applied"] = compliance_reason is not None
        if compliance_reason is not None:
            item["reason"] = compliance_reason
        item["certificate"] = protection_certificate(item)
        items.append(item)
    states = (VISIBLE, ISOLATED, DORMANT, FORBIDDEN, BLOCKED, DEFERRED)
    updated = dict(surface)
    updated["compliance_mode"] = compliance_mode_key
    updated["compliance_mode_description"] = compliance_mode["description"]
    updated["items"] = items
    updated["counts"] = {state: sum(1 for item in items if item["final_state"] == state) for state in states}
    updated["visible_surface"] = [item["capability_key"] for item in items if item["final_state"] in ADMITTED_STATES]
    updated["deferred_surface"] = [item["capability_key"] for item in items if item["final_state"] == DEFERRED]
    updated["surface_certificate"] = protection_certificate(updated)
    return updated


def resolve_compliance_mode_surface(scenario_key: str, profile_key: str, request_key: str, policy_key: str, document_class_key: str, role_key: str, context_key: str, approval_key: str, release_mode_key: str, actor_key: str, job_state_key: str, retention_state_key: str, data_destination_key: str, device_health_key: str, risk_posture_key: str, compliance_mode_key: str) -> dict:
    surface = resolve_risk_posture_surface(scenario_key, profile_key, request_key, policy_key, document_class_key, role_key, context_key, approval_key, release_mode_key, actor_key, job_state_key, retention_state_key, data_destination_key, device_health_key, risk_posture_key)
    return apply_compliance_mode_layer(surface, compliance_mode_key)


def compliance_mode_audit(policy_key: str = "standard", document_class_key: str = "public_document", role_key: str = "employee", context_key: str = "trusted_office_device", approval_key: str = "manager_approved", release_mode_key: str = "secure_pull_release", actor_key: str = "release_operator", job_state_key: str = "released_job", retention_state_key: str = "short_spool_retention", data_destination_key: str = "department_queue", device_health_key: str = "healthy_device", risk_posture_key: str = "normal_risk", scenario_key: str = "remote_print", profile_key: str = "connected", request_key: str = "normal") -> dict:
    blocks = []
    for compliance_mode_key in COMPLIANCE_MODE_ORDER:
        surface = resolve_compliance_mode_surface(scenario_key, profile_key, request_key, policy_key, document_class_key, role_key, context_key, approval_key, release_mode_key, actor_key, job_state_key, retention_state_key, data_destination_key, device_health_key, risk_posture_key, compliance_mode_key)
        print_state = next(item for item in surface["items"] if item["capability_key"] == "print_engine")["final_state"]
        cloud_state = next(item for item in surface["items"] if item["capability_key"] == "cloud_print")["final_state"]
        remote_state = next(item for item in surface["items"] if item["capability_key"] == "remote_print_api")["final_state"]
        scan_state = next(item for item in surface["items"] if item["capability_key"] == "scan_to_email")["final_state"]
        cache_state = next(item for item in surface["items"] if item["capability_key"] == "document_cache")["final_state"]
        admin_state = next(item for item in surface["items"] if item["capability_key"] == "admin_console")["final_state"]
        firmware_state = next(item for item in surface["items"] if item["capability_key"] == "firmware_update")["final_state"]
        audit_state = next(item for item in surface["items"] if item["capability_key"] == "audit_logs")["final_state"]
        secure_state = next(item for item in surface["items"] if item["capability_key"] == "secure_release")["final_state"]
        block = {
            "compliance_mode": compliance_mode_key,
            "description": COMPLIANCE_MODES[compliance_mode_key]["description"],
            "surface_certificate": surface["surface_certificate"],
            "visible_surface": surface["visible_surface"],
            "deferred_surface": surface["deferred_surface"],
            "print_engine": print_state,
            "cloud_print": cloud_state,
            "remote_print_api": remote_state,
            "scan_to_email": scan_state,
            "document_cache": cache_state,
            "admin_console": admin_state,
            "firmware_update": firmware_state,
            "audit_logs": audit_state,
            "secure_release": secure_state,
        }
        block["compliance_mode_certificate"] = protection_certificate(block)
        blocks.append(block)
    signatures = {block["compliance_mode"]: (tuple(block["visible_surface"]), tuple(block["deferred_surface"])) for block in blocks}
    states = {block["compliance_mode"]: (block["print_engine"], block["cloud_print"], block["remote_print_api"], block["scan_to_email"], block["document_cache"], block["admin_console"], block["firmware_update"], block["audit_logs"], block["secure_release"]) for block in blocks}
    checks = {
        "compliance_mode_changes_visibility_outcome": len(set(signatures.values())) > 1,
        "ordinary_mode_preserves_output": states["ordinary_mode"][0] in ADMITTED_STATES,
        "confidential_mode_preserves_audit": states["confidential_mode"][7] == ISOLATED,
        "regulated_mode_preserves_audit": states["regulated_mode"][7] == ISOLATED,
        "records_mode_preserves_records_visibility": states["records_mode"][7] == ISOLATED and states["records_mode"][8] == ISOLATED,
        "legal_hold_mode_preserves_cache_evidence": states["legal_hold_mode"][4] == ISOLATED,
        "incident_mode_preserves_evidence": states["incident_mode"][7] == ISOLATED,
    }
    payload = {
        "project": PROJECT_NAME,
        "version": VERSION,
        "result": "PASS" if all(checks.values()) else "FAIL",
        "scenario": scenario_key,
        "profile": profile_key,
        "request": request_key,
        "policy": policy_key,
        "document_class": document_class_key,
        "role": role_key,
        "context": context_key,
        "approval": approval_key,
        "release_mode": release_mode_key,
        "actor": actor_key,
        "job_state": job_state_key,
        "retention_state": retention_state_key,
        "data_destination": data_destination_key,
        "device_health": device_health_key,
        "risk_posture": risk_posture_key,
        "compliance_mode_count": len(COMPLIANCE_MODE_ORDER),
        "checks": checks,
        "blocks": blocks,
    }
    payload["compliance_mode_audit_certificate"] = protection_certificate(payload)
    return payload


def apply_trust_zone_layer(surface: dict, trust_zone_key: str) -> dict:
    trust_zone = TRUST_ZONES[trust_zone_key]
    items = []
    for source_item in surface["items"]:
        item = dict(source_item)
        capability_key = item["capability_key"]
        state = item["final_state"]
        trust_reason = None
        if trust_zone_key == "local_trusted_zone":
            pass
        elif trust_zone_key == "department_zone":
            if capability_key in ("scan_to_email", "fax_module", "document_cache", "admin_console", "firmware_update", "telemetry_export") and state in ADMITTED_STATES:
                item["final_state"] = FORBIDDEN if capability_key == "document_cache" else DEFERRED
                trust_reason = "Trust zone narrows external export, cache, service, and telemetry visibility."
            if capability_key in ("job_queue", "audit_logs") and state in (FORBIDDEN, DORMANT, DEFERRED, BLOCKED):
                item["final_state"] = ISOLATED
                trust_reason = "Trust zone preserves departmental queue or audit evidence."
        elif trust_zone_key == "enterprise_zone":
            if capability_key in ("document_cache", "fax_module") and state in ADMITTED_STATES:
                item["final_state"] = FORBIDDEN if capability_key == "document_cache" else DEFERRED
                trust_reason = "Trust zone keeps cache and fax visibility governed separately."
            if capability_key == "audit_logs" and state in (FORBIDDEN, DORMANT, DEFERRED, BLOCKED):
                item["final_state"] = ISOLATED
                trust_reason = "Trust zone preserves enterprise audit evidence."
        elif trust_zone_key == "guest_zone":
            if capability_key in ("print_engine", "paper_feed", "ink_toner_system", "cloud_print", "remote_print_api", "scan_to_email", "fax_module", "secure_release", "admin_console", "firmware_update", "telemetry_export", "document_cache") and state in ADMITTED_STATES:
                item["final_state"] = FORBIDDEN if capability_key == "document_cache" else DEFERRED
                trust_reason = "Trust zone defers document movement, output, release, service, telemetry, and cache visibility."
            if capability_key in ("job_queue", "audit_logs") and state in (FORBIDDEN, DORMANT, DEFERRED, BLOCKED):
                item["final_state"] = ISOLATED
                trust_reason = "Trust zone preserves bounded evidence."
        elif trust_zone_key == "vendor_zone":
            if capability_key in ("print_engine", "paper_feed", "ink_toner_system", "cloud_print", "remote_print_api", "scan_to_email", "fax_module", "secure_release", "document_cache") and state in ADMITTED_STATES:
                item["final_state"] = FORBIDDEN if capability_key == "document_cache" else DEFERRED
                trust_reason = "Trust zone defers document movement, output, release, and cache visibility."
            if capability_key in ("admin_console", "firmware_update", "audit_logs", "supply_monitor") and state in (FORBIDDEN, DORMANT, DEFERRED, BLOCKED):
                item["final_state"] = ISOLATED
                trust_reason = "Trust zone admits bounded service or audit visibility."
        elif trust_zone_key == "external_zone":
            if capability_key in ("print_engine", "paper_feed", "ink_toner_system", "cloud_print", "remote_print_api", "scan_to_email", "fax_module", "secure_release", "admin_console", "firmware_update", "telemetry_export", "document_cache") and state in ADMITTED_STATES:
                item["final_state"] = FORBIDDEN if capability_key == "document_cache" else DEFERRED
                trust_reason = "Trust zone defers document movement, output, release, service change, telemetry, and cache visibility."
            if capability_key in ("job_queue", "audit_logs") and state in (FORBIDDEN, DORMANT, DEFERRED, BLOCKED):
                item["final_state"] = ISOLATED
                trust_reason = "Trust zone preserves bounded evidence."
        item["trust_zone"] = trust_zone_key
        item["trust_zone_description"] = trust_zone["description"]
        item["trust_zone_applied"] = trust_reason is not None
        if trust_reason is not None:
            item["reason"] = trust_reason
        item["certificate"] = protection_certificate(item)
        items.append(item)
    states = (VISIBLE, ISOLATED, DORMANT, FORBIDDEN, BLOCKED, DEFERRED)
    updated = dict(surface)
    updated["trust_zone"] = trust_zone_key
    updated["trust_zone_description"] = trust_zone["description"]
    updated["items"] = items
    updated["counts"] = {state: sum(1 for item in items if item["final_state"] == state) for state in states}
    updated["visible_surface"] = [item["capability_key"] for item in items if item["final_state"] in ADMITTED_STATES]
    updated["deferred_surface"] = [item["capability_key"] for item in items if item["final_state"] == DEFERRED]
    updated["surface_certificate"] = protection_certificate(updated)
    return updated


def resolve_trust_zone_surface(scenario_key: str, profile_key: str, request_key: str, policy_key: str, document_class_key: str, role_key: str, context_key: str, approval_key: str, release_mode_key: str, actor_key: str, job_state_key: str, retention_state_key: str, data_destination_key: str, device_health_key: str, risk_posture_key: str, compliance_mode_key: str, trust_zone_key: str) -> dict:
    surface = resolve_compliance_mode_surface(scenario_key, profile_key, request_key, policy_key, document_class_key, role_key, context_key, approval_key, release_mode_key, actor_key, job_state_key, retention_state_key, data_destination_key, device_health_key, risk_posture_key, compliance_mode_key)
    return apply_trust_zone_layer(surface, trust_zone_key)


def trust_zone_audit(policy_key: str = "standard", document_class_key: str = "public_document", role_key: str = "employee", context_key: str = "trusted_office_device", approval_key: str = "manager_approved", release_mode_key: str = "secure_pull_release", actor_key: str = "release_operator", job_state_key: str = "released_job", retention_state_key: str = "short_spool_retention", data_destination_key: str = "department_queue", device_health_key: str = "healthy_device", risk_posture_key: str = "normal_risk", compliance_mode_key: str = "ordinary_mode", scenario_key: str = "remote_print", profile_key: str = "connected", request_key: str = "normal") -> dict:
    blocks = []
    for trust_zone_key in TRUST_ZONE_ORDER:
        surface = resolve_trust_zone_surface(scenario_key, profile_key, request_key, policy_key, document_class_key, role_key, context_key, approval_key, release_mode_key, actor_key, job_state_key, retention_state_key, data_destination_key, device_health_key, risk_posture_key, compliance_mode_key, trust_zone_key)
        print_state = next(item for item in surface["items"] if item["capability_key"] == "print_engine")["final_state"]
        cloud_state = next(item for item in surface["items"] if item["capability_key"] == "cloud_print")["final_state"]
        remote_state = next(item for item in surface["items"] if item["capability_key"] == "remote_print_api")["final_state"]
        scan_state = next(item for item in surface["items"] if item["capability_key"] == "scan_to_email")["final_state"]
        cache_state = next(item for item in surface["items"] if item["capability_key"] == "document_cache")["final_state"]
        admin_state = next(item for item in surface["items"] if item["capability_key"] == "admin_console")["final_state"]
        firmware_state = next(item for item in surface["items"] if item["capability_key"] == "firmware_update")["final_state"]
        audit_state = next(item for item in surface["items"] if item["capability_key"] == "audit_logs")["final_state"]
        secure_state = next(item for item in surface["items"] if item["capability_key"] == "secure_release")["final_state"]
        block = {
            "trust_zone": trust_zone_key,
            "description": TRUST_ZONES[trust_zone_key]["description"],
            "surface_certificate": surface["surface_certificate"],
            "visible_surface": surface["visible_surface"],
            "deferred_surface": surface["deferred_surface"],
            "print_engine": print_state,
            "cloud_print": cloud_state,
            "remote_print_api": remote_state,
            "scan_to_email": scan_state,
            "document_cache": cache_state,
            "admin_console": admin_state,
            "firmware_update": firmware_state,
            "audit_logs": audit_state,
            "secure_release": secure_state,
        }
        block["trust_zone_certificate"] = protection_certificate(block)
        blocks.append(block)
    signatures = {block["trust_zone"]: (tuple(block["visible_surface"]), tuple(block["deferred_surface"])) for block in blocks}
    states = {block["trust_zone"]: (block["print_engine"], block["cloud_print"], block["remote_print_api"], block["scan_to_email"], block["document_cache"], block["admin_console"], block["firmware_update"], block["audit_logs"], block["secure_release"]) for block in blocks}
    checks = {
        "trust_zone_changes_visibility_outcome": len(set(signatures.values())) > 1,
        "local_trusted_zone_preserves_output": states["local_trusted_zone"][0] in ADMITTED_STATES,
        "department_zone_preserves_evidence": states["department_zone"][7] == ISOLATED,
        "enterprise_zone_preserves_audit": states["enterprise_zone"][7] == ISOLATED,
        "guest_zone_defers_output": states["guest_zone"][0] == DEFERRED,
        "vendor_zone_admits_service_visibility": states["vendor_zone"][5] == ISOLATED and states["vendor_zone"][6] == ISOLATED,
        "external_zone_preserves_evidence": states["external_zone"][7] == ISOLATED,
    }
    payload = {
        "project": PROJECT_NAME,
        "version": VERSION,
        "result": "PASS" if all(checks.values()) else "FAIL",
        "scenario": scenario_key,
        "profile": profile_key,
        "request": request_key,
        "policy": policy_key,
        "document_class": document_class_key,
        "role": role_key,
        "context": context_key,
        "approval": approval_key,
        "release_mode": release_mode_key,
        "actor": actor_key,
        "job_state": job_state_key,
        "retention_state": retention_state_key,
        "data_destination": data_destination_key,
        "device_health": device_health_key,
        "risk_posture": risk_posture_key,
        "compliance_mode": compliance_mode_key,
        "trust_zone_count": len(TRUST_ZONE_ORDER),
        "checks": checks,
        "blocks": blocks,
    }
    payload["trust_zone_audit_certificate"] = protection_certificate(payload)
    return payload



def apply_evidence_view_layer(surface: dict, evidence_view_key: str) -> dict:
    evidence_view = EVIDENCE_VIEWS[evidence_view_key]
    items = []
    for source_item in surface["items"]:
        item = dict(source_item)
        capability_key = item["capability_key"]
        state = item["final_state"]
        evidence_reason = None
        if evidence_view_key == "no_evidence_view":
            if capability_key in ("audit_logs", "document_cache") and state in ADMITTED_STATES:
                item["final_state"] = FORBIDDEN
                evidence_reason = "Evidence view keeps audit and cache visibility closed."
        elif evidence_view_key == "operator_evidence_view":
            if capability_key == "job_queue" and state in (FORBIDDEN, DORMANT, DEFERRED, BLOCKED):
                item["final_state"] = ISOLATED
                evidence_reason = "Evidence view admits bounded operator queue evidence."
            elif capability_key in ("audit_logs", "document_cache") and state in ADMITTED_STATES:
                item["final_state"] = FORBIDDEN
                evidence_reason = "Evidence view does not admit audit or cache evidence."
        elif evidence_view_key == "audit_evidence_view":
            if capability_key == "audit_logs" and state in (FORBIDDEN, DORMANT, DEFERRED, BLOCKED):
                item["final_state"] = ISOLATED
                evidence_reason = "Evidence view admits bounded audit evidence."
            elif capability_key == "document_cache" and state in ADMITTED_STATES:
                item["final_state"] = FORBIDDEN
                evidence_reason = "Evidence view keeps cache evidence closed."
        elif evidence_view_key == "records_evidence_view":
            if capability_key in ("job_queue", "audit_logs") and state in (FORBIDDEN, DORMANT, DEFERRED, BLOCKED):
                item["final_state"] = ISOLATED
                evidence_reason = "Evidence view admits records queue or audit evidence."
            elif capability_key == "document_cache" and state in ADMITTED_STATES:
                item["final_state"] = FORBIDDEN
                evidence_reason = "Evidence view keeps cache evidence governed separately."
        elif evidence_view_key == "incident_evidence_view":
            if capability_key in ("print_engine", "paper_feed", "ink_toner_system", "cloud_print", "remote_print_api", "scan_to_email", "fax_module", "secure_release") and state in ADMITTED_STATES:
                item["final_state"] = DEFERRED
                evidence_reason = "Evidence view defers movement, release, and physical output while incident evidence is reviewed."
            elif capability_key in ("job_queue", "audit_logs", "document_cache") and state in (FORBIDDEN, DORMANT, DEFERRED, BLOCKED):
                item["final_state"] = ISOLATED
                evidence_reason = "Evidence view preserves incident queue, audit, or cache evidence."
        elif evidence_view_key == "legal_evidence_view":
            if capability_key in ("print_engine", "paper_feed", "ink_toner_system", "cloud_print", "remote_print_api", "scan_to_email", "fax_module", "secure_release") and state in ADMITTED_STATES:
                item["final_state"] = DEFERRED
                evidence_reason = "Evidence view defers movement, release, and physical output while legal evidence is preserved."
            elif capability_key in ("job_queue", "audit_logs", "document_cache") and state in (FORBIDDEN, DORMANT, DEFERRED, BLOCKED):
                item["final_state"] = ISOLATED
                evidence_reason = "Evidence view preserves legal queue, audit, or cache evidence."
        item["evidence_view"] = evidence_view_key
        item["evidence_view_description"] = evidence_view["description"]
        item["evidence_view_applied"] = evidence_reason is not None
        if evidence_reason is not None:
            item["reason"] = evidence_reason
        item["certificate"] = protection_certificate(item)
        items.append(item)
    states = (VISIBLE, ISOLATED, DORMANT, FORBIDDEN, BLOCKED, DEFERRED)
    updated = dict(surface)
    updated["evidence_view"] = evidence_view_key
    updated["evidence_view_description"] = evidence_view["description"]
    updated["items"] = items
    updated["counts"] = {state: sum(1 for item in items if item["final_state"] == state) for state in states}
    updated["visible_surface"] = [item["capability_key"] for item in items if item["final_state"] in ADMITTED_STATES]
    updated["deferred_surface"] = [item["capability_key"] for item in items if item["final_state"] == DEFERRED]
    updated["surface_certificate"] = protection_certificate(updated)
    return updated


def resolve_evidence_view_surface(scenario_key: str, profile_key: str, request_key: str, policy_key: str, document_class_key: str, role_key: str, context_key: str, approval_key: str, release_mode_key: str, actor_key: str, job_state_key: str, retention_state_key: str, data_destination_key: str, device_health_key: str, risk_posture_key: str, compliance_mode_key: str, trust_zone_key: str, evidence_view_key: str) -> dict:
    surface = resolve_trust_zone_surface(scenario_key, profile_key, request_key, policy_key, document_class_key, role_key, context_key, approval_key, release_mode_key, actor_key, job_state_key, retention_state_key, data_destination_key, device_health_key, risk_posture_key, compliance_mode_key, trust_zone_key)
    return apply_evidence_view_layer(surface, evidence_view_key)


def evidence_view_audit(policy_key: str = "standard", document_class_key: str = "public_document", role_key: str = "employee", context_key: str = "trusted_office_device", approval_key: str = "manager_approved", release_mode_key: str = "secure_pull_release", actor_key: str = "release_operator", job_state_key: str = "released_job", retention_state_key: str = "short_spool_retention", data_destination_key: str = "department_queue", device_health_key: str = "healthy_device", risk_posture_key: str = "normal_risk", compliance_mode_key: str = "ordinary_mode", trust_zone_key: str = "local_trusted_zone", scenario_key: str = "remote_print", profile_key: str = "connected", request_key: str = "normal") -> dict:
    blocks = []
    for evidence_view_key in EVIDENCE_VIEW_ORDER:
        surface = resolve_evidence_view_surface(scenario_key, profile_key, request_key, policy_key, document_class_key, role_key, context_key, approval_key, release_mode_key, actor_key, job_state_key, retention_state_key, data_destination_key, device_health_key, risk_posture_key, compliance_mode_key, trust_zone_key, evidence_view_key)
        print_state = next(item for item in surface["items"] if item["capability_key"] == "print_engine")["final_state"]
        cloud_state = next(item for item in surface["items"] if item["capability_key"] == "cloud_print")["final_state"]
        remote_state = next(item for item in surface["items"] if item["capability_key"] == "remote_print_api")["final_state"]
        cache_state = next(item for item in surface["items"] if item["capability_key"] == "document_cache")["final_state"]
        audit_state = next(item for item in surface["items"] if item["capability_key"] == "audit_logs")["final_state"]
        queue_state = next(item for item in surface["items"] if item["capability_key"] == "job_queue")["final_state"]
        secure_state = next(item for item in surface["items"] if item["capability_key"] == "secure_release")["final_state"]
        block = {
            "evidence_view": evidence_view_key,
            "description": EVIDENCE_VIEWS[evidence_view_key]["description"],
            "surface_certificate": surface["surface_certificate"],
            "visible_surface": surface["visible_surface"],
            "deferred_surface": surface["deferred_surface"],
            "print_engine": print_state,
            "cloud_print": cloud_state,
            "remote_print_api": remote_state,
            "document_cache": cache_state,
            "audit_logs": audit_state,
            "job_queue": queue_state,
            "secure_release": secure_state,
        }
        block["evidence_view_certificate"] = protection_certificate(block)
        blocks.append(block)
    signatures = {block["evidence_view"]: (tuple(block["visible_surface"]), tuple(block["deferred_surface"])) for block in blocks}
    states = {block["evidence_view"]: (block["print_engine"], block["cloud_print"], block["remote_print_api"], block["document_cache"], block["audit_logs"], block["job_queue"], block["secure_release"]) for block in blocks}
    checks = {
        "evidence_view_changes_visibility_outcome": len(set(signatures.values())) > 1,
        "no_evidence_view_keeps_cache_closed": states["no_evidence_view"][3] == FORBIDDEN,
        "operator_evidence_view_admits_queue": states["operator_evidence_view"][5] == ISOLATED,
        "audit_evidence_view_admits_audit": states["audit_evidence_view"][4] == ISOLATED,
        "records_evidence_view_preserves_queue_and_audit": states["records_evidence_view"][5] == ISOLATED and states["records_evidence_view"][4] == ISOLATED,
        "incident_evidence_view_preserves_cache": states["incident_evidence_view"][3] == ISOLATED,
        "legal_evidence_view_preserves_cache": states["legal_evidence_view"][3] == ISOLATED,
    }
    payload = {
        "project": PROJECT_NAME,
        "version": VERSION,
        "result": "PASS" if all(checks.values()) else "FAIL",
        "scenario": scenario_key,
        "profile": profile_key,
        "request": request_key,
        "policy": policy_key,
        "document_class": document_class_key,
        "role": role_key,
        "context": context_key,
        "approval": approval_key,
        "release_mode": release_mode_key,
        "actor": actor_key,
        "job_state": job_state_key,
        "retention_state": retention_state_key,
        "data_destination": data_destination_key,
        "device_health": device_health_key,
        "risk_posture": risk_posture_key,
        "compliance_mode": compliance_mode_key,
        "trust_zone": trust_zone_key,
        "evidence_view_count": len(EVIDENCE_VIEW_ORDER),
        "checks": checks,
        "blocks": blocks,
    }
    payload["evidence_view_audit_certificate"] = protection_certificate(payload)
    return payload



def apply_recovery_action_layer(surface: dict, recovery_action_key: str) -> dict:
    recovery_action = RECOVERY_ACTIONS[recovery_action_key]
    items = []
    for source_item in surface["items"]:
        item = dict(source_item)
        capability_key = item["capability_key"]
        state = item["final_state"]
        recovery_reason = None
        if recovery_action_key == "no_recovery_action":
            pass
        elif recovery_action_key == "retry_job":
            if capability_key == "job_queue" and state in (FORBIDDEN, DORMANT, DEFERRED, BLOCKED):
                item["final_state"] = ISOLATED
                recovery_reason = "Recovery action preserves queue visibility for retry handling."
            elif capability_key in ("document_cache", "admin_console", "firmware_update") and state in ADMITTED_STATES:
                item["final_state"] = DEFERRED
                recovery_reason = "Recovery action does not admit cache or service-change visibility."
        elif recovery_action_key == "requeue_job":
            if capability_key == "job_queue" and state in (FORBIDDEN, DORMANT, DEFERRED, BLOCKED):
                item["final_state"] = ISOLATED
                recovery_reason = "Recovery action admits bounded queue handling for requeue."
            elif capability_key in ("print_engine", "paper_feed", "ink_toner_system", "cloud_print", "remote_print_api", "scan_to_email", "fax_module", "secure_release") and state in ADMITTED_STATES:
                item["final_state"] = DEFERRED
                recovery_reason = "Recovery action defers movement, release, and physical output until requeue is resolved."
        elif recovery_action_key == "purge_job":
            if capability_key in ("print_engine", "paper_feed", "ink_toner_system", "cloud_print", "remote_print_api", "scan_to_email", "fax_module", "secure_release", "document_cache") and state in ADMITTED_STATES:
                item["final_state"] = FORBIDDEN
                recovery_reason = "Recovery action closes output, movement, release, and cache visibility."
            elif capability_key == "audit_logs" and state in (FORBIDDEN, DORMANT, DEFERRED, BLOCKED):
                item["final_state"] = ISOLATED
                recovery_reason = "Recovery action preserves bounded audit evidence for purge review."
            elif capability_key == "job_queue" and state in ADMITTED_STATES:
                item["final_state"] = DORMANT
                recovery_reason = "Recovery action closes active queue visibility after purge."
        elif recovery_action_key == "restore_job":
            if capability_key in ("job_queue", "audit_logs") and state in (FORBIDDEN, DORMANT, DEFERRED, BLOCKED):
                item["final_state"] = ISOLATED
                recovery_reason = "Recovery action admits bounded queue or audit visibility for restoration."
            elif capability_key in ("print_engine", "paper_feed", "ink_toner_system", "cloud_print", "remote_print_api", "scan_to_email", "fax_module", "secure_release") and state in ADMITTED_STATES:
                item["final_state"] = DEFERRED
                recovery_reason = "Recovery action keeps movement, release, and physical output pending after restoration."
        elif recovery_action_key == "escalate_review":
            if capability_key in ("print_engine", "paper_feed", "ink_toner_system", "cloud_print", "remote_print_api", "scan_to_email", "fax_module", "secure_release") and state in ADMITTED_STATES:
                item["final_state"] = DEFERRED
                recovery_reason = "Recovery action defers movement, release, and physical output during review."
            elif capability_key in ("job_queue", "audit_logs", "document_cache") and state in (FORBIDDEN, DORMANT, DEFERRED, BLOCKED):
                item["final_state"] = ISOLATED
                recovery_reason = "Recovery action preserves queue, audit, or cache evidence for review."
        item["recovery_action"] = recovery_action_key
        item["recovery_action_description"] = recovery_action["description"]
        item["recovery_action_applied"] = recovery_reason is not None
        if recovery_reason is not None:
            item["reason"] = recovery_reason
        item["certificate"] = protection_certificate(item)
        items.append(item)
    states = (VISIBLE, ISOLATED, DORMANT, FORBIDDEN, BLOCKED, DEFERRED)
    updated = dict(surface)
    updated["recovery_action"] = recovery_action_key
    updated["recovery_action_description"] = recovery_action["description"]
    updated["items"] = items
    updated["counts"] = {state: sum(1 for item in items if item["final_state"] == state) for state in states}
    updated["visible_surface"] = [item["capability_key"] for item in items if item["final_state"] in ADMITTED_STATES]
    updated["deferred_surface"] = [item["capability_key"] for item in items if item["final_state"] == DEFERRED]
    updated["surface_certificate"] = protection_certificate(updated)
    return updated


def resolve_recovery_action_surface(scenario_key: str, profile_key: str, request_key: str, policy_key: str, document_class_key: str, role_key: str, context_key: str, approval_key: str, release_mode_key: str, actor_key: str, job_state_key: str, retention_state_key: str, data_destination_key: str, device_health_key: str, risk_posture_key: str, compliance_mode_key: str, trust_zone_key: str, evidence_view_key: str, recovery_action_key: str) -> dict:
    surface = resolve_evidence_view_surface(scenario_key, profile_key, request_key, policy_key, document_class_key, role_key, context_key, approval_key, release_mode_key, actor_key, job_state_key, retention_state_key, data_destination_key, device_health_key, risk_posture_key, compliance_mode_key, trust_zone_key, evidence_view_key)
    return apply_recovery_action_layer(surface, recovery_action_key)


def recovery_action_audit(policy_key: str = "standard", document_class_key: str = "public_document", role_key: str = "employee", context_key: str = "trusted_office_device", approval_key: str = "manager_approved", release_mode_key: str = "secure_pull_release", actor_key: str = "release_operator", job_state_key: str = "released_job", retention_state_key: str = "short_spool_retention", data_destination_key: str = "department_queue", device_health_key: str = "healthy_device", risk_posture_key: str = "normal_risk", compliance_mode_key: str = "ordinary_mode", trust_zone_key: str = "local_trusted_zone", evidence_view_key: str = "operator_evidence_view", scenario_key: str = "remote_print", profile_key: str = "connected", request_key: str = "normal") -> dict:
    blocks = []
    for recovery_action_key in RECOVERY_ACTION_ORDER:
        surface = resolve_recovery_action_surface(scenario_key, profile_key, request_key, policy_key, document_class_key, role_key, context_key, approval_key, release_mode_key, actor_key, job_state_key, retention_state_key, data_destination_key, device_health_key, risk_posture_key, compliance_mode_key, trust_zone_key, evidence_view_key, recovery_action_key)
        print_state = next(item for item in surface["items"] if item["capability_key"] == "print_engine")["final_state"]
        cloud_state = next(item for item in surface["items"] if item["capability_key"] == "cloud_print")["final_state"]
        remote_state = next(item for item in surface["items"] if item["capability_key"] == "remote_print_api")["final_state"]
        cache_state = next(item for item in surface["items"] if item["capability_key"] == "document_cache")["final_state"]
        audit_state = next(item for item in surface["items"] if item["capability_key"] == "audit_logs")["final_state"]
        queue_state = next(item for item in surface["items"] if item["capability_key"] == "job_queue")["final_state"]
        secure_state = next(item for item in surface["items"] if item["capability_key"] == "secure_release")["final_state"]
        block = {
            "recovery_action": recovery_action_key,
            "description": RECOVERY_ACTIONS[recovery_action_key]["description"],
            "surface_certificate": surface["surface_certificate"],
            "visible_surface": surface["visible_surface"],
            "deferred_surface": surface["deferred_surface"],
            "print_engine": print_state,
            "cloud_print": cloud_state,
            "remote_print_api": remote_state,
            "document_cache": cache_state,
            "audit_logs": audit_state,
            "job_queue": queue_state,
            "secure_release": secure_state,
        }
        block["recovery_action_certificate"] = protection_certificate(block)
        blocks.append(block)
    signatures = {block["recovery_action"]: (tuple(block["visible_surface"]), tuple(block["deferred_surface"])) for block in blocks}
    states = {block["recovery_action"]: (block["print_engine"], block["cloud_print"], block["remote_print_api"], block["document_cache"], block["audit_logs"], block["job_queue"], block["secure_release"]) for block in blocks}
    checks = {
        "recovery_action_changes_visibility_outcome": len(set(signatures.values())) > 1,
        "retry_job_preserves_queue": states["retry_job"][5] == ISOLATED,
        "requeue_job_defers_output": states["requeue_job"][0] == DEFERRED,
        "purge_job_closes_active_queue": states["purge_job"][5] in (DORMANT, FORBIDDEN),
        "purge_job_preserves_audit": states["purge_job"][4] == ISOLATED,
        "restore_job_preserves_queue_or_audit": states["restore_job"][5] == ISOLATED or states["restore_job"][4] == ISOLATED,
        "escalate_review_preserves_cache": states["escalate_review"][3] == ISOLATED,
    }
    payload = {
        "project": PROJECT_NAME,
        "version": VERSION,
        "result": "PASS" if all(checks.values()) else "FAIL",
        "scenario": scenario_key,
        "profile": profile_key,
        "request": request_key,
        "policy": policy_key,
        "document_class": document_class_key,
        "role": role_key,
        "context": context_key,
        "approval": approval_key,
        "release_mode": release_mode_key,
        "actor": actor_key,
        "job_state": job_state_key,
        "retention_state": retention_state_key,
        "data_destination": data_destination_key,
        "device_health": device_health_key,
        "risk_posture": risk_posture_key,
        "compliance_mode": compliance_mode_key,
        "trust_zone": trust_zone_key,
        "evidence_view": evidence_view_key,
        "recovery_action_count": len(RECOVERY_ACTION_ORDER),
        "checks": checks,
        "blocks": blocks,
    }
    payload["recovery_action_audit_certificate"] = protection_certificate(payload)
    return payload


def apply_transfer_boundary_layer(surface: dict, transfer_boundary_key: str) -> dict:
    transfer_boundary = TRANSFER_BOUNDARIES[transfer_boundary_key]
    items = []
    for source_item in surface["items"]:
        item = dict(source_item)
        capability_key = item["capability_key"]
        state = item["final_state"]
        transfer_reason = None
        if transfer_boundary_key == "no_transfer":
            if capability_key in ("cloud_print", "remote_print_api", "scan_to_email", "fax_module") and state in ADMITTED_STATES:
                item["final_state"] = DEFERRED
                transfer_reason = "Transfer boundary does not admit document or job movement visibility."
            elif capability_key == "document_cache" and state in ADMITTED_STATES:
                item["final_state"] = FORBIDDEN
                transfer_reason = "Transfer boundary keeps cache visibility closed without transfer scope."
        elif transfer_boundary_key == "same_device_transfer":
            if capability_key in ("cloud_print", "remote_print_api", "scan_to_email", "fax_module") and state in ADMITTED_STATES:
                item["final_state"] = DEFERRED
                transfer_reason = "Transfer boundary keeps movement inside the same device."
            elif capability_key in ("job_queue", "secure_release") and state in (FORBIDDEN, DORMANT, DEFERRED, BLOCKED):
                item["final_state"] = ISOLATED
                transfer_reason = "Transfer boundary admits bounded same-device queue or release visibility."
        elif transfer_boundary_key == "same_department_transfer":
            if capability_key in ("cloud_print", "remote_print_api", "job_queue") and state in (FORBIDDEN, DORMANT, DEFERRED, BLOCKED):
                item["final_state"] = ISOLATED
                transfer_reason = "Transfer boundary admits bounded department transfer visibility."
            elif capability_key in ("scan_to_email", "fax_module") and state in ADMITTED_STATES:
                item["final_state"] = DEFERRED
                transfer_reason = "Transfer boundary does not admit external export visibility."
        elif transfer_boundary_key == "enterprise_transfer":
            if capability_key in ("cloud_print", "remote_print_api", "job_queue", "audit_logs") and state in (FORBIDDEN, DORMANT, DEFERRED, BLOCKED):
                item["final_state"] = ISOLATED
                transfer_reason = "Transfer boundary admits bounded enterprise routing or audit visibility."
            elif capability_key in ("document_cache", "fax_module") and state in ADMITTED_STATES:
                item["final_state"] = DEFERRED
                transfer_reason = "Transfer boundary keeps cache or legacy export governed separately."
        elif transfer_boundary_key == "vendor_transfer":
            if capability_key in ("admin_console", "firmware_update", "audit_logs", "supply_monitor") and state in (FORBIDDEN, DORMANT, DEFERRED, BLOCKED):
                item["final_state"] = ISOLATED
                transfer_reason = "Transfer boundary admits bounded vendor service visibility."
            elif capability_key in ("print_engine", "paper_feed", "ink_toner_system", "cloud_print", "remote_print_api", "scan_to_email", "fax_module", "secure_release", "document_cache") and state in ADMITTED_STATES:
                item["final_state"] = DEFERRED
                transfer_reason = "Transfer boundary defers document movement, output, release, and cache visibility for vendor transfer."
        elif transfer_boundary_key == "external_transfer":
            if capability_key in ("print_engine", "paper_feed", "ink_toner_system", "cloud_print", "remote_print_api", "scan_to_email", "fax_module", "secure_release", "document_cache") and state in ADMITTED_STATES:
                item["final_state"] = DEFERRED
                transfer_reason = "Transfer boundary defers external document movement, release, output, and cache visibility."
            elif capability_key in ("audit_logs", "job_queue") and state in (FORBIDDEN, DORMANT, DEFERRED, BLOCKED):
                item["final_state"] = ISOLATED
                transfer_reason = "Transfer boundary preserves bounded evidence for external transfer review."
        item["transfer_boundary"] = transfer_boundary_key
        item["transfer_boundary_description"] = transfer_boundary["description"]
        item["transfer_boundary_applied"] = transfer_reason is not None
        if transfer_reason is not None:
            item["reason"] = transfer_reason
        item["certificate"] = protection_certificate(item)
        items.append(item)
    states = (VISIBLE, ISOLATED, DORMANT, FORBIDDEN, BLOCKED, DEFERRED)
    updated = dict(surface)
    updated["transfer_boundary"] = transfer_boundary_key
    updated["transfer_boundary_description"] = transfer_boundary["description"]
    updated["items"] = items
    updated["counts"] = {state: sum(1 for item in items if item["final_state"] == state) for state in states}
    updated["visible_surface"] = [item["capability_key"] for item in items if item["final_state"] in ADMITTED_STATES]
    updated["deferred_surface"] = [item["capability_key"] for item in items if item["final_state"] == DEFERRED]
    updated["surface_certificate"] = protection_certificate(updated)
    return updated


def resolve_transfer_boundary_surface(scenario_key: str, profile_key: str, request_key: str, policy_key: str, document_class_key: str, role_key: str, context_key: str, approval_key: str, release_mode_key: str, actor_key: str, job_state_key: str, retention_state_key: str, data_destination_key: str, device_health_key: str, risk_posture_key: str, compliance_mode_key: str, trust_zone_key: str, evidence_view_key: str, recovery_action_key: str, transfer_boundary_key: str) -> dict:
    surface = resolve_recovery_action_surface(scenario_key, profile_key, request_key, policy_key, document_class_key, role_key, context_key, approval_key, release_mode_key, actor_key, job_state_key, retention_state_key, data_destination_key, device_health_key, risk_posture_key, compliance_mode_key, trust_zone_key, evidence_view_key, recovery_action_key)
    return apply_transfer_boundary_layer(surface, transfer_boundary_key)


def transfer_boundary_audit(policy_key: str = "standard", document_class_key: str = "public_document", role_key: str = "employee", context_key: str = "trusted_office_device", approval_key: str = "manager_approved", release_mode_key: str = "secure_pull_release", actor_key: str = "release_operator", job_state_key: str = "released_job", retention_state_key: str = "short_spool_retention", data_destination_key: str = "department_queue", device_health_key: str = "healthy_device", risk_posture_key: str = "normal_risk", compliance_mode_key: str = "ordinary_mode", trust_zone_key: str = "local_trusted_zone", evidence_view_key: str = "operator_evidence_view", recovery_action_key: str = "no_recovery_action", scenario_key: str = "remote_print", profile_key: str = "connected", request_key: str = "normal") -> dict:
    blocks = []
    for transfer_boundary_key in TRANSFER_BOUNDARY_ORDER:
        surface = resolve_transfer_boundary_surface(scenario_key, profile_key, request_key, policy_key, document_class_key, role_key, context_key, approval_key, release_mode_key, actor_key, job_state_key, retention_state_key, data_destination_key, device_health_key, risk_posture_key, compliance_mode_key, trust_zone_key, evidence_view_key, recovery_action_key, transfer_boundary_key)
        print_state = next(item for item in surface["items"] if item["capability_key"] == "print_engine")["final_state"]
        cloud_state = next(item for item in surface["items"] if item["capability_key"] == "cloud_print")["final_state"]
        remote_state = next(item for item in surface["items"] if item["capability_key"] == "remote_print_api")["final_state"]
        scan_state = next(item for item in surface["items"] if item["capability_key"] == "scan_to_email")["final_state"]
        cache_state = next(item for item in surface["items"] if item["capability_key"] == "document_cache")["final_state"]
        admin_state = next(item for item in surface["items"] if item["capability_key"] == "admin_console")["final_state"]
        firmware_state = next(item for item in surface["items"] if item["capability_key"] == "firmware_update")["final_state"]
        audit_state = next(item for item in surface["items"] if item["capability_key"] == "audit_logs")["final_state"]
        queue_state = next(item for item in surface["items"] if item["capability_key"] == "job_queue")["final_state"]
        secure_state = next(item for item in surface["items"] if item["capability_key"] == "secure_release")["final_state"]
        block = {
            "transfer_boundary": transfer_boundary_key,
            "description": TRANSFER_BOUNDARIES[transfer_boundary_key]["description"],
            "surface_certificate": surface["surface_certificate"],
            "visible_surface": surface["visible_surface"],
            "deferred_surface": surface["deferred_surface"],
            "print_engine": print_state,
            "cloud_print": cloud_state,
            "remote_print_api": remote_state,
            "scan_to_email": scan_state,
            "document_cache": cache_state,
            "admin_console": admin_state,
            "firmware_update": firmware_state,
            "audit_logs": audit_state,
            "job_queue": queue_state,
            "secure_release": secure_state,
        }
        block["transfer_boundary_certificate"] = protection_certificate(block)
        blocks.append(block)
    signatures = {block["transfer_boundary"]: (tuple(block["visible_surface"]), tuple(block["deferred_surface"])) for block in blocks}
    states = {block["transfer_boundary"]: (block["print_engine"], block["cloud_print"], block["remote_print_api"], block["scan_to_email"], block["document_cache"], block["admin_console"], block["firmware_update"], block["audit_logs"], block["job_queue"], block["secure_release"]) for block in blocks}
    checks = {
        "transfer_boundary_changes_visibility_outcome": len(set(signatures.values())) > 1,
        "no_transfer_defers_remote_movement": states["no_transfer"][1] in (DEFERRED, FORBIDDEN),
        "same_device_transfer_preserves_local_queue_or_release": states["same_device_transfer"][8] == ISOLATED or states["same_device_transfer"][9] == ISOLATED,
        "same_department_transfer_admits_department_routing": states["same_department_transfer"][1] == ISOLATED or states["same_department_transfer"][2] == ISOLATED,
        "enterprise_transfer_admits_audit_or_routing": states["enterprise_transfer"][7] == ISOLATED or states["enterprise_transfer"][1] == ISOLATED or states["enterprise_transfer"][2] == ISOLATED,
        "vendor_transfer_admits_service_visibility": states["vendor_transfer"][5] == ISOLATED or states["vendor_transfer"][6] == ISOLATED,
        "external_transfer_preserves_evidence": states["external_transfer"][7] == ISOLATED or states["external_transfer"][8] == ISOLATED,
    }
    payload = {
        "project": PROJECT_NAME,
        "version": VERSION,
        "result": "PASS" if all(checks.values()) else "FAIL",
        "scenario": scenario_key,
        "profile": profile_key,
        "request": request_key,
        "policy": policy_key,
        "document_class": document_class_key,
        "role": role_key,
        "context": context_key,
        "approval": approval_key,
        "release_mode": release_mode_key,
        "actor": actor_key,
        "job_state": job_state_key,
        "retention_state": retention_state_key,
        "data_destination": data_destination_key,
        "device_health": device_health_key,
        "risk_posture": risk_posture_key,
        "compliance_mode": compliance_mode_key,
        "trust_zone": trust_zone_key,
        "evidence_view": evidence_view_key,
        "recovery_action": recovery_action_key,
        "transfer_boundary_count": len(TRANSFER_BOUNDARY_ORDER),
        "checks": checks,
        "blocks": blocks,
    }
    payload["transfer_boundary_audit_certificate"] = protection_certificate(payload)
    return payload


def apply_custody_state_layer(surface: dict, custody_state_key: str) -> dict:
    custody_state = CUSTODY_STATES[custody_state_key]
    items = []
    for source_item in surface["items"]:
        item = dict(source_item)
        capability_key = item["capability_key"]
        state = item["final_state"]
        custody_reason = None
        if custody_state_key == "no_custody":
            if capability_key in ("document_cache", "audit_logs") and state in ADMITTED_STATES:
                item["final_state"] = DEFERRED
                custody_reason = "Custody state does not admit evidence visibility beyond the existing active structure."
            elif capability_key in ("cloud_print", "remote_print_api", "scan_to_email", "fax_module") and state in ADMITTED_STATES:
                item["final_state"] = DEFERRED
                custody_reason = "Custody state does not admit document or job movement visibility."
        elif custody_state_key == "operator_custody":
            if capability_key in ("print_engine", "paper_feed", "ink_toner_system", "job_queue", "secure_release") and state in (FORBIDDEN, DORMANT, DEFERRED, BLOCKED):
                item["final_state"] = ISOLATED if capability_key in ("job_queue", "secure_release") else VISIBLE
                custody_reason = "Custody state admits bounded operator handling or local release visibility."
            elif capability_key in ("document_cache", "scan_to_email", "fax_module") and state in ADMITTED_STATES:
                item["final_state"] = DEFERRED
                custody_reason = "Custody state keeps cache and export visibility governed separately."
        elif custody_state_key == "department_custody":
            if capability_key in ("job_queue", "audit_logs", "cloud_print", "remote_print_api") and state in (FORBIDDEN, DORMANT, DEFERRED, BLOCKED):
                item["final_state"] = ISOLATED
                custody_reason = "Custody state admits bounded department custody visibility."
            elif capability_key in ("scan_to_email", "fax_module", "document_cache") and state in ADMITTED_STATES:
                item["final_state"] = DEFERRED
                custody_reason = "Custody state keeps export and cache visibility governed separately."
        elif custody_state_key == "records_custody":
            if capability_key in ("job_queue", "secure_release", "audit_logs") and state in (FORBIDDEN, DORMANT, DEFERRED, BLOCKED):
                item["final_state"] = ISOLATED
                custody_reason = "Custody state admits records-grade queue, release, or audit visibility."
            elif capability_key in ("cloud_print", "remote_print_api", "scan_to_email", "fax_module") and state in ADMITTED_STATES:
                item["final_state"] = DEFERRED
                custody_reason = "Custody state narrows document movement under records responsibility."
        elif custody_state_key == "incident_custody":
            if capability_key in ("job_queue", "document_cache", "audit_logs") and state in (FORBIDDEN, DORMANT, DEFERRED, BLOCKED):
                item["final_state"] = ISOLATED
                custody_reason = "Custody state preserves incident queue, audit, or cache evidence."
            elif capability_key in ("print_engine", "paper_feed", "ink_toner_system", "cloud_print", "remote_print_api", "scan_to_email", "fax_module", "secure_release") and state in ADMITTED_STATES:
                item["final_state"] = DEFERRED
                custody_reason = "Custody state defers movement, release, and physical output during incident custody."
        elif custody_state_key == "legal_custody":
            if capability_key in ("job_queue", "document_cache", "audit_logs") and state in (FORBIDDEN, DORMANT, DEFERRED, BLOCKED):
                item["final_state"] = ISOLATED
                custody_reason = "Custody state preserves legal queue, audit, or cache evidence."
            elif capability_key in ("print_engine", "paper_feed", "ink_toner_system", "cloud_print", "remote_print_api", "scan_to_email", "fax_module", "secure_release") and state in ADMITTED_STATES:
                item["final_state"] = DEFERRED
                custody_reason = "Custody state holds movement, release, and physical output closed during legal custody."
        item["custody_state"] = custody_state_key
        item["custody_state_description"] = custody_state["description"]
        item["custody_state_applied"] = custody_reason is not None
        if custody_reason is not None:
            item["reason"] = custody_reason
        item["certificate"] = protection_certificate(item)
        items.append(item)
    states = (VISIBLE, ISOLATED, DORMANT, FORBIDDEN, BLOCKED, DEFERRED)
    updated = dict(surface)
    updated["custody_state"] = custody_state_key
    updated["custody_state_description"] = custody_state["description"]
    updated["items"] = items
    updated["counts"] = {state: sum(1 for item in items if item["final_state"] == state) for state in states}
    updated["visible_surface"] = [item["capability_key"] for item in items if item["final_state"] in ADMITTED_STATES]
    updated["deferred_surface"] = [item["capability_key"] for item in items if item["final_state"] == DEFERRED]
    updated["surface_certificate"] = protection_certificate(updated)
    return updated


def resolve_custody_state_surface(scenario_key: str, profile_key: str, request_key: str, policy_key: str, document_class_key: str, role_key: str, context_key: str, approval_key: str, release_mode_key: str, actor_key: str, job_state_key: str, retention_state_key: str, data_destination_key: str, device_health_key: str, risk_posture_key: str, compliance_mode_key: str, trust_zone_key: str, evidence_view_key: str, recovery_action_key: str, transfer_boundary_key: str, custody_state_key: str) -> dict:
    surface = resolve_transfer_boundary_surface(scenario_key, profile_key, request_key, policy_key, document_class_key, role_key, context_key, approval_key, release_mode_key, actor_key, job_state_key, retention_state_key, data_destination_key, device_health_key, risk_posture_key, compliance_mode_key, trust_zone_key, evidence_view_key, recovery_action_key, transfer_boundary_key)
    return apply_custody_state_layer(surface, custody_state_key)


def custody_state_audit(policy_key: str = "standard", document_class_key: str = "public_document", role_key: str = "employee", context_key: str = "trusted_office_device", approval_key: str = "manager_approved", release_mode_key: str = "secure_pull_release", actor_key: str = "release_operator", job_state_key: str = "released_job", retention_state_key: str = "short_spool_retention", data_destination_key: str = "department_queue", device_health_key: str = "healthy_device", risk_posture_key: str = "normal_risk", compliance_mode_key: str = "ordinary_mode", trust_zone_key: str = "local_trusted_zone", evidence_view_key: str = "operator_evidence_view", recovery_action_key: str = "no_recovery_action", transfer_boundary_key: str = "no_transfer", scenario_key: str = "remote_print", profile_key: str = "connected", request_key: str = "normal") -> dict:
    blocks = []
    for custody_state_key in CUSTODY_STATE_ORDER:
        surface = resolve_custody_state_surface(scenario_key, profile_key, request_key, policy_key, document_class_key, role_key, context_key, approval_key, release_mode_key, actor_key, job_state_key, retention_state_key, data_destination_key, device_health_key, risk_posture_key, compliance_mode_key, trust_zone_key, evidence_view_key, recovery_action_key, transfer_boundary_key, custody_state_key)
        print_state = next(item for item in surface["items"] if item["capability_key"] == "print_engine")["final_state"]
        cloud_state = next(item for item in surface["items"] if item["capability_key"] == "cloud_print")["final_state"]
        remote_state = next(item for item in surface["items"] if item["capability_key"] == "remote_print_api")["final_state"]
        cache_state = next(item for item in surface["items"] if item["capability_key"] == "document_cache")["final_state"]
        admin_state = next(item for item in surface["items"] if item["capability_key"] == "admin_console")["final_state"]
        firmware_state = next(item for item in surface["items"] if item["capability_key"] == "firmware_update")["final_state"]
        audit_state = next(item for item in surface["items"] if item["capability_key"] == "audit_logs")["final_state"]
        queue_state = next(item for item in surface["items"] if item["capability_key"] == "job_queue")["final_state"]
        secure_state = next(item for item in surface["items"] if item["capability_key"] == "secure_release")["final_state"]
        block = {
            "custody_state": custody_state_key,
            "description": CUSTODY_STATES[custody_state_key]["description"],
            "surface_certificate": surface["surface_certificate"],
            "visible_surface": surface["visible_surface"],
            "deferred_surface": surface["deferred_surface"],
            "print_engine": print_state,
            "cloud_print": cloud_state,
            "remote_print_api": remote_state,
            "document_cache": cache_state,
            "admin_console": admin_state,
            "firmware_update": firmware_state,
            "audit_logs": audit_state,
            "job_queue": queue_state,
            "secure_release": secure_state,
        }
        block["custody_state_certificate"] = protection_certificate(block)
        blocks.append(block)
    signatures = {block["custody_state"]: (tuple(block["visible_surface"]), tuple(block["deferred_surface"])) for block in blocks}
    states = {block["custody_state"]: (block["print_engine"], block["cloud_print"], block["remote_print_api"], block["document_cache"], block["admin_console"], block["firmware_update"], block["audit_logs"], block["job_queue"], block["secure_release"]) for block in blocks}
    checks = {
        "custody_state_changes_visibility_outcome": len(set(signatures.values())) > 1,
        "no_custody_limits_evidence": states["no_custody"][3] in (DEFERRED, FORBIDDEN) and states["no_custody"][6] in (DEFERRED, FORBIDDEN, ISOLATED),
        "operator_custody_admits_local_handling": states["operator_custody"][0] in (VISIBLE, ISOLATED, DEFERRED) and states["operator_custody"][7] == ISOLATED,
        "department_custody_admits_queue_or_audit": states["department_custody"][7] == ISOLATED or states["department_custody"][6] == ISOLATED,
        "records_custody_admits_records_evidence": states["records_custody"][6] == ISOLATED and states["records_custody"][7] == ISOLATED,
        "incident_custody_preserves_cache_or_audit": states["incident_custody"][3] == ISOLATED or states["incident_custody"][6] == ISOLATED,
        "legal_custody_preserves_hold_evidence": states["legal_custody"][3] == ISOLATED and states["legal_custody"][6] == ISOLATED,
    }
    payload = {
        "project": PROJECT_NAME,
        "version": VERSION,
        "result": "PASS" if all(checks.values()) else "FAIL",
        "scenario": scenario_key,
        "profile": profile_key,
        "request": request_key,
        "policy": policy_key,
        "document_class": document_class_key,
        "role": role_key,
        "context": context_key,
        "approval": approval_key,
        "release_mode": release_mode_key,
        "actor": actor_key,
        "job_state": job_state_key,
        "retention_state": retention_state_key,
        "data_destination": data_destination_key,
        "device_health": device_health_key,
        "risk_posture": risk_posture_key,
        "compliance_mode": compliance_mode_key,
        "trust_zone": trust_zone_key,
        "evidence_view": evidence_view_key,
        "recovery_action": recovery_action_key,
        "transfer_boundary": transfer_boundary_key,
        "custody_state_count": len(CUSTODY_STATE_ORDER),
        "checks": checks,
        "blocks": blocks,
    }
    payload["custody_state_audit_certificate"] = protection_certificate(payload)
    return payload


def apply_final_decision_layer(surface: dict, final_decision_key: str) -> dict:
    final_decision = FINAL_DECISIONS[final_decision_key]
    items = []
    for source_item in surface["items"]:
        item = dict(source_item)
        capability_key = item["capability_key"]
        state = item["final_state"]
        decision_reason = None
        if final_decision_key == "allow_output":
            if capability_key in ("print_engine", "paper_feed", "ink_toner_system", "secure_release") and state in (FORBIDDEN, DORMANT, DEFERRED, BLOCKED):
                item["final_state"] = ISOLATED if capability_key == "secure_release" else VISIBLE
                decision_reason = "Final decision admits bounded physical output or local release visibility."
            elif capability_key in ("document_cache", "scan_to_email", "fax_module") and state in ADMITTED_STATES:
                item["final_state"] = DEFERRED
                decision_reason = "Final decision admits output without opening cache or export visibility."
        elif final_decision_key == "hold_output":
            if capability_key in ("print_engine", "paper_feed", "ink_toner_system", "secure_release", "cloud_print", "remote_print_api", "scan_to_email", "fax_module") and state in ADMITTED_STATES:
                item["final_state"] = DEFERRED
                decision_reason = "Final decision holds output, release, and document movement visibility."
            elif capability_key in ("job_queue", "audit_logs") and state in (FORBIDDEN, DORMANT, DEFERRED, BLOCKED):
                item["final_state"] = ISOLATED
                decision_reason = "Final decision preserves bounded queue or audit evidence while output is held."
        elif final_decision_key == "deny_output":
            if capability_key in ("print_engine", "paper_feed", "ink_toner_system", "secure_release"):
                item["final_state"] = FORBIDDEN
                decision_reason = "Final decision denies physical output and local release visibility."
            elif capability_key in ("cloud_print", "remote_print_api", "scan_to_email", "fax_module", "document_cache") and state in ADMITTED_STATES:
                item["final_state"] = DEFERRED
                decision_reason = "Final decision keeps document movement or cache visibility closed after denial."
            elif capability_key == "audit_logs" and state in (FORBIDDEN, DORMANT, DEFERRED, BLOCKED):
                item["final_state"] = ISOLATED
                decision_reason = "Final decision preserves bounded audit evidence after denial."
        elif final_decision_key == "allow_evidence_only":
            if capability_key in ("job_queue", "document_cache", "audit_logs") and state in (FORBIDDEN, DORMANT, DEFERRED, BLOCKED):
                item["final_state"] = ISOLATED
                decision_reason = "Final decision admits evidence visibility only."
            elif capability_key in ("print_engine", "paper_feed", "ink_toner_system", "secure_release", "cloud_print", "remote_print_api", "scan_to_email", "fax_module") and state in ADMITTED_STATES:
                item["final_state"] = DEFERRED
                decision_reason = "Final decision keeps output, release, and document movement closed while evidence is visible."
        elif final_decision_key == "allow_service_only":
            if capability_key in ("admin_console", "firmware_update", "audit_logs") and state in (FORBIDDEN, DORMANT, DEFERRED, BLOCKED):
                item["final_state"] = ISOLATED
                decision_reason = "Final decision admits bounded service or audit visibility only."
            elif capability_key in ("print_engine", "paper_feed", "ink_toner_system", "secure_release", "cloud_print", "remote_print_api", "scan_to_email", "fax_module", "document_cache") and state in ADMITTED_STATES:
                item["final_state"] = DEFERRED
                decision_reason = "Final decision keeps document output, release, movement, and cache visibility closed during service-only handling."
        elif final_decision_key == "escalate_decision":
            if capability_key in ("job_queue", "document_cache", "audit_logs") and state in (FORBIDDEN, DORMANT, DEFERRED, BLOCKED):
                item["final_state"] = ISOLATED
                decision_reason = "Final decision preserves review evidence during escalation."
            elif capability_key in ("print_engine", "paper_feed", "ink_toner_system", "secure_release", "cloud_print", "remote_print_api", "scan_to_email", "fax_module") and state in ADMITTED_STATES:
                item["final_state"] = DEFERRED
                decision_reason = "Final decision defers output, release, and document movement during escalation."
            elif capability_key in ("admin_console", "firmware_update") and state in ADMITTED_STATES:
                item["final_state"] = DEFERRED
                decision_reason = "Final decision defers broad service change during escalation."
        item["final_decision"] = final_decision_key
        item["final_decision_description"] = final_decision["description"]
        item["final_decision_applied"] = decision_reason is not None
        if decision_reason is not None:
            item["reason"] = decision_reason
        item["certificate"] = protection_certificate(item)
        items.append(item)
    states = (VISIBLE, ISOLATED, DORMANT, FORBIDDEN, BLOCKED, DEFERRED)
    updated = dict(surface)
    updated["final_decision"] = final_decision_key
    updated["final_decision_description"] = final_decision["description"]
    updated["items"] = items
    updated["counts"] = {state: sum(1 for item in items if item["final_state"] == state) for state in states}
    updated["visible_surface"] = [item["capability_key"] for item in items if item["final_state"] in ADMITTED_STATES]
    updated["deferred_surface"] = [item["capability_key"] for item in items if item["final_state"] == DEFERRED]
    updated["surface_certificate"] = protection_certificate(updated)
    return updated


def resolve_final_decision_surface(scenario_key: str, profile_key: str, request_key: str, policy_key: str, document_class_key: str, role_key: str, context_key: str, approval_key: str, release_mode_key: str, actor_key: str, job_state_key: str, retention_state_key: str, data_destination_key: str, device_health_key: str, risk_posture_key: str, compliance_mode_key: str, trust_zone_key: str, evidence_view_key: str, recovery_action_key: str, transfer_boundary_key: str, custody_state_key: str, final_decision_key: str) -> dict:
    surface = resolve_custody_state_surface(scenario_key, profile_key, request_key, policy_key, document_class_key, role_key, context_key, approval_key, release_mode_key, actor_key, job_state_key, retention_state_key, data_destination_key, device_health_key, risk_posture_key, compliance_mode_key, trust_zone_key, evidence_view_key, recovery_action_key, transfer_boundary_key, custody_state_key)
    return apply_final_decision_layer(surface, final_decision_key)


def final_decision_audit(policy_key: str = "standard", document_class_key: str = "public_document", role_key: str = "employee", context_key: str = "trusted_office_device", approval_key: str = "manager_approved", release_mode_key: str = "secure_pull_release", actor_key: str = "release_operator", job_state_key: str = "released_job", retention_state_key: str = "short_spool_retention", data_destination_key: str = "department_queue", device_health_key: str = "healthy_device", risk_posture_key: str = "normal_risk", compliance_mode_key: str = "ordinary_mode", trust_zone_key: str = "local_trusted_zone", evidence_view_key: str = "operator_evidence_view", recovery_action_key: str = "no_recovery_action", transfer_boundary_key: str = "no_transfer", custody_state_key: str = "operator_custody", scenario_key: str = "remote_print", profile_key: str = "connected", request_key: str = "normal") -> dict:
    blocks = []
    for final_decision_key in FINAL_DECISION_ORDER:
        surface = resolve_final_decision_surface(scenario_key, profile_key, request_key, policy_key, document_class_key, role_key, context_key, approval_key, release_mode_key, actor_key, job_state_key, retention_state_key, data_destination_key, device_health_key, risk_posture_key, compliance_mode_key, trust_zone_key, evidence_view_key, recovery_action_key, transfer_boundary_key, custody_state_key, final_decision_key)
        print_state = next(item for item in surface["items"] if item["capability_key"] == "print_engine")["final_state"]
        cloud_state = next(item for item in surface["items"] if item["capability_key"] == "cloud_print")["final_state"]
        remote_state = next(item for item in surface["items"] if item["capability_key"] == "remote_print_api")["final_state"]
        cache_state = next(item for item in surface["items"] if item["capability_key"] == "document_cache")["final_state"]
        admin_state = next(item for item in surface["items"] if item["capability_key"] == "admin_console")["final_state"]
        firmware_state = next(item for item in surface["items"] if item["capability_key"] == "firmware_update")["final_state"]
        audit_state = next(item for item in surface["items"] if item["capability_key"] == "audit_logs")["final_state"]
        queue_state = next(item for item in surface["items"] if item["capability_key"] == "job_queue")["final_state"]
        secure_state = next(item for item in surface["items"] if item["capability_key"] == "secure_release")["final_state"]
        block = {
            "final_decision": final_decision_key,
            "description": FINAL_DECISIONS[final_decision_key]["description"],
            "surface_certificate": surface["surface_certificate"],
            "visible_surface": surface["visible_surface"],
            "deferred_surface": surface["deferred_surface"],
            "print_engine": print_state,
            "cloud_print": cloud_state,
            "remote_print_api": remote_state,
            "document_cache": cache_state,
            "admin_console": admin_state,
            "firmware_update": firmware_state,
            "audit_logs": audit_state,
            "job_queue": queue_state,
            "secure_release": secure_state,
        }
        block["final_decision_certificate"] = protection_certificate(block)
        blocks.append(block)
    signatures = {block["final_decision"]: (tuple(block["visible_surface"]), tuple(block["deferred_surface"])) for block in blocks}
    states = {block["final_decision"]: (block["print_engine"], block["cloud_print"], block["remote_print_api"], block["document_cache"], block["admin_console"], block["firmware_update"], block["audit_logs"], block["job_queue"], block["secure_release"]) for block in blocks}
    checks = {
        "final_decision_changes_visibility_outcome": len(set(signatures.values())) > 1,
        "allow_output_admits_output": states["allow_output"][0] in (VISIBLE, ISOLATED),
        "hold_output_defers_output": states["hold_output"][0] == DEFERRED,
        "deny_output_closes_output": states["deny_output"][0] == FORBIDDEN and states["deny_output"][8] == FORBIDDEN,
        "allow_evidence_only_preserves_evidence": states["allow_evidence_only"][6] == ISOLATED and states["allow_evidence_only"][0] in (DEFERRED, FORBIDDEN),
        "allow_service_only_admits_service": states["allow_service_only"][4] == ISOLATED and states["allow_service_only"][5] == ISOLATED,
        "escalate_decision_preserves_review_evidence": states["escalate_decision"][6] == ISOLATED and states["escalate_decision"][0] in (DEFERRED, FORBIDDEN),
    }
    payload = {
        "project": PROJECT_NAME,
        "version": VERSION,
        "result": "PASS" if all(checks.values()) else "FAIL",
        "scenario": scenario_key,
        "profile": profile_key,
        "request": request_key,
        "policy": policy_key,
        "document_class": document_class_key,
        "role": role_key,
        "context": context_key,
        "approval": approval_key,
        "release_mode": release_mode_key,
        "actor": actor_key,
        "job_state": job_state_key,
        "retention_state": retention_state_key,
        "data_destination": data_destination_key,
        "device_health": device_health_key,
        "risk_posture": risk_posture_key,
        "compliance_mode": compliance_mode_key,
        "trust_zone": trust_zone_key,
        "evidence_view": evidence_view_key,
        "recovery_action": recovery_action_key,
        "transfer_boundary": transfer_boundary_key,
        "custody_state": custody_state_key,
        "final_decision_count": len(FINAL_DECISION_ORDER),
        "checks": checks,
        "blocks": blocks,
    }
    payload["final_decision_audit_certificate"] = protection_certificate(payload)
    return payload


def governance_audit(scenario_key: str, profile_key: str, request_key: str, policy_key: str, document_class_key: str, role_key: str, context_key: str, approval_key: str, release_mode_key: str, actor_key: str, job_state_key: str, retention_state_key: str, data_destination_key: str, device_health_key: str, risk_posture_key: str, compliance_mode_key: str, trust_zone_key: str, evidence_view_key: str, recovery_action_key: str, transfer_boundary_key: str, custody_state_key: str, final_decision_key: str) -> dict:
    surface = resolve_final_decision_surface(scenario_key, profile_key, request_key, policy_key, document_class_key, role_key, context_key, approval_key, release_mode_key, actor_key, job_state_key, retention_state_key, data_destination_key, device_health_key, risk_posture_key, compliance_mode_key, trust_zone_key, evidence_view_key, recovery_action_key, transfer_boundary_key, custody_state_key, final_decision_key)
    selected = []
    for key in ("cloud_print", "remote_print_api", "scan_to_email", "document_cache", "admin_console", "firmware_update", "audit_logs", "secure_release"):
        item = next(x for x in surface["items"] if x["capability_key"] == key)
        selected.append({
            "capability_key": key,
            "state": item["final_state"],
            "reason": item["reason"],
            "certificate": item["certificate"],
        })
    payload = {
        "project": PROJECT_NAME,
        "version": VERSION,
        "scenario": scenario_key,
        "profile": profile_key,
        "request": request_key,
        "policy": policy_key,
        "document_class": document_class_key,
        "role": role_key,
        "context": context_key,
        "approval": approval_key,
        "release_mode": release_mode_key,
        "actor": actor_key,
        "job_state": job_state_key,
        "retention_state": retention_state_key,
        "data_destination": data_destination_key,
        "device_health": device_health_key,
        "risk_posture": risk_posture_key,
        "compliance_mode": compliance_mode_key,
        "trust_zone": trust_zone_key,
        "evidence_view": evidence_view_key,
        "recovery_action": recovery_action_key,
        "transfer_boundary": transfer_boundary_key,
        "custody_state": custody_state_key,
        "final_decision": final_decision_key,
        "visible_surface": surface["visible_surface"],
        "deferred_surface": surface["deferred_surface"],
        "counts": surface["counts"],
        "surface_certificate": surface["surface_certificate"],
        "selected_capabilities": selected,
    }
    payload["governance_certificate"] = protection_certificate(payload)
    return payload


def role_audit(policy_key: str = "standard", document_class_key: str = "public_document", scenario_key: str = "remote_print", profile_key: str = "connected", request_key: str = "normal") -> dict:
    blocks = []
    for role_key in ROLE_ORDER:
        surface = resolve_role_surface(scenario_key, profile_key, request_key, policy_key, document_class_key, role_key)
        cloud_state = next(item for item in surface["items"] if item["capability_key"] == "cloud_print")["final_state"]
        remote_state = next(item for item in surface["items"] if item["capability_key"] == "remote_print_api")["final_state"]
        admin_state = next(item for item in surface["items"] if item["capability_key"] == "admin_console")["final_state"]
        firmware_state = next(item for item in surface["items"] if item["capability_key"] == "firmware_update")["final_state"]
        block = {
            "role": role_key,
            "description": ROLE_PROFILES[role_key]["description"],
            "surface_certificate": surface["surface_certificate"],
            "visible_surface": surface["visible_surface"],
            "deferred_surface": surface["deferred_surface"],
            "cloud_print": cloud_state,
            "remote_print_api": remote_state,
            "admin_console": admin_state,
            "firmware_update": firmware_state,
        }
        block["role_certificate"] = protection_certificate(block)
        blocks.append(block)
    visibility_signatures = {block["role"]: (tuple(block["visible_surface"]), tuple(block["deferred_surface"])) for block in blocks}
    payload = {
        "project": PROJECT_NAME,
        "version": VERSION,
        "result": "PASS" if len(set(visibility_signatures.values())) > 1 else "FAIL",
        "scenario": scenario_key,
        "profile": profile_key,
        "request": request_key,
        "policy": policy_key,
        "document_class": document_class_key,
        "role_count": len(ROLE_ORDER),
        "blocks": blocks,
    }
    payload["role_audit_certificate"] = protection_certificate(payload)
    return payload


def document_class_audit(policy_key: str = "standard", scenario_key: str = "remote_print", profile_key: str = "connected", request_key: str = "normal") -> dict:
    blocks = []
    for document_class_key in DOCUMENT_CLASS_ORDER:
        surface = resolve_document_surface(scenario_key, profile_key, request_key, policy_key, document_class_key)
        remote_state = next(item for item in surface["items"] if item["capability_key"] == "remote_print_api")["final_state"]
        scan_state = next(item for item in surface["items"] if item["capability_key"] == "scan_to_email")["final_state"]
        cache_state = next(item for item in surface["items"] if item["capability_key"] == "document_cache")["final_state"]
        block = {
            "document_class": document_class_key,
            "description": DOCUMENT_CLASSES[document_class_key]["description"],
            "surface_certificate": surface["surface_certificate"],
            "visible_surface": surface["visible_surface"],
            "deferred_surface": surface["deferred_surface"],
            "remote_print_api": remote_state,
            "scan_to_email": scan_state,
            "document_cache": cache_state,
        }
        block["document_class_certificate"] = protection_certificate(block)
        blocks.append(block)
    remote_states = {block["document_class"]: block["remote_print_api"] for block in blocks}
    visibility_signatures = {block["document_class"]: (tuple(block["visible_surface"]), tuple(block["deferred_surface"])) for block in blocks}
    payload = {
        "project": PROJECT_NAME,
        "version": VERSION,
        "result": "PASS" if len(set(visibility_signatures.values())) > 1 else "FAIL",
        "scenario": scenario_key,
        "profile": profile_key,
        "request": request_key,
        "policy": policy_key,
        "document_class_count": len(blocks),
        "remote_print_states": remote_states,
        "visibility_signatures": visibility_signatures,
        "document_classes": blocks,
    }
    payload["document_class_audit_certificate"] = protection_certificate(payload)
    return payload


def print_document_classes() -> None:
    for key in DOCUMENT_CLASS_ORDER:
        print(f"{key}: {DOCUMENT_CLASSES[key]['description']}")


def print_document_class_audit(payload: dict) -> None:
    print(f"{PROJECT_NAME} v{VERSION} Document-Class Audit")
    print(f"Document-Class Result: {payload['result']}")
    print(f"Scenario: {payload['scenario']}")
    print(f"Profile: {payload['profile']}")
    print(f"Request: {payload['request']}")
    print(f"Policy: {payload['policy']}")
    print(f"Document Class Count: {payload['document_class_count']}")
    print(f"Document-Class Audit Certificate: {payload['document_class_audit_certificate']}")
    for block in payload["document_classes"]:
        print(f"Document Class: {block['document_class']} | cert={block['document_class_certificate']}")
        print(f"  description: {block['description']}")
        print(f"  remote_print_api: {block['remote_print_api']}")
        print(f"  scan_to_email: {block['scan_to_email']}")
        print(f"  document_cache: {block['document_cache']}")
        visible = ", ".join(block["visible_surface"]) if block["visible_surface"] else "none"
        deferred = ", ".join(block["deferred_surface"]) if block["deferred_surface"] else "none"
        print(f"  visible: {visible}")
        print(f"  deferred: {deferred}")

def apply_policy_layer(surface: dict, policy_key: str) -> dict:
    policy = POLICY_PROFILES[policy_key]
    items = []
    for source_item in surface["items"]:
        item = dict(source_item)
        capability_key = item["capability_key"]
        state = item["final_state"]
        policy_reason = None
        if state in ADMITTED_STATES:
            if capability_key in ("cloud_print", "remote_print_api") and not policy["allow_remote_print"]:
                item["final_state"] = DEFERRED
                policy_reason = "Capability is structurally admissible, but policy defers remote print visibility."
            elif capability_key in ("scan_to_email", "fax_module") and not policy["allow_scan_export"]:
                item["final_state"] = DEFERRED
                policy_reason = "Capability is structurally admissible, but policy defers document export visibility."
            elif capability_key == "firmware_update" and not policy["allow_firmware_update"]:
                item["final_state"] = DEFERRED
                policy_reason = "Firmware update is structurally ready, but policy requires approved update timing."
            elif capability_key == "document_cache" and not policy["allow_document_cache"]:
                item["final_state"] = FORBIDDEN
                policy_reason = "Document cache visibility is refused by policy."
            elif capability_key == "admin_console" and not policy["admin_approval"]:
                item["final_state"] = DEFERRED
                policy_reason = "Admin console is structurally admissible, but policy requires administrative approval."
        item["policy"] = policy_key
        item["policy_description"] = policy["description"]
        item["policy_applied"] = policy_reason is not None
        if policy_reason is not None:
            item["reason"] = policy_reason
        item["certificate"] = protection_certificate(item)
        items.append(item)
    states = (VISIBLE, ISOLATED, DORMANT, FORBIDDEN, BLOCKED, DEFERRED)
    updated = dict(surface)
    updated["policy"] = policy_key
    updated["policy_description"] = policy["description"]
    updated["items"] = items
    updated["counts"] = {state: sum(1 for item in items if item["final_state"] == state) for state in states}
    updated["visible_surface"] = [item["capability_key"] for item in items if item["final_state"] in ADMITTED_STATES]
    updated["deferred_surface"] = [item["capability_key"] for item in items if item["final_state"] == DEFERRED]
    updated["surface_certificate"] = protection_certificate(updated)
    return updated


def resolve_policy_surface(scenario_key: str, profile_key: str, request_key: str, policy_key: str) -> dict:
    surface = resolve_surface(scenario_key, profile_key, request_key)
    if policy_key == "standard":
        surface["policy"] = policy_key
        surface["policy_description"] = POLICY_PROFILES[policy_key]["description"]
        surface["surface_certificate"] = protection_certificate(surface)
        return surface
    return apply_policy_layer(surface, policy_key)


def resolve_surface(scenario_key: str, profile_key: str, request_key: str) -> dict:
    items = [resolve_capability(key, scenario_key, profile_key, request_key) for key in CAPABILITIES]
    items = apply_dependency_layer(items, scenario_key)
    states = (VISIBLE, ISOLATED, DORMANT, FORBIDDEN, BLOCKED, DEFERRED)
    counts = {state: sum(1 for item in items if item["final_state"] == state) for state in states}
    payload = {
        "project": PROJECT_NAME,
        "version": VERSION,
        "scenario": scenario_key,
        "profile": profile_key,
        "request": request_key,
        "counts": counts,
        "capability_count": len(CAPABILITIES),
        "visible_surface": [item["capability_key"] for item in items if item["final_state"] in ADMITTED_STATES],
        "deferred_surface": [item["capability_key"] for item in items if item["final_state"] == DEFERRED],
        "items": items,
        "posture": STRUCTURAL_POSTURE.get(scenario_key, {}),
    }
    payload["surface_certificate"] = protection_certificate(payload)
    return payload

def print_surface(surface: dict, explain: bool = False) -> None:
    print(f"{PROJECT_NAME} v{VERSION}")
    print(f"Scenario: {surface['scenario']}")
    print(f"Profile: {surface['profile']}")
    print(f"Request: {surface['request']}")
    if surface.get("policy"):
        print(f"Policy: {surface['policy']}")
    if surface.get("document_class"):
        print(f"Document Class: {surface['document_class']}")
    if surface.get("role"):
        print(f"Role: {surface['role']}")
    if surface.get("context"):
        print(f"Context: {surface['context']}")
    if surface.get("approval"):
        print(f"Approval: {surface['approval']}")
    if surface.get("release_mode"):
        print(f"Release Mode: {surface['release_mode']}")
    if surface.get("actor"):
        print(f"Actor: {surface['actor']}")
    if surface.get("job_state"):
        print(f"Job State: {surface['job_state']}")
    if surface.get("retention_state"):
        print(f"Retention State: {surface['retention_state']}")
    if surface.get("data_destination"):
        print(f"Data Destination: {surface['data_destination']}")
    if surface.get("device_health"):
        print(f"Device Health: {surface['device_health']}")
    print(f"Capability Count: {surface['capability_count']}")
    print("Counts:")
    for state in (VISIBLE, ISOLATED, DORMANT, FORBIDDEN, BLOCKED, DEFERRED):
        print(f"  {state}: {surface['counts'][state]}")
    print(f"Surface Certificate: {surface['surface_certificate']}")
    print("Visible Surface:")
    if surface["visible_surface"]:
        for key in surface["visible_surface"]:
            print(f"  - {key}")
    else:
        print("  - NO VISIBLE CAPABILITIES")
    if surface.get("deferred_surface"):
        print("Deferred Surface:")
        for key in surface["deferred_surface"]:
            print(f"  - {key}")
    if explain:
        print("Capability Resolution:")
        for item in surface["items"]:
            print(f"  - {item['capability_key']}: {item['final_state']} | {item['reason']} | cert={item['certificate']}")
        print(f"Final Visible Output: {'NO FORCED VISIBILITY' if surface['counts'][BLOCKED] > 0 and REQUESTS[surface['request']]['forced_visibility'] else 'STRUCTURAL VISIBILITY RESOLVED'}")


def verify_cases() -> List[Tuple[str, str, str]]:
    return [
        ("local_print", "minimal", "normal"),
        ("secure_print", "balanced", "normal"),
        ("guest_print", "balanced", "normal"),
        ("remote_print", "connected", "normal"),
        ("scan_to_email", "connected", "normal"),
        ("maintenance", "maintenance", "normal"),
        ("firmware_update", "maintenance", "normal"),
        ("maintenance_with_jobs", "maintenance", "normal"),
        ("maintenance_after_jobs_clear", "maintenance", "normal"),
        ("managed_service", "maintenance", "normal"),
        ("remote_print", "connected", "remote_job_spoof"),
        ("scan_to_email", "connected", "scan_leak"),
        ("maintenance", "maintenance", "firmware_push"),
    ]


def run_verify() -> dict:
    results = []
    ok = True
    for scenario_key, profile_key, request_key in verify_cases():
        first = resolve_surface(scenario_key, profile_key, request_key)
        second = resolve_surface(scenario_key, profile_key, request_key)
        same = first == second and first["surface_certificate"] == second["surface_certificate"]
        ok = ok and same
        results.append({
            "scenario": scenario_key,
            "profile": profile_key,
            "request": request_key,
            "certificate": first["surface_certificate"],
            "same": same,
        })
    payload = {"project": PROJECT_NAME, "version": VERSION, "result": "PASS" if ok else "FAIL", "cases": results}
    payload["verification_certificate"] = protection_certificate(payload)
    return payload


def run_challenge() -> dict:
    challenge_cases = [
        ("remote_print", "connected", "remote_job_spoof", "remote_print_api"),
        ("maintenance", "maintenance", "cache_exfiltration", "document_cache"),
        ("scan_to_email", "connected", "scan_leak", "scan_to_email"),
        ("fax_send", "connected", "fax_abuse", "fax_module"),
        ("firmware_update", "maintenance", "firmware_push", "firmware_update"),
        ("maintenance", "maintenance", "admin_probe", "admin_console"),
        ("managed_service", "maintenance", "telemetry_leak", "telemetry_export"),
        ("guest_print", "balanced", "guest_escape", "job_queue"),
        ("mobile_pair", "balanced", "mobile_pair_spoof", "mobile_pairing"),
    ]
    cases = []
    ok = True
    for scenario_key, profile_key, request_key, target in challenge_cases:
        item = resolve_capability(target, scenario_key, profile_key, request_key)
        passed = item["final_state"] == BLOCKED and item["caps_admissible"] is False
        ok = ok and passed
        cases.append({
            "scenario": scenario_key,
            "profile": profile_key,
            "request": request_key,
            "target": target,
            "state": item["final_state"],
            "passed": passed,
            "certificate": item["certificate"],
        })
    payload = {"project": PROJECT_NAME, "version": VERSION, "result": "PASS" if ok else "FAIL", "cases": cases}
    payload["challenge_certificate"] = protection_certificate(payload)
    return payload


def run_invariants() -> dict:
    base = resolve_surface("secure_print", "balanced", "normal")
    replay = resolve_surface("secure_print", "balanced", "normal")
    changed_profile = resolve_surface("secure_print", "strict", "normal")
    unsafe = resolve_capability("remote_print_api", "remote_print", "connected", "remote_job_spoof")
    capability_surface_preserved = set(CAPABILITIES.keys()) == set(item["capability_key"] for item in base["items"])
    firmware_surface = resolve_surface("firmware_update", "maintenance", "normal")
    maintenance_surface = resolve_surface("maintenance", "maintenance", "normal")
    cache_firmware = resolve_capability("document_cache", "firmware_update", "maintenance", "normal")
    maintenance_with_jobs = resolve_surface("maintenance_with_jobs", "maintenance", "normal")
    maintenance_after_clear = resolve_surface("maintenance_after_jobs_clear", "maintenance", "normal")
    checks = {
        "same_structure_same_certificate": base["surface_certificate"] == replay["surface_certificate"],
        "same_structure_same_visibility": base["visible_surface"] == replay["visible_surface"],
        "profile_change_can_change_visibility": base["visible_surface"] != changed_profile["visible_surface"],
        "capability_existence_preserved": capability_surface_preserved,
        "unsafe_forced_visibility_blocked": unsafe["final_state"] == BLOCKED,
        "firmware_update_does_not_expose_document_cache": cache_firmware["final_state"] == FORBIDDEN,
        "firmware_update_does_not_expose_print_engine": "print_engine" not in firmware_surface["visible_surface"],
        "maintenance_does_not_expose_physical_output_engine": "print_engine" not in maintenance_surface["visible_surface"],
        "active_jobs_defer_firmware_update": "firmware_update" in maintenance_with_jobs["deferred_surface"],
        "deferred_is_not_visible": "firmware_update" not in maintenance_with_jobs["visible_surface"],
        "clearance_admits_firmware_update": "firmware_update" in maintenance_after_clear["visible_surface"],
        "clearance_removes_firmware_deferral": "firmware_update" not in maintenance_after_clear["deferred_surface"],
        "lifecycle_audit_passes": lifecycle_audit()["result"] == "PASS",
        "document_class_audit_passes": document_class_audit()["result"] == "PASS",
        "role_audit_passes": role_audit()["result"] == "PASS",
        "context_audit_passes": context_audit()["result"] == "PASS",
        "approval_audit_passes": approval_audit()["result"] == "PASS",
        "release_mode_audit_passes": release_mode_audit()["result"] == "PASS",
        "actor_audit_passes": actor_audit()["result"] == "PASS",
        "job_state_audit_passes": job_state_audit()["result"] == "PASS",
        "retention_state_audit_passes": retention_state_audit()["result"] == "PASS",
        "data_destination_audit_passes": data_destination_audit()["result"] == "PASS",
        "device_health_audit_passes": device_health_audit()["result"] == "PASS",
        "risk_posture_audit_passes": risk_posture_audit()["result"] == "PASS",
        "compliance_mode_audit_passes": compliance_mode_audit()["result"] == "PASS",
        "trust_zone_audit_passes": trust_zone_audit()["result"] == "PASS",
        "evidence_view_audit_passes": evidence_view_audit()["result"] == "PASS",
        "recovery_action_audit_passes": recovery_action_audit()["result"] == "PASS",
        "transfer_boundary_audit_passes": transfer_boundary_audit()["result"] == "PASS",
    }
    ok = all(checks.values())
    payload = {"project": PROJECT_NAME, "version": VERSION, "result": "PASS" if ok else "FAIL", "checks": checks}
    payload["invariant_certificate"] = protection_certificate(payload)
    return payload


def manifest() -> dict:
    payload = {
        "project": PROJECT_NAME,
        "version": VERSION,
        "capability_count": len(CAPABILITIES),
        "scenario_count": len(SCENARIOS),
        "profile_count": len(PROFILES),
        "request_count": len(REQUESTS),
        "policy_count": len(POLICY_PROFILES),
        "document_class_count": len(DOCUMENT_CLASSES),
        "release_mode_count": len(RELEASE_MODES),
        "actor_count": len(ACTOR_PROFILES),
        "job_state_count": len(JOB_STATES),
        "retention_state_count": len(RETENTION_STATES),
        "data_destination_count": len(DATA_DESTINATIONS),
        "device_health_count": len(DEVICE_HEALTHS),
        "risk_posture_count": len(RISK_POSTURES),
        "compliance_mode_count": len(COMPLIANCE_MODES),
        "trust_zone_count": len(TRUST_ZONES),
        "evidence_view_count": len(EVIDENCE_VIEWS),
        "recovery_action_count": len(RECOVERY_ACTIONS),
        "transfer_boundary_count": len(TRANSFER_BOUNDARIES),
        "custody_state_count": len(CUSTODY_STATES),
        "final_decision_count": len(FINAL_DECISIONS),
        "states": [VISIBLE, ISOLATED, DORMANT, FORBIDDEN, BLOCKED, DEFERRED],
        "core_formula": "capability_visible = resolve(capability, scenario, protection_profile, request_structure)",
        "core_invariant": "same structure -> same visibility -> same certificate",
        "version_focus": "final-decision layer governing output, evidence-only, service-only, hold, denial, and escalation visibility",
        "capabilities": list(CAPABILITIES.keys()),
        "scenarios": list(SCENARIOS.keys()),
        "profiles": list(PROFILES.keys()),
        "requests": list(REQUESTS.keys()),
        "policies": list(POLICY_PROFILES.keys()),
        "document_classes": list(DOCUMENT_CLASSES.keys()),
        "release_modes": list(RELEASE_MODES.keys()),
        "actors": list(ACTOR_PROFILES.keys()),
        "job_states": list(JOB_STATES.keys()),
        "retention_states": list(RETENTION_STATES.keys()),
        "data_destinations": list(DATA_DESTINATIONS.keys()),
        "device_healths": list(DEVICE_HEALTHS.keys()),
        "risk_postures": list(RISK_POSTURES.keys()),
        "compliance_modes": list(COMPLIANCE_MODES.keys()),
        "trust_zones": list(TRUST_ZONES.keys()),
        "evidence_views": list(EVIDENCE_VIEWS.keys()),
        "recovery_actions": list(RECOVERY_ACTIONS.keys()),
        "transfer_boundaries": list(TRANSFER_BOUNDARIES.keys()),
        "custody_states": list(CUSTODY_STATES.keys()),
        "final_decisions": list(FINAL_DECISIONS.keys()),
    }
    payload["release_certificate"] = protection_certificate(payload)
    return payload


def print_key_value_payload(payload: dict, certificate_key: str) -> None:
    result = payload.get("result")
    if result:
        label = certificate_key.replace("_", " ").title()
        if "verification" in certificate_key:
            print(f"Verification Result: {result}")
            print(f"Verification Certificate: {payload[certificate_key]}")
            print("Deterministic replay confirmed." if result == "PASS" else "Deterministic replay failed.")
        elif "challenge" in certificate_key:
            print(f"Challenge Result: {result}")
            print(f"Challenge Certificate: {payload[certificate_key]}")
        elif "invariant" in certificate_key:
            print(f"Invariant Result: {result}")
            print(f"Invariant Certificate: {payload[certificate_key]}")
    else:
        print(json.dumps(payload, indent=2, sort_keys=True))


def quickstart() -> None:
    cmd = command_name()
    print(f"{PROJECT_NAME} v{VERSION} Quickstart")
    print("")
    print("Discover commands:")
    print(f"python {cmd} --quickstart")
    print("")
    print("Run deterministic replay verification:")
    print(f"python {cmd} --verify")
    print("")
    print("Run challenge checks:")
    print(f"python {cmd} --challenge")
    print("")
    print("Explore visibility surface:")
    print(f"python {cmd} --surface")
    print("")
    print("Unsafe remote print refused:")
    print(f"python {cmd} --scenario remote_print --profile connected --request remote_job_spoof --explain")
    print("")
    print("Document cache exfiltration refused:")
    print(f"python {cmd} --scenario maintenance --profile maintenance --request cache_exfiltration --explain")
    print("")
    print("Scan leak refused:")
    print(f"python {cmd} --scenario scan_to_email --profile connected --request scan_leak --explain")
    print("")
    print("Firmware update admitted:")
    print(f"python {cmd} --scenario firmware_update --profile maintenance --request normal --explain")
    print("")
    print("Firmware update deferred when active jobs exist:")
    print(f"python {cmd} --scenario maintenance_with_jobs --profile maintenance --request normal --explain")
    print("")
    print("Show dependency graph:")
    print(f"python {cmd} --dependency-graph")
    print("")
    print("Show structural transition audit:")
    print(f"python {cmd} --transition-audit --profile maintenance")
    print("")
    print("Show operational lifecycle audit:")
    print(f"python {cmd} --lifecycle-audit")
    print("")
    print("Show document classes:")
    print(f"python {cmd} --document-classes")
    print("")
    print("Show document-class audit:")
    print(f"python {cmd} --document-class-audit --scenario remote_print --profile connected --request normal --policy standard")
    print("")
    print("Show approval-chain audit:")
    print(f"python {cmd} --approval-audit --scenario remote_print --profile connected --request normal --policy standard --document-class public_document --role employee --context trusted_office_device")
    print("Show release-mode audit:")
    print(f"python {cmd} --release-mode-audit --scenario remote_print --profile connected --request normal --policy standard --document-class public_document --role employee --context trusted_office_device --approval manager_approved")
    print("")
    print("Expected invariant:")
    print("same structure -> same visibility -> same certificate")


def print_profiles() -> None:
    for key in PROFILE_ORDER:
        print(f"{key}: {PROFILES[key]['description']}")


def print_requests() -> None:
    for key in ("normal",) + REQUEST_ORDER:
        print(f"{key}: {REQUESTS[key]['description']}")


def print_manifest(payload: dict) -> None:
    print(f"Project: {payload['project']}")
    print(f"Version: {payload['version']}")
    print(f"Capability Count: {payload['capability_count']}")
    print(f"Scenario Count: {payload['scenario_count']}")
    print(f"Profile Count: {payload['profile_count']}")
    print(f"Request Count: {payload['request_count']}")
    if "approval_count" in payload:
        print(f"Approval Count: {payload['approval_count']}")
    print(f"Core Formula: {payload['core_formula']}")
    print(f"Core Invariant: {payload['core_invariant']}")
    print(f"Release Certificate: {payload['release_certificate']}")


def print_surface_table(scenarios: Tuple[str, ...], profiles: Tuple[str, ...], request_key: str) -> None:
    print(f"{PROJECT_NAME} v{VERSION} Visibility Matrix")
    print(f"Request: {request_key}")
    print("scenario,profile,visible,isolated,dormant,forbidden,blocked,deferred,certificate")
    for scenario_key in scenarios:
        for profile_key in profiles:
            surface = resolve_surface(scenario_key, profile_key, request_key)
            counts = surface["counts"]
            print(f"{scenario_key},{profile_key},{counts[VISIBLE]},{counts[ISOLATED]},{counts[DORMANT]},{counts[FORBIDDEN]},{counts[BLOCKED]},{counts[DEFERRED]},{surface['surface_certificate']}")



def print_dependency_graph() -> None:
    print(f"{PROJECT_NAME} v{VERSION} Dependency Graph")
    print("capability,dependencies,conflicts")
    for key in CAPABILITIES:
        dependencies = ";".join(DEPENDENCY_GRAPH.get(key, ())) or "none"
        conflicts = ";".join(CONFLICT_GRAPH.get(key, ())) or "none"
        print(f"{key},{dependencies},{conflicts}")


def transition_audit(from_scenario: str, to_scenario: str, profile_key: str, request_key: str) -> dict:
    before = resolve_surface(from_scenario, profile_key, request_key)
    after = resolve_surface(to_scenario, profile_key, request_key)
    before_by_key = {item["capability_key"]: item for item in before["items"]}
    after_by_key = {item["capability_key"]: item for item in after["items"]}
    transitions = []
    for key in CAPABILITIES:
        left = before_by_key[key]
        right = after_by_key[key]
        changed = left["final_state"] != right["final_state"] or left["reason"] != right["reason"]
        if changed:
            entry = {
                "capability_key": key,
                "from_state": left["final_state"],
                "to_state": right["final_state"],
                "from_reason": left["reason"],
                "to_reason": right["reason"],
                "from_active_conflicts": left.get("active_conflicts", []),
                "to_active_conflicts": right.get("active_conflicts", []),
                "from_missing_dependencies": left.get("missing_dependencies", []),
                "to_missing_dependencies": right.get("missing_dependencies", []),
            }
            entry["transition_certificate"] = protection_certificate(entry)
            transitions.append(entry)
    payload = {
        "project": PROJECT_NAME,
        "version": VERSION,
        "from_scenario": from_scenario,
        "to_scenario": to_scenario,
        "profile": profile_key,
        "request": request_key,
        "from_surface_certificate": before["surface_certificate"],
        "to_surface_certificate": after["surface_certificate"],
        "transition_count": len(transitions),
        "transitions": transitions,
    }
    payload["audit_certificate"] = protection_certificate(payload)
    return payload


def print_transition_audit(payload: dict) -> None:
    print(f"{PROJECT_NAME} v{VERSION} Structural Transition Audit")
    print(f"From Scenario: {payload['from_scenario']}")
    print(f"To Scenario: {payload['to_scenario']}")
    print(f"Profile: {payload['profile']}")
    print(f"Request: {payload['request']}")
    print(f"From Surface Certificate: {payload['from_surface_certificate']}")
    print(f"To Surface Certificate: {payload['to_surface_certificate']}")
    print(f"Transition Count: {payload['transition_count']}")
    print(f"Audit Certificate: {payload['audit_certificate']}")
    print("Transitions:")
    if not payload["transitions"]:
        print("  - NO STRUCTURAL STATE CHANGES")
        return
    for item in payload["transitions"]:
        print(f"  - {item['capability_key']}: {item['from_state']} -> {item['to_state']} | cert={item['transition_certificate']}")
        print(f"    from_reason: {item['from_reason']}")
        print(f"    to_reason: {item['to_reason']}")
        if item["from_active_conflicts"] or item["to_active_conflicts"]:
            print(f"    conflicts: {item['from_active_conflicts']} -> {item['to_active_conflicts']}")
        if item["from_missing_dependencies"] or item["to_missing_dependencies"]:
            print(f"    missing_dependencies: {item['from_missing_dependencies']} -> {item['to_missing_dependencies']}")



def lifecycle_steps() -> List[dict]:
    return [
        {"phase": "REMOTE_PRINT_ACTIVE", "scenario": "remote_print", "profile": "connected", "request": "normal", "meaning": "Authenticated remote print job is structurally admitted."},
        {"phase": "MAINTENANCE_REQUESTED_WITH_ACTIVE_JOBS", "scenario": "maintenance_with_jobs", "profile": "maintenance", "request": "normal", "meaning": "Maintenance is requested while active document workload still exists."},
        {"phase": "WORKLOAD_CLEARED", "scenario": "maintenance_after_jobs_clear", "profile": "maintenance", "request": "normal", "meaning": "Active document workload is cleared and maintenance readiness is restored."},
        {"phase": "FIRMWARE_UPDATE_READY", "scenario": "firmware_update", "profile": "maintenance", "request": "normal", "meaning": "Firmware update visibility is admitted inside authenticated update posture."},
    ]


def lifecycle_audit() -> dict:
    steps = []
    for item in lifecycle_steps():
        surface = resolve_surface(item["scenario"], item["profile"], item["request"])
        firmware_item = next(x for x in surface["items"] if x["capability_key"] == "firmware_update")
        step = {
            "phase": item["phase"],
            "meaning": item["meaning"],
            "scenario": item["scenario"],
            "profile": item["profile"],
            "request": item["request"],
            "surface_certificate": surface["surface_certificate"],
            "visible_surface": surface["visible_surface"],
            "deferred_surface": surface["deferred_surface"],
            "firmware_update_state": firmware_item["final_state"],
            "firmware_update_reason": firmware_item["reason"],
            "firmware_update_conflicts": firmware_item.get("active_conflicts", []),
        }
        step["step_certificate"] = protection_certificate(step)
        steps.append(step)

    transitions = []
    for left, right in zip(steps, steps[1:]):
        before = resolve_surface(left["scenario"], left["profile"], left["request"])
        after = resolve_surface(right["scenario"], right["profile"], right["request"])
        before_by_key = {item["capability_key"]: item for item in before["items"]}
        after_by_key = {item["capability_key"]: item for item in after["items"]}
        changes = []
        for key in CAPABILITIES:
            left_item = before_by_key[key]
            right_item = after_by_key[key]
            changed = left_item["final_state"] != right_item["final_state"] or left_item["reason"] != right_item["reason"]
            if changed:
                entry = {
                    "capability_key": key,
                    "from_state": left_item["final_state"],
                    "to_state": right_item["final_state"],
                    "from_reason": left_item["reason"],
                    "to_reason": right_item["reason"],
                    "from_active_conflicts": left_item.get("active_conflicts", []),
                    "to_active_conflicts": right_item.get("active_conflicts", []),
                    "from_missing_dependencies": left_item.get("missing_dependencies", []),
                    "to_missing_dependencies": right_item.get("missing_dependencies", []),
                }
                entry["transition_certificate"] = protection_certificate(entry)
                changes.append(entry)
        block = {
            "from_phase": left["phase"],
            "to_phase": right["phase"],
            "from_surface_certificate": before["surface_certificate"],
            "to_surface_certificate": after["surface_certificate"],
            "transition_count": len(changes),
            "transitions": changes,
        }
        block["audit_certificate"] = protection_certificate(block)
        transitions.append(block)

    checks = {
        "remote_print_active_contains_remote_print_path": "cloud_print" in steps[0]["visible_surface"] and "job_queue" in steps[0]["visible_surface"],
        "remote_print_api_not_forced_open_during_active_job": steps[0]["firmware_update_state"] == FORBIDDEN,
        "maintenance_with_jobs_defers_firmware_update": steps[1]["firmware_update_state"] == DEFERRED,
        "workload_clear_admits_firmware_update": steps[2]["firmware_update_state"] == ISOLATED,
        "firmware_update_ready_remains_admitted": steps[3]["firmware_update_state"] == ISOLATED,
        "lifecycle_has_stable_certificates": all(step["surface_certificate"] for step in steps),
    }
    payload = {
        "project": PROJECT_NAME,
        "version": VERSION,
        "result": "PASS" if all(checks.values()) else "FAIL",
        "checks": checks,
        "step_count": len(steps),
        "transition_count": len(transitions),
        "steps": steps,
        "transitions": transitions,
    }
    payload["lifecycle_certificate"] = protection_certificate(payload)
    return payload


def print_lifecycle_audit(payload: dict) -> None:
    print(f"{PROJECT_NAME} v{VERSION} Operational Lifecycle Audit")
    print(f"Lifecycle Result: {payload['result']}")
    print(f"Step Count: {payload['step_count']}")
    print(f"Transition Count: {payload['transition_count']}")
    print(f"Lifecycle Certificate: {payload['lifecycle_certificate']}")
    print("Steps:")
    for step in payload["steps"]:
        print(f"  - {step['phase']}: scenario={step['scenario']} profile={step['profile']} request={step['request']} | surface_cert={step['surface_certificate']} | step_cert={step['step_certificate']}")
        print(f"    meaning: {step['meaning']}")
        print(f"    firmware_update: {step['firmware_update_state']} | conflicts={step['firmware_update_conflicts']}")
        if step["visible_surface"]:
            print(f"    visible: {', '.join(step['visible_surface'])}")
        if step["deferred_surface"]:
            print(f"    deferred: {', '.join(step['deferred_surface'])}")
    print("Transitions:")
    for block in payload["transitions"]:
        print(f"  - {block['from_phase']} -> {block['to_phase']} | changes={block['transition_count']} | cert={block['audit_certificate']}")
        for item in block["transitions"]:
            if item["capability_key"] == "firmware_update":
                print(f"    firmware_update: {item['from_state']} -> {item['to_state']} | conflicts={item['from_active_conflicts']} -> {item['to_active_conflicts']} | cert={item['transition_certificate']}")


def policy_lifecycle_audit() -> dict:
    policy_blocks = []
    for policy_key in POLICY_ORDER:
        steps = []
        for item in lifecycle_steps():
            surface = resolve_policy_surface(item["scenario"], item["profile"], item["request"], policy_key)
            firmware_item = next(x for x in surface["items"] if x["capability_key"] == "firmware_update")
            step = {
                "phase": item["phase"],
                "meaning": item["meaning"],
                "scenario": item["scenario"],
                "profile": item["profile"],
                "request": item["request"],
                "policy": policy_key,
                "surface_certificate": surface["surface_certificate"],
                "visible_surface": surface["visible_surface"],
                "deferred_surface": surface["deferred_surface"],
                "firmware_update_state": firmware_item["final_state"],
                "firmware_update_reason": firmware_item["reason"],
                "firmware_update_conflicts": firmware_item.get("active_conflicts", []),
            }
            step["step_certificate"] = protection_certificate(step)
            steps.append(step)
        block = {
            "policy": policy_key,
            "policy_description": POLICY_PROFILES[policy_key]["description"],
            "steps": steps,
            "final_firmware_state": steps[-1]["firmware_update_state"],
            "final_visible_surface": steps[-1]["visible_surface"],
            "final_deferred_surface": steps[-1]["deferred_surface"],
        }
        block["policy_certificate"] = protection_certificate(block)
        policy_blocks.append(block)
    final_states = {block["policy"]: block["final_firmware_state"] for block in policy_blocks}
    checks = {
        "business_hours_defers_final_update": final_states["business_hours"] == DEFERRED,
        "after_hours_admits_final_update": final_states["after_hours"] == ISOLATED,
        "emergency_patch_admits_final_update_after_clearance": final_states["emergency_patch"] == ISOLATED,
        "records_lockdown_defers_final_update": final_states["records_lockdown"] == DEFERRED,
        "policy_changes_visibility_outcome": len(set(final_states.values())) > 1,
    }
    payload = {
        "project": PROJECT_NAME,
        "version": VERSION,
        "result": "PASS" if all(checks.values()) else "FAIL",
        "checks": checks,
        "policy_count": len(policy_blocks),
        "policies": policy_blocks,
    }
    payload["policy_lifecycle_certificate"] = protection_certificate(payload)
    return payload


def print_policy_lifecycle_audit(payload: dict) -> None:
    print(f"{PROJECT_NAME} v{VERSION} Policy-Aware Lifecycle Audit")
    print(f"Policy Lifecycle Result: {payload['result']}")
    print(f"Policy Count: {payload['policy_count']}")
    print(f"Policy Lifecycle Certificate: {payload['policy_lifecycle_certificate']}")
    for block in payload["policies"]:
        print(f"Policy: {block['policy']} | cert={block['policy_certificate']}")
        print(f"  description: {block['policy_description']}")
        for step in block["steps"]:
            print(f"  - {step['phase']}: firmware_update={step['firmware_update_state']} | surface_cert={step['surface_certificate']} | step_cert={step['step_certificate']}")
            print(f"    reason: {step['firmware_update_reason']}")
            if step["visible_surface"]:
                print(f"    visible: {', '.join(step['visible_surface'])}")
            if step["deferred_surface"]:
                print(f"    deferred: {', '.join(step['deferred_surface'])}")
        print(f"  final_firmware_update: {block['final_firmware_state']}")


def print_contexts() -> None:
    print(f"{PROJECT_NAME} v{VERSION} Contexts")
    for key in CONTEXT_ORDER:
        print(f"{key}: {CONTEXT_PROFILES[key]['description']}")


def print_context_audit(payload: dict) -> None:
    print(f"{PROJECT_NAME} v{VERSION} Context-Aware Audit")
    print(f"Context-Aware Result: {payload['result']}")
    print(f"Scenario: {payload['scenario']}")
    print(f"Profile: {payload['profile']}")
    print(f"Request: {payload['request']}")
    print(f"Policy: {payload['policy']}")
    print(f"Document Class: {payload['document_class']}")
    print(f"Role: {payload['role']}")
    print(f"Context Count: {payload['context_count']}")
    print(f"Context-Aware Audit Certificate: {payload['context_audit_certificate']}")
    for block in payload["blocks"]:
        print(f"Context: {block['context']} | cert={block['context_certificate']}")
        print(f"  description: {block['description']}")
        print(f"  cloud_print: {block['cloud_print']}")
        print(f"  remote_print_api: {block['remote_print_api']}")
        print(f"  admin_console: {block['admin_console']}")
        print(f"  firmware_update: {block['firmware_update']}")
        if block["visible_surface"]:
            print(f"  visible: {', '.join(block['visible_surface'])}")
        if block["deferred_surface"]:
            print(f"  deferred: {', '.join(block['deferred_surface'])}")


def print_governance_audit(payload: dict) -> None:
    print(f"{PROJECT_NAME} v{VERSION} Governance Audit")
    print(f"Scenario: {payload['scenario']}")
    print(f"Profile: {payload['profile']}")
    print(f"Request: {payload['request']}")
    print(f"Policy: {payload['policy']}")
    print(f"Document Class: {payload['document_class']}")
    print(f"Role: {payload['role']}")
    print(f"Context: {payload['context']}")
    print(f"Approval: {payload['approval']}")
    print(f"Release Mode: {payload['release_mode']}")
    print(f"Actor: {payload['actor']}")
    print(f"Job State: {payload['job_state']}")
    print(f"Retention State: {payload['retention_state']}")
    print(f"Data Destination: {payload['data_destination']}")
    if payload.get("device_health"):
        print(f"Device Health: {payload['device_health']}")
    print(f"Risk Posture: {payload['risk_posture']}")
    print(f"Compliance Mode: {payload['compliance_mode']}")
    print(f"Trust Zone: {payload['trust_zone']}")
    print(f"Evidence View: {payload['evidence_view']}")
    print(f"Recovery Action: {payload['recovery_action']}")
    print(f"Transfer Boundary: {payload['transfer_boundary']}")
    print(f"Custody State: {payload['custody_state']}")
    print(f"Final Decision: {payload['final_decision']}")
    print(f"Surface Certificate: {payload['surface_certificate']}")
    print(f"Governance Certificate: {payload['governance_certificate']}")
    print("Selected Capability States:")
    for item in payload["selected_capabilities"]:
        print(f"  - {item['capability_key']}: {item['state']} | {item['reason']} | cert={item['certificate']}")
    visible = ", ".join(payload["visible_surface"]) if payload["visible_surface"] else "none"
    deferred = ", ".join(payload["deferred_surface"]) if payload["deferred_surface"] else "none"
    print(f"Visible Surface: {visible}")
    print(f"Deferred Surface: {deferred}")


def print_roles() -> None:
    print(f"{PROJECT_NAME} v{VERSION} Roles")
    for key in ROLE_ORDER:
        print(f"{key}: {ROLE_PROFILES[key]['description']}")


def print_role_audit(payload: dict) -> None:
    print(f"{PROJECT_NAME} v{VERSION} Role-Aware Audit")
    print(f"Role-Aware Result: {payload['result']}")
    print(f"Scenario: {payload['scenario']}")
    print(f"Profile: {payload['profile']}")
    print(f"Request: {payload['request']}")
    print(f"Policy: {payload['policy']}")
    print(f"Document Class: {payload['document_class']}")
    print(f"Role Count: {payload['role_count']}")
    print(f"Role-Aware Audit Certificate: {payload['role_audit_certificate']}")
    for block in payload["blocks"]:
        print(f"Role: {block['role']} | cert={block['role_certificate']}")
        print(f"  description: {block['description']}")
        print(f"  cloud_print: {block['cloud_print']}")
        print(f"  remote_print_api: {block['remote_print_api']}")
        print(f"  admin_console: {block['admin_console']}")
        print(f"  firmware_update: {block['firmware_update']}")
        if block["visible_surface"]:
            print(f"  visible: {', '.join(block['visible_surface'])}")
        if block["deferred_surface"]:
            print(f"  deferred: {', '.join(block['deferred_surface'])}")



def print_approvals() -> None:
    print(f"{PROJECT_NAME} v{VERSION} Approvals")
    for key in APPROVAL_ORDER:
        print(f"{key}: {APPROVAL_PROFILES[key]['description']}")


def print_approval_audit(payload: dict) -> None:
    print(f"{PROJECT_NAME} v{VERSION} Approval-Chain Audit")
    print(f"Approval-Chain Result: {payload['result']}")
    print(f"Scenario: {payload['scenario']}")
    print(f"Profile: {payload['profile']}")
    print(f"Request: {payload['request']}")
    print(f"Policy: {payload['policy']}")
    print(f"Document Class: {payload['document_class']}")
    print(f"Role: {payload['role']}")
    print(f"Context: {payload['context']}")
    print(f"Approval Count: {payload['approval_count']}")
    print(f"Approval-Chain Audit Certificate: {payload['approval_audit_certificate']}")
    for block in payload["blocks"]:
        print(f"Approval: {block['approval']} | cert={block['approval_certificate']}")
        print(f"  description: {block['description']}")
        print(f"  cloud_print: {block['cloud_print']}")
        print(f"  remote_print_api: {block['remote_print_api']}")
        print(f"  admin_console: {block['admin_console']}")
        print(f"  firmware_update: {block['firmware_update']}")
        if block["visible_surface"]:
            print(f"  visible: {', '.join(block['visible_surface'])}")
        if block["deferred_surface"]:
            print(f"  deferred: {', '.join(block['deferred_surface'])}")


def print_release_modes() -> None:
    print(f"{PROJECT_NAME} v{VERSION} Release Modes")
    for key in RELEASE_MODE_ORDER:
        print(f"{key}: {RELEASE_MODES[key]['description']}")




def print_actors() -> None:
    print(f"{PROJECT_NAME} v{VERSION} Actors")
    for key in ACTOR_ORDER:
        print(f"{key}: {ACTOR_PROFILES[key]['description']}")


def print_actor_audit(payload: dict) -> None:
    print(f"{PROJECT_NAME} v{VERSION} Actor-Aware Audit")
    print(f"Actor-Aware Result: {payload['result']}")
    print(f"Scenario: {payload['scenario']}")
    print(f"Profile: {payload['profile']}")
    print(f"Request: {payload['request']}")
    print(f"Policy: {payload['policy']}")
    print(f"Document Class: {payload['document_class']}")
    print(f"Role: {payload['role']}")
    print(f"Context: {payload['context']}")
    print(f"Approval: {payload['approval']}")
    print(f"Release Mode: {payload['release_mode']}")
    print(f"Actor Count: {payload['actor_count']}")
    print(f"Actor-Aware Audit Certificate: {payload['actor_audit_certificate']}")
    for block in payload["blocks"]:
        print(f"Actor: {block['actor']} | cert={block['actor_certificate']}")
        print(f"  description: {block['description']}")
        print(f"  cloud_print: {block['cloud_print']}")
        print(f"  remote_print_api: {block['remote_print_api']}")
        print(f"  secure_release: {block['secure_release']}")
        print(f"  print_engine: {block['print_engine']}")
        print(f"  audit_logs: {block['audit_logs']}")
        print(f"  visible: {', '.join(block['visible_surface'])}")
        if block["deferred_surface"]:
            print(f"  deferred: {', '.join(block['deferred_surface'])}")

def print_release_mode_audit(payload: dict) -> None:
    print(f"{PROJECT_NAME} v{VERSION} Release-Mode Audit")
    print(f"Release-Mode Result: {payload['result']}")
    print(f"Scenario: {payload['scenario']}")
    print(f"Profile: {payload['profile']}")
    print(f"Request: {payload['request']}")
    print(f"Policy: {payload['policy']}")
    print(f"Document Class: {payload['document_class']}")
    print(f"Role: {payload['role']}")
    print(f"Context: {payload['context']}")
    print(f"Approval: {payload['approval']}")
    print(f"Release Mode Count: {payload['release_mode_count']}")
    print(f"Release-Mode Audit Certificate: {payload['release_mode_audit_certificate']}")
    for block in payload["blocks"]:
        print(f"Release Mode: {block['release_mode']} | cert={block['release_mode_certificate']}")
        print(f"  description: {block['description']}")
        print(f"  cloud_print: {block['cloud_print']}")
        print(f"  remote_print_api: {block['remote_print_api']}")
        print(f"  secure_release: {block['secure_release']}")
        print(f"  print_engine: {block['print_engine']}")
        if block["visible_surface"]:
            print(f"  visible: {', '.join(block['visible_surface'])}")
        if block["deferred_surface"]:
            print(f"  deferred: {', '.join(block['deferred_surface'])}")


def print_job_states() -> None:
    print(f"{PROJECT_NAME} v{VERSION} Job States")
    for key in JOB_STATE_ORDER:
        print(f"{key}: {JOB_STATES[key]['description']}")


def print_job_state_audit(payload: dict) -> None:
    print(f"{PROJECT_NAME} v{VERSION} Job-State Audit")
    print(f"Job-State Result: {payload['result']}")
    print(f"Scenario: {payload['scenario']}")
    print(f"Profile: {payload['profile']}")
    print(f"Request: {payload['request']}")
    print(f"Policy: {payload['policy']}")
    print(f"Document Class: {payload['document_class']}")
    print(f"Role: {payload['role']}")
    print(f"Context: {payload['context']}")
    print(f"Approval: {payload['approval']}")
    print(f"Release Mode: {payload['release_mode']}")
    print(f"Actor: {payload['actor']}")
    print(f"Job State Count: {payload['job_state_count']}")
    print(f"Job-State Audit Certificate: {payload['job_state_audit_certificate']}")
    for block in payload["blocks"]:
        print(f"Job State: {block['job_state']} | cert={block['job_state_certificate']}")
        print(f"  description: {block['description']}")
        print(f"  cloud_print: {block['cloud_print']}")
        print(f"  remote_print_api: {block['remote_print_api']}")
        print(f"  secure_release: {block['secure_release']}")
        print(f"  print_engine: {block['print_engine']}")
        print(f"  job_queue: {block['job_queue']}")
        print(f"  audit_logs: {block['audit_logs']}")
        if block["visible_surface"]:
            print(f"  visible: {', '.join(block['visible_surface'])}")
        if block["deferred_surface"]:
            print(f"  deferred: {', '.join(block['deferred_surface'])}")



def print_retention_states() -> None:
    print(f"{PROJECT_NAME} v{VERSION} Retention States")
    for key in RETENTION_STATE_ORDER:
        print(f"{key}: {RETENTION_STATES[key]['description']}")


def print_retention_state_audit(payload: dict) -> None:
    print(f"{PROJECT_NAME} v{VERSION} Retention-State Audit")
    print(f"Retention-State Result: {payload['result']}")
    print(f"Scenario: {payload['scenario']}")
    print(f"Profile: {payload['profile']}")
    print(f"Request: {payload['request']}")
    print(f"Policy: {payload['policy']}")
    print(f"Document Class: {payload['document_class']}")
    print(f"Role: {payload['role']}")
    print(f"Context: {payload['context']}")
    print(f"Approval: {payload['approval']}")
    print(f"Release Mode: {payload['release_mode']}")
    print(f"Actor: {payload['actor']}")
    print(f"Job State: {payload['job_state']}")
    print(f"Retention State Count: {payload['retention_state_count']}")
    print(f"Retention-State Audit Certificate: {payload['retention_state_audit_certificate']}")
    for block in payload["blocks"]:
        print(f"Retention State: {block['retention_state']} | cert={block['retention_state_certificate']}")
        print(f"  description: {block['description']}")
        print(f"  job_queue: {block['job_queue']}")
        print(f"  audit_logs: {block['audit_logs']}")
        print(f"  document_cache: {block['document_cache']}")
        print(f"  print_engine: {block['print_engine']}")
        print(f"  cloud_print: {block['cloud_print']}")
        if block["visible_surface"]:
            print(f"  visible: {', '.join(block['visible_surface'])}")
        if block["deferred_surface"]:
            print(f"  deferred: {', '.join(block['deferred_surface'])}")

def print_data_destinations() -> None:
    print(f"{PROJECT_NAME} v{VERSION} Data Destinations")
    for key in DATA_DESTINATION_ORDER:
        print(f"{key}: {DATA_DESTINATIONS[key]['description']}")


def print_data_destination_audit(payload: dict) -> None:
    print(f"{PROJECT_NAME} v{VERSION} Data-Destination Audit")
    print(f"Data-Destination Result: {payload['result']}")
    print(f"Scenario: {payload['scenario']}")
    print(f"Profile: {payload['profile']}")
    print(f"Request: {payload['request']}")
    print(f"Policy: {payload['policy']}")
    print(f"Document Class: {payload['document_class']}")
    print(f"Role: {payload['role']}")
    print(f"Context: {payload['context']}")
    print(f"Approval: {payload['approval']}")
    print(f"Release Mode: {payload['release_mode']}")
    print(f"Actor: {payload['actor']}")
    print(f"Job State: {payload['job_state']}")
    print(f"Retention State: {payload['retention_state']}")
    print(f"Data Destination Count: {payload['data_destination_count']}")
    print(f"Data-Destination Audit Certificate: {payload['data_destination_audit_certificate']}")
    for block in payload["blocks"]:
        print(f"Data Destination: {block['data_destination']} | cert={block['data_destination_certificate']}")
        print(f"  description: {block['description']}")
        print(f"  cloud_print: {block['cloud_print']}")
        print(f"  remote_print_api: {block['remote_print_api']}")
        print(f"  scan_to_email: {block['scan_to_email']}")
        print(f"  fax_module: {block['fax_module']}")
        print(f"  document_cache: {block['document_cache']}")
        print(f"  audit_logs: {block['audit_logs']}")
        print(f"  print_engine: {block['print_engine']}")
        if block["visible_surface"]:
            print(f"  visible: {', '.join(block['visible_surface'])}")
        if block["deferred_surface"]:
            print(f"  deferred: {', '.join(block['deferred_surface'])}")


def print_device_healths() -> None:
    print(f"{PROJECT_NAME} v{VERSION} Device Health States")
    for key in DEVICE_HEALTH_ORDER:
        print(f"{key}: {DEVICE_HEALTHS[key]['description']}")


def print_device_health_audit(payload: dict) -> None:
    print(f"{PROJECT_NAME} v{VERSION} Device-Health Audit")
    print(f"Device-Health Result: {payload['result']}")
    print(f"Scenario: {payload['scenario']}")
    print(f"Profile: {payload['profile']}")
    print(f"Request: {payload['request']}")
    print(f"Policy: {payload['policy']}")
    print(f"Document Class: {payload['document_class']}")
    print(f"Role: {payload['role']}")
    print(f"Context: {payload['context']}")
    print(f"Approval: {payload['approval']}")
    print(f"Release Mode: {payload['release_mode']}")
    print(f"Actor: {payload['actor']}")
    print(f"Job State: {payload['job_state']}")
    print(f"Retention State: {payload['retention_state']}")
    print(f"Data Destination: {payload['data_destination']}")
    print(f"Device Health Count: {payload['device_health_count']}")
    print(f"Device-Health Audit Certificate: {payload['device_health_audit_certificate']}")
    for block in payload["blocks"]:
        print(f"Device Health: {block['device_health']} | cert={block['device_health_certificate']}")
        print(f"  description: {block['description']}")
        print(f"  print_engine: {block['print_engine']}")
        print(f"  paper_feed: {block['paper_feed']}")
        print(f"  ink_toner_system: {block['ink_toner_system']}")
        print(f"  cloud_print: {block['cloud_print']}")
        print(f"  remote_print_api: {block['remote_print_api']}")
        print(f"  admin_console: {block['admin_console']}")
        print(f"  firmware_update: {block['firmware_update']}")
        print(f"  audit_logs: {block['audit_logs']}")
        if block["visible_surface"]:
            print(f"  visible: {', '.join(block['visible_surface'])}")
        if block["deferred_surface"]:
            print(f"  deferred: {', '.join(block['deferred_surface'])}")



def print_risk_postures() -> None:
    print(f"{PROJECT_NAME} v{VERSION} Risk Postures")
    for key in RISK_POSTURE_ORDER:
        print(f"{key}: {RISK_POSTURES[key]['description']}")


def print_risk_posture_audit(payload: dict) -> None:
    print(f"{PROJECT_NAME} v{VERSION} Risk-Posture Audit")
    print(f"Risk-Posture Result: {payload['result']}")
    print(f"Scenario: {payload['scenario']}")
    print(f"Profile: {payload['profile']}")
    print(f"Request: {payload['request']}")
    print(f"Policy: {payload['policy']}")
    print(f"Document Class: {payload['document_class']}")
    print(f"Role: {payload['role']}")
    print(f"Context: {payload['context']}")
    print(f"Approval: {payload['approval']}")
    print(f"Release Mode: {payload['release_mode']}")
    print(f"Actor: {payload['actor']}")
    print(f"Job State: {payload['job_state']}")
    print(f"Retention State: {payload['retention_state']}")
    print(f"Data Destination: {payload['data_destination']}")
    print(f"Device Health: {payload['device_health']}")
    print(f"Risk Posture Count: {payload['risk_posture_count']}")
    print(f"Risk-Posture Audit Certificate: {payload['risk_posture_audit_certificate']}")
    for block in payload["blocks"]:
        print(f"Risk Posture: {block['risk_posture']} | cert={block['risk_posture_certificate']}")
        print(f"  description: {block['description']}")
        print(f"  print_engine: {block['print_engine']}")
        print(f"  cloud_print: {block['cloud_print']}")
        print(f"  remote_print_api: {block['remote_print_api']}")
        print(f"  scan_to_email: {block['scan_to_email']}")
        print(f"  document_cache: {block['document_cache']}")
        print(f"  admin_console: {block['admin_console']}")
        print(f"  firmware_update: {block['firmware_update']}")
        print(f"  audit_logs: {block['audit_logs']}")
        if block["visible_surface"]:
            print(f"  visible: {', '.join(block['visible_surface'])}")
        if block["deferred_surface"]:
            print(f"  deferred: {', '.join(block['deferred_surface'])}")




def print_trust_zones() -> None:
    print(f"{PROJECT_NAME} v{VERSION} Trust Zones")
    for key in TRUST_ZONE_ORDER:
        print(f"{key}: {TRUST_ZONES[key]['description']}")


def print_trust_zone_audit(payload: dict) -> None:
    print(f"{PROJECT_NAME} v{VERSION} Trust-Zone Audit")
    print(f"Trust-Zone Result: {payload['result']}")
    print(f"Scenario: {payload['scenario']}")
    print(f"Profile: {payload['profile']}")
    print(f"Request: {payload['request']}")
    print(f"Policy: {payload['policy']}")
    print(f"Document Class: {payload['document_class']}")
    print(f"Role: {payload['role']}")
    print(f"Context: {payload['context']}")
    print(f"Approval: {payload['approval']}")
    print(f"Release Mode: {payload['release_mode']}")
    print(f"Actor: {payload['actor']}")
    print(f"Job State: {payload['job_state']}")
    print(f"Retention State: {payload['retention_state']}")
    print(f"Data Destination: {payload['data_destination']}")
    print(f"Device Health: {payload['device_health']}")
    print(f"Risk Posture: {payload['risk_posture']}")
    print(f"Compliance Mode: {payload['compliance_mode']}")
    print(f"Trust Zone Count: {payload['trust_zone_count']}")
    print(f"Trust-Zone Audit Certificate: {payload['trust_zone_audit_certificate']}")
    for block in payload["blocks"]:
        print(f"Trust Zone: {block['trust_zone']} | cert={block['trust_zone_certificate']}")
        print(f"  description: {block['description']}")
        print(f"  print_engine: {block['print_engine']}")
        print(f"  cloud_print: {block['cloud_print']}")
        print(f"  remote_print_api: {block['remote_print_api']}")
        print(f"  scan_to_email: {block['scan_to_email']}")
        print(f"  document_cache: {block['document_cache']}")
        print(f"  admin_console: {block['admin_console']}")
        print(f"  firmware_update: {block['firmware_update']}")
        print(f"  audit_logs: {block['audit_logs']}")
        print(f"  secure_release: {block['secure_release']}")
        if block["visible_surface"]:
            print(f"  visible: {', '.join(block['visible_surface'])}")
        if block["deferred_surface"]:
            print(f"  deferred: {', '.join(block['deferred_surface'])}")




def print_evidence_views() -> None:
    print(f"{PROJECT_NAME} v{VERSION} Evidence Views")
    for key in EVIDENCE_VIEW_ORDER:
        print(f"{key}: {EVIDENCE_VIEWS[key]['description']}")


def print_evidence_view_audit(payload: dict) -> None:
    print(f"{PROJECT_NAME} v{VERSION} Evidence-View Audit")
    print(f"Evidence-View Result: {payload['result']}")
    print(f"Scenario: {payload['scenario']}")
    print(f"Profile: {payload['profile']}")
    print(f"Request: {payload['request']}")
    print(f"Policy: {payload['policy']}")
    print(f"Document Class: {payload['document_class']}")
    print(f"Role: {payload['role']}")
    print(f"Context: {payload['context']}")
    print(f"Approval: {payload['approval']}")
    print(f"Release Mode: {payload['release_mode']}")
    print(f"Actor: {payload['actor']}")
    print(f"Job State: {payload['job_state']}")
    print(f"Retention State: {payload['retention_state']}")
    print(f"Data Destination: {payload['data_destination']}")
    print(f"Device Health: {payload['device_health']}")
    print(f"Risk Posture: {payload['risk_posture']}")
    print(f"Compliance Mode: {payload['compliance_mode']}")
    print(f"Trust Zone: {payload['trust_zone']}")
    print(f"Evidence View Count: {payload['evidence_view_count']}")
    print(f"Evidence-View Audit Certificate: {payload['evidence_view_audit_certificate']}")
    for block in payload["blocks"]:
        print(f"Evidence View: {block['evidence_view']} | cert={block['evidence_view_certificate']}")
        print(f"  description: {block['description']}")
        print(f"  print_engine: {block['print_engine']}")
        print(f"  cloud_print: {block['cloud_print']}")
        print(f"  remote_print_api: {block['remote_print_api']}")
        print(f"  document_cache: {block['document_cache']}")
        print(f"  audit_logs: {block['audit_logs']}")
        print(f"  job_queue: {block['job_queue']}")
        print(f"  secure_release: {block['secure_release']}")
        if block["visible_surface"]:
            print(f"  visible: {', '.join(block['visible_surface'])}")
        if block["deferred_surface"]:
            print(f"  deferred: {', '.join(block['deferred_surface'])}")



def print_recovery_actions() -> None:
    print(f"{PROJECT_NAME} v{VERSION} Recovery Actions")
    for key in RECOVERY_ACTION_ORDER:
        print(f"{key}: {RECOVERY_ACTIONS[key]['description']}")


def print_recovery_action_audit(payload: dict) -> None:
    print(f"{PROJECT_NAME} v{VERSION} Recovery-Action Audit")
    print(f"Recovery-Action Result: {payload['result']}")
    print(f"Scenario: {payload['scenario']}")
    print(f"Profile: {payload['profile']}")
    print(f"Request: {payload['request']}")
    print(f"Policy: {payload['policy']}")
    print(f"Document Class: {payload['document_class']}")
    print(f"Role: {payload['role']}")
    print(f"Context: {payload['context']}")
    print(f"Approval: {payload['approval']}")
    print(f"Release Mode: {payload['release_mode']}")
    print(f"Actor: {payload['actor']}")
    print(f"Job State: {payload['job_state']}")
    print(f"Retention State: {payload['retention_state']}")
    print(f"Data Destination: {payload['data_destination']}")
    print(f"Device Health: {payload['device_health']}")
    print(f"Risk Posture: {payload['risk_posture']}")
    print(f"Compliance Mode: {payload['compliance_mode']}")
    print(f"Trust Zone: {payload['trust_zone']}")
    print(f"Evidence View: {payload['evidence_view']}")
    print(f"Recovery Action Count: {payload['recovery_action_count']}")
    print(f"Recovery-Action Audit Certificate: {payload['recovery_action_audit_certificate']}")
    for block in payload["blocks"]:
        print(f"Recovery Action: {block['recovery_action']} | cert={block['recovery_action_certificate']}")
        print(f"  description: {block['description']}")
        print(f"  print_engine: {block['print_engine']}")
        print(f"  cloud_print: {block['cloud_print']}")
        print(f"  remote_print_api: {block['remote_print_api']}")
        print(f"  document_cache: {block['document_cache']}")
        print(f"  audit_logs: {block['audit_logs']}")
        print(f"  job_queue: {block['job_queue']}")
        print(f"  secure_release: {block['secure_release']}")
        if block["visible_surface"]:
            print(f"  visible: {', '.join(block['visible_surface'])}")
        if block["deferred_surface"]:
            print(f"  deferred: {', '.join(block['deferred_surface'])}")


def print_transfer_boundaries() -> None:
    print(f"{PROJECT_NAME} v{VERSION} Transfer Boundaries")
    for key in TRANSFER_BOUNDARY_ORDER:
        print(f"{key}: {TRANSFER_BOUNDARIES[key]['description']}")


def print_transfer_boundary_audit(payload: dict) -> None:
    print(f"{PROJECT_NAME} v{VERSION} Transfer-Boundary Audit")
    print(f"Transfer-Boundary Result: {payload['result']}")
    print(f"Scenario: {payload['scenario']}")
    print(f"Profile: {payload['profile']}")
    print(f"Request: {payload['request']}")
    print(f"Policy: {payload['policy']}")
    print(f"Document Class: {payload['document_class']}")
    print(f"Role: {payload['role']}")
    print(f"Context: {payload['context']}")
    print(f"Approval: {payload['approval']}")
    print(f"Release Mode: {payload['release_mode']}")
    print(f"Actor: {payload['actor']}")
    print(f"Job State: {payload['job_state']}")
    print(f"Retention State: {payload['retention_state']}")
    print(f"Data Destination: {payload['data_destination']}")
    print(f"Device Health: {payload['device_health']}")
    print(f"Risk Posture: {payload['risk_posture']}")
    print(f"Compliance Mode: {payload['compliance_mode']}")
    print(f"Trust Zone: {payload['trust_zone']}")
    print(f"Evidence View: {payload['evidence_view']}")
    print(f"Recovery Action: {payload['recovery_action']}")
    print(f"Transfer Boundary Count: {payload['transfer_boundary_count']}")
    print(f"Transfer-Boundary Audit Certificate: {payload['transfer_boundary_audit_certificate']}")
    for block in payload["blocks"]:
        print(f"Transfer Boundary: {block['transfer_boundary']} | cert={block['transfer_boundary_certificate']}")
        print(f"  description: {block['description']}")
        print(f"  print_engine: {block['print_engine']}")
        print(f"  cloud_print: {block['cloud_print']}")
        print(f"  remote_print_api: {block['remote_print_api']}")
        print(f"  scan_to_email: {block['scan_to_email']}")
        print(f"  document_cache: {block['document_cache']}")
        print(f"  admin_console: {block['admin_console']}")
        print(f"  firmware_update: {block['firmware_update']}")
        print(f"  audit_logs: {block['audit_logs']}")
        print(f"  job_queue: {block['job_queue']}")
        print(f"  secure_release: {block['secure_release']}")
        if block["visible_surface"]:
            print(f"  visible: {', '.join(block['visible_surface'])}")
        if block["deferred_surface"]:
            print(f"  deferred: {', '.join(block['deferred_surface'])}")


def print_compliance_modes() -> None:
    print(f"{PROJECT_NAME} v{VERSION} Compliance Modes")
    for key in COMPLIANCE_MODE_ORDER:
        print(f"{key}: {COMPLIANCE_MODES[key]['description']}")


def print_compliance_mode_audit(payload: dict) -> None:
    print(f"{PROJECT_NAME} v{VERSION} Compliance-Mode Audit")
    print(f"Compliance-Mode Result: {payload['result']}")
    print(f"Scenario: {payload['scenario']}")
    print(f"Profile: {payload['profile']}")
    print(f"Request: {payload['request']}")
    print(f"Policy: {payload['policy']}")
    print(f"Document Class: {payload['document_class']}")
    print(f"Role: {payload['role']}")
    print(f"Context: {payload['context']}")
    print(f"Approval: {payload['approval']}")
    print(f"Release Mode: {payload['release_mode']}")
    print(f"Actor: {payload['actor']}")
    print(f"Job State: {payload['job_state']}")
    print(f"Retention State: {payload['retention_state']}")
    print(f"Data Destination: {payload['data_destination']}")
    print(f"Device Health: {payload['device_health']}")
    print(f"Risk Posture: {payload['risk_posture']}")
    print(f"Compliance Mode Count: {payload['compliance_mode_count']}")
    print(f"Compliance-Mode Audit Certificate: {payload['compliance_mode_audit_certificate']}")
    for block in payload["blocks"]:
        print(f"Compliance Mode: {block['compliance_mode']} | cert={block['compliance_mode_certificate']}")
        print(f"  description: {block['description']}")
        print(f"  print_engine: {block['print_engine']}")
        print(f"  cloud_print: {block['cloud_print']}")
        print(f"  remote_print_api: {block['remote_print_api']}")
        print(f"  scan_to_email: {block['scan_to_email']}")
        print(f"  document_cache: {block['document_cache']}")
        print(f"  admin_console: {block['admin_console']}")
        print(f"  firmware_update: {block['firmware_update']}")
        print(f"  audit_logs: {block['audit_logs']}")
        print(f"  secure_release: {block['secure_release']}")
        if block["visible_surface"]:
            print(f"  visible: {', '.join(block['visible_surface'])}")
        if block["deferred_surface"]:
            print(f"  deferred: {', '.join(block['deferred_surface'])}")


def print_policies() -> None:
    print(f"{PROJECT_NAME} v{VERSION} Policies")
    for key in POLICY_ORDER:
        print(f"{key}: {POLICY_PROFILES[key]['description']}")



def print_custody_states() -> None:
    print(f"{PROJECT_NAME} v{VERSION} Custody States")
    for key in CUSTODY_STATE_ORDER:
        print(f"{key}: {CUSTODY_STATES[key]['description']}")


def print_custody_state_audit(payload: dict) -> None:
    print(f"{PROJECT_NAME} v{VERSION} Chain-of-Custody Audit")
    print(f"Chain-of-Custody Result: {payload['result']}")
    print(f"Scenario: {payload['scenario']}")
    print(f"Profile: {payload['profile']}")
    print(f"Request: {payload['request']}")
    print(f"Policy: {payload['policy']}")
    print(f"Document Class: {payload['document_class']}")
    print(f"Role: {payload['role']}")
    print(f"Context: {payload['context']}")
    print(f"Approval: {payload['approval']}")
    print(f"Release Mode: {payload['release_mode']}")
    print(f"Actor: {payload['actor']}")
    print(f"Job State: {payload['job_state']}")
    print(f"Retention State: {payload['retention_state']}")
    print(f"Data Destination: {payload['data_destination']}")
    print(f"Device Health: {payload['device_health']}")
    print(f"Risk Posture: {payload['risk_posture']}")
    print(f"Compliance Mode: {payload['compliance_mode']}")
    print(f"Trust Zone: {payload['trust_zone']}")
    print(f"Evidence View: {payload['evidence_view']}")
    print(f"Recovery Action: {payload['recovery_action']}")
    print(f"Transfer Boundary: {payload['transfer_boundary']}")
    print(f"Custody State Count: {payload['custody_state_count']}")
    print(f"Chain-of-Custody Audit Certificate: {payload['custody_state_audit_certificate']}")
    for block in payload["blocks"]:
        print(f"Custody State: {block['custody_state']} | cert={block['custody_state_certificate']}")
        print(f"  description: {block['description']}")
        print(f"  print_engine: {block['print_engine']}")
        print(f"  cloud_print: {block['cloud_print']}")
        print(f"  remote_print_api: {block['remote_print_api']}")
        print(f"  document_cache: {block['document_cache']}")
        print(f"  admin_console: {block['admin_console']}")
        print(f"  firmware_update: {block['firmware_update']}")
        print(f"  audit_logs: {block['audit_logs']}")
        print(f"  job_queue: {block['job_queue']}")
        print(f"  secure_release: {block['secure_release']}")
        if block["visible_surface"]:
            print(f"  visible: {', '.join(block['visible_surface'])}")
        if block["deferred_surface"]:
            print(f"  deferred: {', '.join(block['deferred_surface'])}")


def print_final_decisions() -> None:
    print(f"{PROJECT_NAME} v{VERSION} Final Decisions")
    for key in FINAL_DECISION_ORDER:
        print(f"{key}: {FINAL_DECISIONS[key]['description']}")


def print_final_decision_audit(payload: dict) -> None:
    print(f"{PROJECT_NAME} v{VERSION} Final-Decision Audit")
    print(f"Final-Decision Result: {payload['result']}")
    print(f"Scenario: {payload['scenario']}")
    print(f"Profile: {payload['profile']}")
    print(f"Request: {payload['request']}")
    print(f"Policy: {payload['policy']}")
    print(f"Document Class: {payload['document_class']}")
    print(f"Role: {payload['role']}")
    print(f"Context: {payload['context']}")
    print(f"Approval: {payload['approval']}")
    print(f"Release Mode: {payload['release_mode']}")
    print(f"Actor: {payload['actor']}")
    print(f"Job State: {payload['job_state']}")
    print(f"Retention State: {payload['retention_state']}")
    print(f"Data Destination: {payload['data_destination']}")
    print(f"Device Health: {payload['device_health']}")
    print(f"Risk Posture: {payload['risk_posture']}")
    print(f"Compliance Mode: {payload['compliance_mode']}")
    print(f"Trust Zone: {payload['trust_zone']}")
    print(f"Evidence View: {payload['evidence_view']}")
    print(f"Recovery Action: {payload['recovery_action']}")
    print(f"Transfer Boundary: {payload['transfer_boundary']}")
    print(f"Custody State: {payload['custody_state']}")
    print(f"Final Decision Count: {payload['final_decision_count']}")
    print(f"Final-Decision Audit Certificate: {payload['final_decision_audit_certificate']}")
    for block in payload["blocks"]:
        print(f"Final Decision: {block['final_decision']} | cert={block['final_decision_certificate']}")
        print(f"  description: {block['description']}")
        print(f"  print_engine: {block['print_engine']}")
        print(f"  cloud_print: {block['cloud_print']}")
        print(f"  remote_print_api: {block['remote_print_api']}")
        print(f"  document_cache: {block['document_cache']}")
        print(f"  admin_console: {block['admin_console']}")
        print(f"  firmware_update: {block['firmware_update']}")
        print(f"  audit_logs: {block['audit_logs']}")
        print(f"  job_queue: {block['job_queue']}")
        print(f"  secure_release: {block['secure_release']}")
        if block["visible_surface"]:
            print(f"  visible: {', '.join(block['visible_surface'])}")
        if block["deferred_surface"]:
            print(f"  deferred: {', '.join(block['deferred_surface'])}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="CAPS-Printer structural visibility demonstration")
    parser.add_argument("--quickstart", action="store_true")
    parser.add_argument("--verify", action="store_true")
    parser.add_argument("--challenge", action="store_true")
    parser.add_argument("--invariants", action="store_true")
    parser.add_argument("--manifest", action="store_true")
    parser.add_argument("--profiles", action="store_true")
    parser.add_argument("--requests", action="store_true")
    parser.add_argument("--surface", action="store_true")
    parser.add_argument("--matrix", action="store_true")
    parser.add_argument("--compare", action="store_true")
    parser.add_argument("--request-compare", action="store_true")
    parser.add_argument("--dependency-graph", action="store_true")
    parser.add_argument("--transition-audit", action="store_true")
    parser.add_argument("--lifecycle-audit", action="store_true")
    parser.add_argument("--policy-lifecycle-audit", action="store_true")
    parser.add_argument("--policies", action="store_true")
    parser.add_argument("--document-classes", action="store_true")
    parser.add_argument("--document-class-audit", action="store_true")
    parser.add_argument("--roles", action="store_true")
    parser.add_argument("--role-audit", action="store_true")
    parser.add_argument("--contexts", action="store_true")
    parser.add_argument("--context-audit", action="store_true")
    parser.add_argument("--approvals", action="store_true")
    parser.add_argument("--approval-audit", action="store_true")
    parser.add_argument("--release-modes", action="store_true")
    parser.add_argument("--release-mode-audit", action="store_true")
    parser.add_argument("--actors", action="store_true")
    parser.add_argument("--actor-audit", action="store_true")
    parser.add_argument("--job-states", action="store_true")
    parser.add_argument("--job-state-audit", action="store_true")
    parser.add_argument("--retention-states", action="store_true")
    parser.add_argument("--retention-state-audit", action="store_true")
    parser.add_argument("--data-destinations", action="store_true")
    parser.add_argument("--data-destination-audit", action="store_true")
    parser.add_argument("--device-healths", action="store_true")
    parser.add_argument("--device-health-audit", action="store_true")
    parser.add_argument("--risk-postures", action="store_true")
    parser.add_argument("--risk-posture-audit", action="store_true")
    parser.add_argument("--compliance-modes", action="store_true")
    parser.add_argument("--compliance-mode-audit", action="store_true")
    parser.add_argument("--trust-zones", action="store_true")
    parser.add_argument("--trust-zone-audit", action="store_true")
    parser.add_argument("--evidence-views", action="store_true")
    parser.add_argument("--evidence-view-audit", action="store_true")
    parser.add_argument("--recovery-actions", action="store_true")
    parser.add_argument("--recovery-action-audit", action="store_true")
    parser.add_argument("--transfer-boundaries", action="store_true")
    parser.add_argument("--transfer-boundary-audit", action="store_true")
    parser.add_argument("--custody-states", action="store_true")
    parser.add_argument("--chain-of-custody-audit", action="store_true")
    parser.add_argument("--final-decisions", action="store_true")
    parser.add_argument("--final-decision-audit", action="store_true")
    parser.add_argument("--governance-audit", action="store_true")
    parser.add_argument("--from-scenario", choices=SCENARIO_ORDER, default="maintenance_with_jobs")
    parser.add_argument("--to-scenario", choices=SCENARIO_ORDER, default="maintenance_after_jobs_clear")
    parser.add_argument("--scenario", choices=SCENARIO_ORDER, default="local_print")
    parser.add_argument("--profile", choices=PROFILE_ORDER, default="balanced")
    parser.add_argument("--policy", choices=POLICY_ORDER, default="standard")
    parser.add_argument("--document-class", choices=DOCUMENT_CLASS_ORDER, default="public_document")
    parser.add_argument("--role", choices=ROLE_ORDER, default="employee")
    parser.add_argument("--context", choices=CONTEXT_ORDER, default="trusted_office_device")
    parser.add_argument("--approval", choices=APPROVAL_ORDER, default="manager_approved")
    parser.add_argument("--release-mode", choices=RELEASE_MODE_ORDER, default="secure_pull_release")
    parser.add_argument("--actor", choices=ACTOR_ORDER, default="requester")
    parser.add_argument("--job-state", choices=JOB_STATE_ORDER, default="submitted_job")
    parser.add_argument("--retention-state", choices=RETENTION_STATE_ORDER, default="short_spool_retention")
    parser.add_argument("--data-destination", choices=DATA_DESTINATION_ORDER, default="local_printer_only")
    parser.add_argument("--device-health", choices=DEVICE_HEALTH_ORDER, default="healthy_device")
    parser.add_argument("--risk-posture", choices=RISK_POSTURE_ORDER, default="normal_risk")
    parser.add_argument("--compliance-mode", choices=COMPLIANCE_MODE_ORDER, default="ordinary_mode")
    parser.add_argument("--trust-zone", choices=TRUST_ZONE_ORDER, default="local_trusted_zone")
    parser.add_argument("--evidence-view", choices=EVIDENCE_VIEW_ORDER, default="operator_evidence_view")
    parser.add_argument("--recovery-action", choices=RECOVERY_ACTION_ORDER, default="no_recovery_action")
    parser.add_argument("--transfer-boundary", choices=TRANSFER_BOUNDARY_ORDER, default="no_transfer")
    parser.add_argument("--custody-state", choices=CUSTODY_STATE_ORDER, default="no_custody")
    parser.add_argument("--final-decision", choices=FINAL_DECISION_ORDER, default="hold_output")
    parser.add_argument("--request", choices=("normal",) + REQUEST_ORDER, default="normal")
    parser.add_argument("--explain", action="store_true")
    parser.add_argument("--json", action="store_true")
    return parser


def main(argv: List[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.quickstart:
        quickstart()
        return 0

    if args.verify:
        payload = run_verify()
        if args.json:
            print(json.dumps(payload, indent=2, sort_keys=True))
        else:
            print_key_value_payload(payload, "verification_certificate")
        return 0 if payload["result"] == "PASS" else 1

    if args.challenge:
        payload = run_challenge()
        if args.json:
            print(json.dumps(payload, indent=2, sort_keys=True))
        else:
            print_key_value_payload(payload, "challenge_certificate")
        return 0 if payload["result"] == "PASS" else 1

    if args.invariants:
        payload = run_invariants()
        if args.json:
            print(json.dumps(payload, indent=2, sort_keys=True))
        else:
            print_key_value_payload(payload, "invariant_certificate")
        return 0 if payload["result"] == "PASS" else 1

    if args.manifest:
        payload = manifest()
        if args.json:
            print(json.dumps(payload, indent=2, sort_keys=True))
        else:
            print_manifest(payload)
        return 0

    if args.profiles:
        print_profiles()
        return 0

    if args.policies:
        print_policies()
        return 0

    if args.document_classes:
        print_document_classes()
        return 0

    if args.roles:
        print_roles()
        return 0

    if args.contexts:
        print_contexts()
        return 0

    if args.approvals:
        print_approvals()
        return 0

    if args.release_modes:
        print_release_modes()
        return 0

    if args.actors:
        print_actors()
        return 0

    if args.job_states:
        print_job_states()
        return 0

    if args.retention_states:
        print_retention_states()
        return 0

    if args.data_destinations:
        print_data_destinations()
        return 0

    if args.device_healths:
        print_device_healths()
        return 0

    if args.risk_postures:
        print_risk_postures()
        return 0

    if args.compliance_modes:
        print_compliance_modes()
        return 0

    if args.trust_zones:
        print_trust_zones()
        return 0

    if args.evidence_views:
        print_evidence_views()
        return 0

    if args.recovery_actions:
        print_recovery_actions()
        return 0

    if args.transfer_boundaries:
        print_transfer_boundaries()
        return 0

    if args.requests:
        print_requests()
        return 0

    if args.dependency_graph:
        print_dependency_graph()
        return 0

    if args.transition_audit:
        payload = transition_audit(args.from_scenario, args.to_scenario, args.profile, args.request)
        if args.json:
            print(json.dumps(payload, indent=2, sort_keys=True))
        else:
            print_transition_audit(payload)
        return 0

    if args.lifecycle_audit:
        payload = lifecycle_audit()
        if args.json:
            print(json.dumps(payload, indent=2, sort_keys=True))
        else:
            print_lifecycle_audit(payload)
        return 0 if payload["result"] == "PASS" else 1

    if args.policy_lifecycle_audit:
        payload = policy_lifecycle_audit()
        if args.json:
            print(json.dumps(payload, indent=2, sort_keys=True))
        else:
            print_policy_lifecycle_audit(payload)
        return 0 if payload["result"] == "PASS" else 1

    if args.document_class_audit:
        payload = document_class_audit(args.policy, args.scenario, args.profile, args.request)
        if args.json:
            print(json.dumps(payload, indent=2, sort_keys=True))
        else:
            print_document_class_audit(payload)
        return 0 if payload["result"] == "PASS" else 1

    if args.role_audit:
        payload = role_audit(args.policy, args.document_class, args.scenario, args.profile, args.request)
        if args.json:
            print(json.dumps(payload, indent=2, sort_keys=True))
        else:
            print_role_audit(payload)
        return 0 if payload["result"] == "PASS" else 1

    if args.context_audit:
        payload = context_audit(args.policy, args.document_class, args.role, args.scenario, args.profile, args.request)
        if args.json:
            print(json.dumps(payload, indent=2, sort_keys=True))
        else:
            print_context_audit(payload)
        return 0 if payload["result"] == "PASS" else 1

    if args.approval_audit:
        payload = approval_audit(args.policy, args.document_class, args.role, args.context, args.scenario, args.profile, args.request)
        if args.json:
            print(json.dumps(payload, indent=2, sort_keys=True))
        else:
            print_approval_audit(payload)
        return 0 if payload["result"] == "PASS" else 1

    if args.release_mode_audit:
        payload = release_mode_audit(args.policy, args.document_class, args.role, args.context, args.approval, args.scenario, args.profile, args.request)
        if args.json:
            print(json.dumps(payload, indent=2, sort_keys=True))
        else:
            print_release_mode_audit(payload)
        return 0 if payload["result"] == "PASS" else 1

    if args.actor_audit:
        payload = actor_audit(args.policy, args.document_class, args.role, args.context, args.approval, args.release_mode, args.scenario, args.profile, args.request)
        if args.json:
            print(json.dumps(payload, indent=2, sort_keys=True))
        else:
            print_actor_audit(payload)
        return 0 if payload["result"] == "PASS" else 1

    if args.job_state_audit:
        payload = job_state_audit(args.policy, args.document_class, args.role, args.context, args.approval, args.release_mode, args.actor, args.scenario, args.profile, args.request)
        if args.json:
            print(json.dumps(payload, indent=2, sort_keys=True))
        else:
            print_job_state_audit(payload)
        return 0 if payload["result"] == "PASS" else 1

    if args.retention_state_audit:
        payload = retention_state_audit(args.policy, args.document_class, args.role, args.context, args.approval, args.release_mode, args.actor, args.job_state, args.scenario, args.profile, args.request)
        if args.json:
            print(json.dumps(payload, indent=2, sort_keys=True))
        else:
            print_retention_state_audit(payload)
        return 0 if payload["result"] == "PASS" else 1

    if args.data_destination_audit:
        payload = data_destination_audit(args.policy, args.document_class, args.role, args.context, args.approval, args.release_mode, args.actor, args.job_state, args.retention_state, args.scenario, args.profile, args.request)
        if args.json:
            print(json.dumps(payload, indent=2, sort_keys=True))
        else:
            print_data_destination_audit(payload)
        return 0 if payload["result"] == "PASS" else 1

    if args.device_health_audit:
        payload = device_health_audit(args.policy, args.document_class, args.role, args.context, args.approval, args.release_mode, args.actor, args.job_state, args.retention_state, args.data_destination, args.scenario, args.profile, args.request)
        if args.json:
            print(json.dumps(payload, indent=2, sort_keys=True))
        else:
            print_device_health_audit(payload)
        return 0 if payload["result"] == "PASS" else 1

    if args.risk_posture_audit:
        payload = risk_posture_audit(args.policy, args.document_class, args.role, args.context, args.approval, args.release_mode, args.actor, args.job_state, args.retention_state, args.data_destination, args.device_health, args.scenario, args.profile, args.request)
        if args.json:
            print(json.dumps(payload, indent=2, sort_keys=True))
        else:
            print_risk_posture_audit(payload)
        return 0 if payload["result"] == "PASS" else 1

    if args.compliance_mode_audit:
        payload = compliance_mode_audit(args.policy, args.document_class, args.role, args.context, args.approval, args.release_mode, args.actor, args.job_state, args.retention_state, args.data_destination, args.device_health, args.risk_posture, args.scenario, args.profile, args.request)
        if args.json:
            print(json.dumps(payload, indent=2, sort_keys=True))
        else:
            print_compliance_mode_audit(payload)
        return 0 if payload["result"] == "PASS" else 1

    if args.trust_zone_audit:
        payload = trust_zone_audit(args.policy, args.document_class, args.role, args.context, args.approval, args.release_mode, args.actor, args.job_state, args.retention_state, args.data_destination, args.device_health, args.risk_posture, args.compliance_mode, args.scenario, args.profile, args.request)
        if args.json:
            print(json.dumps(payload, indent=2, sort_keys=True))
        else:
            print_trust_zone_audit(payload)
        return 0 if payload["result"] == "PASS" else 1

    if args.evidence_view_audit:
        payload = evidence_view_audit(args.policy, args.document_class, args.role, args.context, args.approval, args.release_mode, args.actor, args.job_state, args.retention_state, args.data_destination, args.device_health, args.risk_posture, args.compliance_mode, args.trust_zone, args.scenario, args.profile, args.request)
        if args.json:
            print(json.dumps(payload, indent=2, sort_keys=True))
        else:
            print_evidence_view_audit(payload)
        return 0 if payload["result"] == "PASS" else 1

    if args.recovery_action_audit:
        payload = recovery_action_audit(args.policy, args.document_class, args.role, args.context, args.approval, args.release_mode, args.actor, args.job_state, args.retention_state, args.data_destination, args.device_health, args.risk_posture, args.compliance_mode, args.trust_zone, args.evidence_view, args.scenario, args.profile, args.request)
        if args.json:
            print(json.dumps(payload, indent=2, sort_keys=True))
        else:
            print_recovery_action_audit(payload)
        return 0 if payload["result"] == "PASS" else 1

    if args.transfer_boundary_audit:
        payload = transfer_boundary_audit(args.policy, args.document_class, args.role, args.context, args.approval, args.release_mode, args.actor, args.job_state, args.retention_state, args.data_destination, args.device_health, args.risk_posture, args.compliance_mode, args.trust_zone, args.evidence_view, args.recovery_action, args.scenario, args.profile, args.request)
        if args.json:
            print(json.dumps(payload, indent=2, sort_keys=True))
        else:
            print_transfer_boundary_audit(payload)
        return 0 if payload["result"] == "PASS" else 1

    if args.chain_of_custody_audit:
        payload = custody_state_audit(args.policy, args.document_class, args.role, args.context, args.approval, args.release_mode, args.actor, args.job_state, args.retention_state, args.data_destination, args.device_health, args.risk_posture, args.compliance_mode, args.trust_zone, args.evidence_view, args.recovery_action, args.transfer_boundary, args.scenario, args.profile, args.request)
        if args.json:
            print(json.dumps(payload, indent=2, sort_keys=True))
        else:
            print_custody_state_audit(payload)
        return 0 if payload["result"] == "PASS" else 1

    if args.final_decision_audit:
        payload = final_decision_audit(args.policy, args.document_class, args.role, args.context, args.approval, args.release_mode, args.actor, args.job_state, args.retention_state, args.data_destination, args.device_health, args.risk_posture, args.compliance_mode, args.trust_zone, args.evidence_view, args.recovery_action, args.transfer_boundary, args.custody_state, args.scenario, args.profile, args.request)
        if args.json:
            print(json.dumps(payload, indent=2, sort_keys=True))
        else:
            print_final_decision_audit(payload)
        return 0 if payload["result"] == "PASS" else 1

    if args.governance_audit:
        payload = governance_audit(args.scenario, args.profile, args.request, args.policy, args.document_class, args.role, args.context, args.approval, args.release_mode, args.actor, args.job_state, args.retention_state, args.data_destination, args.device_health, args.risk_posture, args.compliance_mode, args.trust_zone, args.evidence_view, args.recovery_action, args.transfer_boundary, args.custody_state, args.final_decision)
        if args.json:
            print(json.dumps(payload, indent=2, sort_keys=True))
        else:
            print_governance_audit(payload)
        return 0

    if args.matrix:
        print_surface_table(SCENARIO_ORDER, PROFILE_ORDER, args.request)
        return 0

    if args.compare:
        print_surface_table(SCENARIO_ORDER, (args.profile,), args.request)
        return 0

    if args.request_compare:
        print(f"{PROJECT_NAME} v{VERSION} Request Comparison")
        print(f"Scenario: {args.scenario}")
        print(f"Profile: {args.profile}")
        print("request,visible,isolated,dormant,forbidden,blocked,deferred,certificate")
        for request_key in ("normal",) + REQUEST_ORDER:
            surface = resolve_surface(args.scenario, args.profile, request_key)
            counts = surface["counts"]
            print(f"{request_key},{counts[VISIBLE]},{counts[ISOLATED]},{counts[DORMANT]},{counts[FORBIDDEN]},{counts[BLOCKED]},{counts[DEFERRED]},{surface['surface_certificate']}")
        return 0

    if args.surface or args.explain or args.scenario or args.profile or args.request:
        surface = resolve_final_decision_surface(args.scenario, args.profile, args.request, args.policy, args.document_class, args.role, args.context, args.approval, args.release_mode, args.actor, args.job_state, args.retention_state, args.data_destination, args.device_health, args.risk_posture, args.compliance_mode, args.trust_zone, args.evidence_view, args.recovery_action, args.transfer_boundary, args.custody_state, args.final_decision)
        if args.json:
            print(json.dumps(surface, indent=2, sort_keys=True))
        else:
            print_surface(surface, explain=args.explain)
        return 0

    quickstart()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
