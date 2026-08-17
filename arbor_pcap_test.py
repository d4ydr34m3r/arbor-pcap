#!/usr/bin/env python3
"""
Arbor Sightline TMS Packet Capture -- LIMITED TEST SCRIPT

This is a test/tuning version only. It:
  1. Enumerates all TMS devices carrying traffic for the mitigation.
  2. Prints a 1-2 line summary of each, ranked by current traffic
     (highest first).
  3. Captures ONLY the single highest-traffic device, then stops.
  4. Saves a cleaned, human-readable JSON summary for that device.
  5. Prints/saves a partial report so we can review formatting.

This intentionally does NOT loop through all devices yet -- that comes
once we've confirmed the report and terminal output look right.

Usage: 
    python3 arbor_pcap_test.py <mitigation_number>

Example:
    python3 arbor_pcap_test.py 60634

You will be prompted for your API token (not stored, not echoed) and for
an FCAP expression.
"""

import getpass
import json
import os
import sys
from datetime import datetime, timezone
from collections import defaultdict

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BASE_URL = "https://8.28.72.57/api/sp"

FLOW_FIELDS = [
    "ipv4:source_addr",
    "ipv4:dest_addr",
    "udp:source_port",
    "udp:dest_port",
    "tcp:source_port",
    "tcp:dest_port",
]


def get_args():
    if len(sys.argv) != 2:
        sys.exit("Usage: python3 arbor_pcap_test.py <mitigation_number>")
    mitigation_number = sys.argv[1]
    return f"tms-{mitigation_number}"


def get_token():
    token = getpass.getpass("Sightline API token (input hidden): ").strip()
    if not token:
        sys.exit("ERROR: No token entered.")
    return token


def get_device_rates(session, mitigation_id):
    """
    Returns a list of dicts, one per device carrying traffic for this
    mitigation, ranked by total current traffic (drop + pass, pps)
    descending. Each dict has: device_id, name, pps, bps.

    Note: this only includes devices with a recorded rates entry. A
    device that is a member of the mitigation's TMS group but has no
    rates data at all (rather than a 0 reading) will not appear here.
    Enumerating full group membership requires walking
    tms_group -> tms_ports[] -> device, which costs one API call per
    port (potentially 100+) -- too expensive for routine use, so this
    tool intentionally does not do that.
    """
    url = f"{BASE_URL}/mitigations/{mitigation_id}/rates/"
    resp = session.get(url, verify=False, timeout=30)

    if resp.status_code == 404:
        sys.exit(
            f"ERROR: Mitigation '{mitigation_id}' was not found, or is not "
            "a TMS mitigation. Blackhole/flowspec mitigations are not "
            "supported by this tool."
        )
    resp.raise_for_status()

    data = resp.json().get("data", [])
    if not data:
        sys.exit(f"No devices have rate data for mitigation '{mitigation_id}'.")

    devices = []
    for entry in data:
        device_id = entry.get("relationships", {}).get("device", {}).get("data", {}).get("id")
        total = entry.get("attributes", {}).get("total", {})
        drop_pps = (total.get("drop", {}).get("pps", {}) or {}).get("current", 0) or 0
        pass_pps = (total.get("pass", {}).get("pps", {}) or {}).get("current", 0) or 0
        drop_bps = (total.get("drop", {}).get("bps", {}) or {}).get("current", 0) or 0
        pass_bps = (total.get("pass", {}).get("bps", {}) or {}).get("current", 0) or 0

        devices.append({
            "device_id": device_id,
            "pps": drop_pps + pass_pps,
            "bps": drop_bps + pass_bps,
        })

    for d in devices:
        d["name"] = get_device_name(session, d["device_id"])

    devices.sort(key=lambda d: d["pps"], reverse=True)
    return devices


def get_device_name(session, device_id):
    url = f"{BASE_URL}/devices/{device_id}"
    resp = session.get(url, verify=False, timeout=30)
    resp.raise_for_status()
    return resp.json().get("data", {}).get("attributes", {}).get("name", f"(device {device_id})")


def format_bps(bps):
    if bps >= 1_000_000:
        return f"{bps / 1_000_000:.1f} Mbps"
    if bps >= 1_000:
        return f"{bps / 1_000:.1f} Kbps"
    return f"{bps:.0f} bps"


def format_pps(pps):
    if pps >= 1_000_000:
        return f"{pps / 1_000_000:.1f} Mpps"
    if pps >= 1_000:
        return f"{pps / 1_000:.1f} Kpps"
    return f"{pps:.0f} pps"


def print_device_summary(devices):
    print(f"\nFound {len(devices)} device(s) carrying traffic for this mitigation:\n")
    for i, d in enumerate(devices, start=1):
        print(f"  {i}. {d['name']} -- {format_pps(d['pps'])} / {format_bps(d['bps'])}")
    print()


def run_packet_capture(session, mitigation_id, device_id, fcap_filter, max_results=50):
    url = f"{BASE_URL}/packet_capture_analyses/"
    payload = {
        "data": {
            "attributes": {
                "fcap_filter": fcap_filter,
                "max_results": max_results,
                "mode": "synchronous",
            },
            "relationships": {
                "mitigation": {"data": {"id": mitigation_id, "type": "mitigation"}},
                "tms": {"data": {"id": device_id, "type": "device"}},
            },
        }
    }
    try:
        resp = session.post(url, json=payload, verify=False, timeout=90)
        resp.raise_for_status()
        return resp.json()
    except requests.exceptions.RequestException as e:
        return {"error": str(e)}


def build_clean_summary(mitigation_id, device_id, device_name, fcap_filter, capture_json):
    """
    Wraps the raw capture response with identifying metadata (mitigation,
    device, FCAP filter used, timestamp) and preserves every field the
    API returned for every expression exactly as-is -- including the raw
    regex and any payload pattern fields. Nothing is filtered or grouped.
    The only "cleanup" here is consistent structure and indentation, not
    a reduction in content.
    """
    summary = {
        "mitigation_id": mitigation_id,
        "device_id": device_id,
        "device_name": device_name,
        "fcap_filter": fcap_filter,
        "captured_at": datetime.now(timezone.utc).isoformat(),
    }

    if "error" in capture_json:
        summary["status"] = "failed"
        summary["error"] = capture_json["error"]
        return summary

    expressions = capture_json.get("data", {}).get("attributes", {}).get("expressions")

    if not expressions:
        summary["status"] = "no_match"
        summary["match_count"] = 0
        summary["matches"] = []
        return summary

    # Preserve every expression exactly as returned -- full match_fields
    # (including payload:* entries) and the full regex string. Sorted by
    # match_percent purely for readability; no data is dropped or merged.
    matches = sorted(
        expressions,
        key=lambda e: e.get("packet_percent_match", 0),
        reverse=True,
    )

    summary["status"] = "matched"
    summary["match_count"] = len(matches)
    summary["matches"] = matches

    return summary


def safe_filename_part(text):
    """Sanitizes a string for safe use in a filename (keeps it readable)."""
    return "".join(c if c.isalnum() or c in ".-_" else "_" for c in text)


def main():
    mitigation_id = get_args()
    print(f"Mitigation: {mitigation_id}")

    token = get_token()
    session = requests.Session()
    session.headers.update({
        "X-Arbux-APIToken": token,
        "Content-Type": "application/vnd.api+json",
    })

    print("\nLooking up TMS devices for this mitigation...")
    devices = get_device_rates(session, mitigation_id)
    print_device_summary(devices)

    fcap_filter = input("Enter FCAP expression: ").strip()
    if not fcap_filter:
        sys.exit("ERROR: No FCAP expression entered.")

    output_dir = "captures"
    os.makedirs(output_dir, exist_ok=True)
    run_timestamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
    print(f"\nSaving captures to: {output_dir}/\n")

    completed = 0
    try:
        for i, target in enumerate(devices, start=1):
            print(f"[{i}/{len(devices)}] Capturing on {target['name']}... "
                  "(up to 60 seconds)")

            raw_result = run_packet_capture(
                session, mitigation_id, target["device_id"], fcap_filter
            )
            clean_summary = build_clean_summary(
                mitigation_id, target["device_id"], target["name"],
                fcap_filter, raw_result
            )

            if clean_summary["status"] == "failed":
                print(f"    FAILED: {clean_summary['error']}")
            elif clean_summary["status"] == "no_match":
                print("    Done -- found 0 matches (no traffic matched the FCAP filter).")
            else:
                print(f"    Done -- found {clean_summary['match_count']} matches.")

            device_name_safe = safe_filename_part(target["name"])
            clean_path = os.path.join(
                output_dir, f"{mitigation_id}_{device_name_safe}_{run_timestamp}.json"
            )
            with open(clean_path, "w") as f:
                json.dump(clean_summary, f, indent=2)

            completed += 1

    except KeyboardInterrupt:
        print(
            f"\n\nInterrupted by user. {completed}/{len(devices)} device "
            f"capture(s) completed and saved to {output_dir}/ before stopping."
        )
        sys.exit(130)

    print(f"\nAll captures complete. {completed}/{len(devices)} device(s) "
          f"saved to {output_dir}/")


if __name__ == "__main__":
    main()
