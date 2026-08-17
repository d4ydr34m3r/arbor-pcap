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

# Optional: set your API token here to skip the prompt each run.
# Leave as "" to be prompted for it instead (recommended if this file is
# ever committed to source control -- a filled-in token here will be
# saved in your git history, even in a private repo).
API_TOKEN = ""

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
    if API_TOKEN:
        print("Using API token set in script (API_TOKEN).")
        return API_TOKEN
    token = getpass.getpass("Sightline API token (input hidden): ").strip()
    if not token:
        sys.exit("ERROR: No token entered.")
    return token


def get_mitigation_tms_group(session, mitigation_id):
    """Returns the tms_group ID for this mitigation."""
    url = f"{BASE_URL}/mitigations/{mitigation_id}"
    resp = session.get(url, verify=False, timeout=30)

    if resp.status_code == 404:
        sys.exit(
            f"ERROR: Mitigation '{mitigation_id}' was not found. "
            "Double-check the mitigation number and that it is a TMS "
            "mitigation (blackhole/flowspec mitigations are not supported)."
        )
    resp.raise_for_status()

    rels = resp.json().get("data", {}).get("relationships", {})
    group_id = rels.get("tms_group", {}).get("data", {}).get("id")

    if not group_id:
        sys.exit(
            f"ERROR: Mitigation '{mitigation_id}' has no tms_group -- it is "
            "likely not a TMS-subtype mitigation."
        )
    return group_id


def get_all_group_device_ids(session, tms_group_id):
    """
    Returns the full, de-duplicated list of device IDs that are members
    of this TMS group, via tms_group -> tms_ports[] -> device. This is
    slower (one API call per port) but is the only way to enumerate
    devices for a mitigation when rates/ returns no data at all.
    """
    url = f"{BASE_URL}/tms_groups/{tms_group_id}"
    resp = session.get(url, verify=False, timeout=30)
    resp.raise_for_status()

    ports = resp.json().get("data", {}).get("relationships", {}).get(
        "tms_ports", {}).get("data", [])

    device_ids = []
    for port in ports:
        port_id = port.get("id")
        port_resp = session.get(f"{BASE_URL}/tms_ports/{port_id}", verify=False, timeout=30)
        port_resp.raise_for_status()
        device_id = port_resp.json().get("data", {}).get(
            "relationships", {}).get("tms", {}).get("data", {}).get("id")
        if device_id and device_id not in device_ids:
            device_ids.append(device_id)

    return device_ids


def get_device_rates(session, mitigation_id):
    """
    Returns the full list of TMS devices for this mitigation, combining
    two sources:

    1. /mitigations/<id>/rates/ -- devices with recorded traffic data,
       ranked by current traffic (drop + pass pps) descending.
    2. tms_group -> tms_ports[] -> device -- full group membership, used
       to catch devices that ARE seeing traffic but have no rates/ entry
       (rates/ only reflects devices that have been sampled recently;
       it is not guaranteed to be complete).

    Devices found only via #2 (not present in #1) are appended to the
    end of the list, in whatever order the API returns them -- they have
    no traffic figures available, so they cannot be ranked, only listed.

    Cost note: because this always walks the full group to find gap
    devices, this makes one API call per port in the group (in addition
    to per-device name lookups) on every run, not just when rates/ is
    empty. For large groups this can be 100+ calls.
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

    rates_data = resp.json().get("data", [])

    ranked_devices = []
    ranked_device_ids = set()
    for entry in rates_data:
        device_id = entry.get("relationships", {}).get("device", {}).get("data", {}).get("id")
        total = entry.get("attributes", {}).get("total", {})
        drop_pps = (total.get("drop", {}).get("pps", {}) or {}).get("current", 0) or 0
        pass_pps = (total.get("pass", {}).get("pps", {}) or {}).get("current", 0) or 0
        drop_bps = (total.get("drop", {}).get("bps", {}) or {}).get("current", 0) or 0
        pass_bps = (total.get("pass", {}).get("bps", {}) or {}).get("current", 0) or 0

        ranked_devices.append({
            "device_id": device_id,
            "pps": drop_pps + pass_pps,
            "bps": drop_bps + pass_bps,
            "has_traffic_data": True,
        })
        ranked_device_ids.add(device_id)

    ranked_devices.sort(key=lambda d: d["pps"], reverse=True)

    print("Enumerating full TMS group membership to check for devices "
          "missing from the traffic-rate data...")
    tms_group_id = get_mitigation_tms_group(session, mitigation_id)
    all_device_ids = get_all_group_device_ids(session, tms_group_id)

    gap_devices = []
    for device_id in all_device_ids:
        if device_id not in ranked_device_ids:
            gap_devices.append({
                "device_id": device_id,
                "pps": 0,
                "bps": 0,
                "has_traffic_data": False,
            })

    all_devices = ranked_devices + gap_devices

    if not all_devices:
        sys.exit(f"No TMS devices found for mitigation '{mitigation_id}'.")

    for d in all_devices:
        d["name"] = get_device_name(session, d["device_id"])

    return all_devices


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
    ranked_count = sum(1 for d in devices if d["has_traffic_data"])
    print(f"\nFound {len(devices)} device(s) total "
          f"({ranked_count} with traffic-rate data, "
          f"{len(devices) - ranked_count} found only via group listing):\n")
    for i, d in enumerate(devices, start=1):
        if d["has_traffic_data"]:
            print(f"  {i}. {d['name']} -- {format_pps(d['pps'])} / {format_bps(d['bps'])}")
        else:
            print(f"  {i}. {d['name']} -- (no traffic-rate data available)")
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
