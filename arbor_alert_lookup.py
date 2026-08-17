#!/usr/bin/env python3
"""
Arbor Sightline Alert Lookup Tool

Given an alert number, this script:
  1. Fetches basic alert info (type, classification, importance, times,
     host address, misuse types, severity, etc.) from /alerts/<id>.
  2. Fetches the alert's traffic patterns (real src/dst prefix + port +
     protocol tuples, each with max/avg bandwidth and pps) from
     /alerts/<id>/patterns/ -- this is the endpoint the Sightline docs
     literally call "traffic patterns."
  3. Derives the top 10 sources by taking the highest-traffic pattern
     for each distinct src_prefix seen in that same data (deduplicated),
     ranked by whichever unit (bps or pps) actually triggered the
     alert (from severity_unit).
  4. Does an RDAP whois lookup (via the rdap.net bootstrap redirector)
     for each of the top 10 sources -- skipped for any source Arbor
     reports as 0.0.0.0, which is displayed as "Highly Distributed"
     instead of a real IP.
  5. Prints a single-page summary: alert info, then one table with
     source, protocol, ports, max bps/pps, destination, and RDAP org
     name per row.

Usage:
    python3 arbor_alert_lookup.py <alert_number>

Example:
    python3 arbor_alert_lookup.py 22105

You will be prompted for your Sightline API token (hidden input, not
stored).
"""

import getpass
import sys
import time
from datetime import datetime, timezone

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BASE_URL = "https://8.28.72.57/api/sp"
RDAP_BASE = "https://www.rdap.net/ip"
TOP_N_SOURCES = 10

# Paste your Sightline API token here to skip the prompt each run.
# Leave as "" to be prompted (hidden input) instead. Note: if you fill
# this in, the token sits in this file in plain text -- fine for a
# personal/local copy, but don't commit or share the file with it set.
API_TOKEN = ""

HIGHLY_DISTRIBUTED_IP = "0.0.0.0"
HIGHLY_DISTRIBUTED_LABEL = "Highly Distributed"

# IANA protocol numbers Sightline is likely to report. Anything not in
# here just falls back to "proto <n>" rather than guessing a name.
PROTOCOL_NAMES = {
    "1": "ICMP",
    "2": "IGMP",
    "6": "TCP",
    "17": "UDP",
    "47": "GRE",
    "50": "ESP",
    "51": "AH",
    "58": "ICMPv6",
    "132": "SCTP",
}


# --------------------------------------------------------------------------
# Setup
# --------------------------------------------------------------------------

def get_alert_id():
    if len(sys.argv) != 2:
        sys.exit("Usage: python3 arbor_alert_lookup.py <alert_number>")
    return sys.argv[1]


def get_token():
    if API_TOKEN:
        return API_TOKEN
    token = getpass.getpass("Sightline API token (input hidden): ").strip()
    if not token:
        sys.exit("ERROR: No token entered.")
    return token


def make_session(token):
    session = requests.Session()
    session.headers.update({
        "X-Arbux-APIToken": token,
        "Content-Type": "application/vnd.api+json",
    })
    return session


# --------------------------------------------------------------------------
# Sightline API calls
# --------------------------------------------------------------------------

def get_alert_basic_info(session, alert_id):
    url = f"{BASE_URL}/alerts/{alert_id}"
    resp = session.get(url, verify=False, timeout=30)

    if resp.status_code == 404:
        sys.exit(f"ERROR: Alert '{alert_id}' was not found.")
    resp.raise_for_status()

    data = resp.json().get("data", {})
    attrs = data.get("attributes", {})
    subobj = attrs.get("subobject", {}) or {}

    return {
        "alert_id": alert_id,
        "alert_type": attrs.get("alert_type"),
        "alert_class": attrs.get("alert_class"),
        "classification": attrs.get("classification"),
        "importance": attrs.get("importance"),
        "ongoing": attrs.get("ongoing"),
        "start_time": attrs.get("start_time"),
        "stop_time": attrs.get("stop_time"),
        "host_address": subobj.get("host_address"),
        "impact_bps": subobj.get("impact_bps"),
        "impact_pps": subobj.get("impact_pps"),
        "impact_boundary": subobj.get("impact_boundary"),
        "misuse_types": subobj.get("misuse_types"),
        "severity_percent": subobj.get("severity_percent"),
        "severity_threshold": subobj.get("severity_threshold"),
        "severity_unit": subobj.get("severity_unit"),
        "ip_version": subobj.get("ip_version"),
    }


def _pattern_key(fields):
    """Unique identity for a traffic pattern entry, used to merge the
    bps-unit call with the pps-unit call for the 'same' pattern."""
    dpr = fields.get("dst_port_range") or {}
    spr = fields.get("src_port_range") or {}
    return (
        fields.get("src_prefix"),
        fields.get("dst_prefix"),
        fields.get("protocol"),
        dpr.get("low"), dpr.get("high"),
        spr.get("low"), spr.get("high"),
    )


def _to_number(value):
    if value is None:
        return None
    try:
        return float(value) if "." in str(value) else int(value)
    except (ValueError, TypeError):
        return None


def _parse_iso(timestamp):
    if not timestamp:
        return None
    try:
        return datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None


def format_duration(start_time, stop_time):
    """
    Computes how long the alert has been (or was) active, choosing
    minutes/hours/days based on magnitude. If stop_time is None, the
    alert is still ongoing, so duration is measured up to now and
    labeled accordingly.
    """
    start_dt = _parse_iso(start_time)
    if start_dt is None:
        return "N/A"

    ongoing = stop_time is None
    end_dt = _parse_iso(stop_time) if stop_time else datetime.now(timezone.utc)
    if end_dt is None:
        end_dt = datetime.now(timezone.utc)

    total_minutes = (end_dt - start_dt).total_seconds() / 60
    if total_minutes < 0:
        return "N/A"

    if total_minutes < 60:
        duration_str = f"{total_minutes:.0f} min"
    elif total_minutes < 60 * 48:
        duration_str = f"{total_minutes / 60:.1f} hr"
    else:
        duration_str = f"{total_minutes / (60 * 24):.1f} d"

    return f"{duration_str} (ongoing)" if ongoing else duration_str


def determine_sort_unit(basic_info):
    """
    Figures out whether the alert was triggered by a bandwidth or
    packet-rate threshold, using severity_unit from the alert's
    subobject. Falls back to 'bps' if severity_unit is missing or is
    something this script doesn't recognize -- better to default to a
    known-good sort than guess at an unfamiliar unit.

    Returns a tuple: (sort_unit, is_confident)
        sort_unit    -- 'bps' or 'pps'
        is_confident -- True if this came from a recognized
                        severity_unit, False if it's the fallback.
    """
    unit = (basic_info.get("severity_unit") or "").strip().lower()
    if unit in ("bps", "pps"):
        return unit, True
    return "bps", False


def _sort_key(entry, sort_unit):
    primary = entry.get(f"max_{sort_unit}")
    other_unit = "pps" if sort_unit == "bps" else "bps"
    fallback = entry.get(f"max_{other_unit}")
    return primary if primary is not None else (fallback or 0)


def get_traffic_patterns(session, alert_id, query_limit, sort_unit="bps"):
    """
    Fetches /alerts/<id>/patterns/ -- the actual "traffic patterns"
    endpoint (real src/dst prefix + port + protocol tuples, each with
    its own traffic_data). Makes two calls (bps, then pps) and merges
    entries that represent the same pattern.

    Returns a list of dicts sorted descending by max <sort_unit>
    (falling back to the other unit if that one is missing), each
    with:
        {src_prefix, dst_prefix, protocol, src_port_range,
         dst_port_range, max_bps, avg_bps, max_pps, avg_pps}
    """
    merged = {}

    for unit in ("bps", "pps"):
        url = f"{BASE_URL}/alerts/{alert_id}/patterns/"
        params = {"query_unit": unit, "query_limit": query_limit}
        resp = session.get(url, params=params, verify=False, timeout=30)

        if resp.status_code == 404:
            continue
        resp.raise_for_status()

        entries = resp.json().get("data", [])
        for entry in entries:
            view = entry.get("attributes", {}).get("view", {})
            if not view:
                continue
            # view is keyed by e.g. "router-1620" -- take whatever key
            # is present rather than assuming a specific router id.
            fields = next(iter(view.values()), {})
            if not fields:
                continue

            key = _pattern_key(fields)
            if key not in merged:
                merged[key] = {
                    "src_prefix": fields.get("src_prefix"),
                    "dst_prefix": fields.get("dst_prefix"),
                    "protocol": fields.get("protocol"),
                    "src_port_range": fields.get("src_port_range"),
                    "dst_port_range": fields.get("dst_port_range"),
                    "max_bps": None,
                    "avg_bps": None,
                    "max_pps": None,
                    "avg_pps": None,
                }

            traffic_data = fields.get("traffic_data", {}) or {}
            merged[key][f"max_{unit}"] = _to_number(traffic_data.get("max"))
            merged[key][f"avg_{unit}"] = _to_number(traffic_data.get("avg"))

    results = list(merged.values())
    results.sort(key=lambda r: _sort_key(r, sort_unit), reverse=True)
    return results


def top_sources_from_patterns(patterns, top_n, sort_unit="bps"):
    """
    Derives a top-N source list from pattern entries: keeps only the
    highest-traffic pattern per distinct src_prefix (ranked by
    sort_unit), then returns the top_n of those, sorted the same way.
    NOTE: this is a derived view, not a native API concept -- see the
    module docstring for what this does and doesn't capture.
    """
    best_by_source = {}
    for p in patterns:
        src = p.get("src_prefix")
        if not src:
            continue
        current_best = best_by_source.get(src)
        this_val = _sort_key(p, sort_unit)
        if current_best is None or this_val > _sort_key(current_best, sort_unit):
            best_by_source[src] = p

    sources = list(best_by_source.values())
    sources.sort(key=lambda r: _sort_key(r, sort_unit), reverse=True)
    return sources[:top_n]


# --------------------------------------------------------------------------
# RDAP
# --------------------------------------------------------------------------

def strip_prefix_length(source_name):
    """
    src_prefix values look like '198.51.100.3/32' or a bare IP
    depending on alert type. RDAP wants the address, not the CIDR
    suffix, so trim it if present.
    """
    return source_name.split("/")[0] if source_name else source_name


def is_highly_distributed(src_prefix):
    """
    Arbor reports a source as 0.0.0.0 (with or without a CIDR suffix)
    when it has collapsed many individual sources into one "Highly
    Distributed" bucket. There's no real IP behind this, so it should
    never be treated as a lookupable address.
    """
    return strip_prefix_length(src_prefix) == HIGHLY_DISTRIBUTED_IP


def rdap_lookup(ip_address, retries=2, timeout=15):
    """
    Looks up an IP via the rdap.net bootstrap redirector. Returns a
    dict with the fields we care about, or an 'error' key if the
    lookup failed (e.g. private/reserved address, network issue).
    """
    url = f"{RDAP_BASE}/{ip_address}"

    for attempt in range(retries + 1):
        try:
            resp = requests.get(
                url,
                headers={"Accept": "application/rdap+json"},
                timeout=timeout,
            )
        except requests.exceptions.RequestException as e:
            if attempt < retries:
                time.sleep(1)
                continue
            return {"ip": ip_address, "error": f"Request failed: {e}"}

        if resp.status_code == 404:
            return {"ip": ip_address, "error": "Not found in RDAP (may be private/reserved/unallocated)"}
        if resp.status_code == 429:
            if attempt < retries:
                time.sleep(2)
                continue
            return {"ip": ip_address, "error": "Rate limited by rdap.net"}
        if resp.status_code != 200:
            return {"ip": ip_address, "error": f"HTTP {resp.status_code}"}

        try:
            data = resp.json()
        except ValueError:
            return {"ip": ip_address, "error": "Non-JSON response"}

        entities = data.get("entities", []) or []
        org_names = []
        for ent in entities:
            vcard = ent.get("vcardArray")
            if vcard and len(vcard) > 1:
                for field in vcard[1]:
                    if field[0] == "fn":
                        org_names.append(field[3])

        return {
            "ip": ip_address,
            "handle": data.get("handle"),
            "name": data.get("name"),
            "country": data.get("country"),
            "start_address": data.get("startAddress"),
            "end_address": data.get("endAddress"),
            "cidr_blocks": [
                f"{cb.get('v4prefix') or cb.get('v6prefix')}/{cb.get('length')}"
                for cb in data.get("cidr0_cidrs", [])
                if cb.get("v4prefix") or cb.get("v6prefix")
            ],
            "org_names": org_names,
            "port43": data.get("port43"),
        }

    return {"ip": ip_address, "error": "Unknown failure"}


# --------------------------------------------------------------------------
# Formatting
# --------------------------------------------------------------------------

def format_bps(bps):
    if bps is None:
        return "N/A"
    if bps >= 1_000_000_000:
        return f"{bps / 1_000_000_000:.1f} Gbps"
    if bps >= 1_000_000:
        return f"{bps / 1_000_000:.1f} Mbps"
    if bps >= 1_000:
        return f"{bps / 1_000:.1f} Kbps"
    return f"{bps:.0f} bps"


def format_pps(pps):
    if pps is None:
        return "N/A"
    if pps >= 1_000_000:
        return f"{pps / 1_000_000:.1f} Mpps"
    if pps >= 1_000:
        return f"{pps / 1_000:.1f} Kpps"
    return f"{pps:.0f} pps"


def print_basic_info(info, sort_unit, sort_confident):
    print("\n" + "=" * 120)
    print(f"ALERT {info['alert_id']}")
    print("=" * 120)
    importance_map = {0: "Low", 1: "Medium", 2: "High"}
    imp = info["importance"]
    print(_cell(f"  Type:            {info['alert_type']} ({info['alert_class']})", 48) +
          f"Classification: {info['classification']}")
    print(_cell(f"  Importance:      {imp} ({importance_map.get(imp, 'unknown')})", 48) +
          f"Ongoing: {info['ongoing']}")
    print(_cell(f"  Start:           {info['start_time']}", 48) +
          f"Stop: {info['stop_time'] or '(still ongoing)'}")
    if info["host_address"]:
        print(_cell(f"  Host address:    {info['host_address']}", 48) +
              f"Duration: {format_duration(info['start_time'], info['stop_time'])}")
    else:
        print(f"  Duration:        {format_duration(info['start_time'], info['stop_time'])}")
    misuse = ", ".join(info["misuse_types"]) if info["misuse_types"] else "N/A"
    print(_cell(f"  Impact:          {format_bps(info['impact_bps'])} / {format_pps(info['impact_pps'])}", 48) +
          f"Misuse types: {misuse}")
    if info["severity_percent"] is not None:
        print(f"  Severity:        {info['severity_percent']}% of {info['severity_threshold']} {info['severity_unit']} threshold")
    label = sort_unit.upper() if sort_confident else f"{sort_unit.upper()} (default -- trigger unit unrecognized)"
    print(_cell(f"  Sorted by:       {label} (alert trigger)", 48) +
          f"Alert source: {info['impact_boundary'] or 'N/A'}")
    print()


def protocol_name(protocol):
    if protocol is None:
        return "?"
    proto_str = str(protocol)
    return PROTOCOL_NAMES.get(proto_str, f"proto {proto_str}")


def _single_port_display(pr):
    """Formats a src/dst port_range as a single value or range for
    display. Does NOT apply the ICMP override -- that's handled by
    the caller, since it needs to know the protocol too."""
    if not pr:
        return "any"
    lo, hi = pr.get("low"), pr.get("high")
    if lo is None or hi is None:
        return "any"
    if lo == hi:
        return str(lo)
    if lo == 0 and hi == 65535:
        return "any"
    return f"{lo}-{hi}"


def port_display(protocol, port_range):
    """
    ICMP has no meaningful ports -- Sightline may report whatever it
    wants in src/dst_port_range for an ICMP pattern, but showing it as
    a real port is misleading. Force 0 for ICMP; otherwise show the
    real value/range from the API.
    """
    if protocol_name(protocol) == "ICMP":
        return "0"
    return _single_port_display(port_range)


def source_display_name(src_prefix):
    if is_highly_distributed(src_prefix):
        return HIGHLY_DISTRIBUTED_LABEL
    return src_prefix


def org_for_source(src_prefix, rdap_result):
    if is_highly_distributed(src_prefix):
        return "-"
    if rdap_result is None:
        return "?"
    if "error" in rdap_result:
        return f"(lookup failed)"
    if rdap_result.get("org_names"):
        return ", ".join(rdap_result["org_names"])
    return rdap_result.get("name") or "unknown"


def _cell(text, width, align="left"):
    text = str(text)
    padded = text.ljust(width) if align == "left" else text.rjust(width)
    # Guarantee at least one separating space even if content overflows
    # the intended column width, so columns never visually merge.
    return padded if len(text) < width else text + " "


def print_sources_table(sources, rdap_by_ip):
    widths = {
        "num": 3, "source": 22, "proto": 6, "sport": 12, "dport": 12,
        "bps": 12, "pps": 12, "dest": 20, "org": 30,
    }
    header = (
        _cell("#", widths["num"]) +
        _cell("SOURCE", widths["source"]) +
        _cell("PROTO", widths["proto"]) +
        _cell("SPORT", widths["sport"]) +
        _cell("DPORT", widths["dport"]) +
        _cell("MAX BPS", widths["bps"], "right") + " " +
        _cell("MAX PPS", widths["pps"], "right") + " " +
        _cell("-> DEST", widths["dest"]) +
        "ORG"
    )
    print("-" * 120)
    print(f"TOP {len(sources)} SOURCES")
    print("-" * 120)
    print(header)
    if not sources:
        print("  No source data derived from traffic patterns.")
        print()
        return

    for i, s in enumerate(sources, start=1):
        src = s["src_prefix"]
        display_src = source_display_name(src)
        ip = strip_prefix_length(src)
        rdap_result = None if is_highly_distributed(src) else rdap_by_ip.get(ip)
        org = org_for_source(src, rdap_result)

        proto = protocol_name(s.get("protocol"))
        sport = port_display(s.get("protocol"), s.get("src_port_range"))
        dport = port_display(s.get("protocol"), s.get("dst_port_range"))

        row = (
            _cell(i, widths["num"]) +
            _cell(display_src, widths["source"]) +
            _cell(proto, widths["proto"]) +
            _cell(sport, widths["sport"]) +
            _cell(dport, widths["dport"]) +
            _cell(format_bps(s["max_bps"]), widths["bps"], "right") + " " +
            _cell(format_pps(s["max_pps"]), widths["pps"], "right") + " " +
            _cell(s["dst_prefix"], widths["dest"]) +
            org
        )
        print(row)
    print()


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def main():
    alert_id = get_alert_id()
    token = get_token()
    session = make_session(token)

    print(f"\nLooking up alert {alert_id}...")
    basic_info = get_alert_basic_info(session, alert_id)
    sort_unit, sort_confident = determine_sort_unit(basic_info)
    print_basic_info(basic_info, sort_unit, sort_confident)

    print("Fetching traffic patterns...")
    patterns = get_traffic_patterns(session, alert_id, query_limit=50, sort_unit=sort_unit)

    print(f"Deriving top {TOP_N_SOURCES} sources from traffic patterns...")
    top_sources = top_sources_from_patterns(patterns, TOP_N_SOURCES, sort_unit=sort_unit)

    lookup_targets = [s for s in top_sources if not is_highly_distributed(s["src_prefix"])]
    print(f"Running RDAP lookups for {len(lookup_targets)} source(s) via rdap.net...")
    rdap_by_ip = {}
    for s in lookup_targets:
        ip = strip_prefix_length(s["src_prefix"])
        rdap_by_ip[ip] = rdap_lookup(ip)

    print_sources_table(top_sources, rdap_by_ip)


if __name__ == "__main__":
    main()
