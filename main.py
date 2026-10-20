
import os
import json
import time
import requests
from datetime import datetime, timezone

# ============================================================
# THREAT INTELLIGENCE AGGREGATOR
# Sources: AlienVault OTX and VirusTotal
# ============================================================

OTX_BASE_URL = "https://otx.alienvault.com/api/v1"
VT_BASE_URL = "https://www.virustotal.com/api/v3"

OUTPUT_FILE = "threat_intelligence_results.json"
REQUEST_TIMEOUT = 30
SLEEP_BETWEEN_VT_REQUESTS = 15

# Read API keys from environment variables.
OTX_API_KEY = os.getenv("OTX_API_KEY", "").strip()
VT_API_KEY = os.getenv("VT_API_KEY", "").strip()

session = requests.Session()


# ------------------------------------------------------------
# 1. Collect indicator information from AlienVault OTX
# ------------------------------------------------------------


def collect_live_iocs(otx_api_key):
    """Collect live-feed IP indicators and retrieve OTX details."""

    feed_url = (
        "https://feodotracker.abuse.ch/"
        "downloads/ipblocklist_recommended.json"
    )

    records = []

    try:
        response = requests.get(feed_url, timeout=30)
        response.raise_for_status()
        feed = response.json()

    except (requests.RequestException, ValueError) as error:
        print(f"Could not retrieve live feed: {error}")
        return records

    # Limit the first run to five indicators.
    for item in feed[:5]:
        ip = item.get("ip_address")

        if not ip:
            continue

        record = {
            "indicator": ip,
            "type": "IPv4",
            "source": "Feodo Tracker live feed",
            "feed_status": item.get("status"),
            "hostname": item.get("hostname"),
            "malware": item.get("malware"),
            "otx_reputation": None,
            "virustotal": {}
        }

        # Enrich each feed IP with OTX indicator details.
        otx_url = (
            f"{OTX_BASE_URL}/indicators/IPv4/{ip}/general"
        )

        try:
            otx_response = requests.get(
                otx_url,
                headers={"X-OTX-API-KEY": otx_api_key},
                timeout=30
            )

            if otx_response.status_code == 200:
                otx_data = otx_response.json()
                record["otx_reputation"] = (
                    otx_data.get("reputation")
                )
            else:
                print(
                    f"OTX lookup for {ip}: "
                    f"HTTP {otx_response.status_code}"
                )

        except (requests.RequestException, ValueError) as error:
            print(f"OTX lookup error for {ip}: {error}")

        records.append(record)
        print(f"Collected live-feed indicator: {ip}")

    print(f"Collected {len(records)} live-feed indicators.")
    return records



# ------------------------------------------------------------
# 2. Enrich indicators using VirusTotal
# ------------------------------------------------------------

def enrich_with_virustotal(record, api_key):
    """Retrieve VirusTotal analysis statistics for an indicator."""

    indicator = record["indicator"]
    indicator_type = record["type"]

    if indicator_type == "IPv4":
        endpoint = f"ip_addresses/{indicator}"
        gui_type = "ip-address"
    elif indicator_type == "domain":
        endpoint = f"domains/{indicator}"
        gui_type = "domain"
    else:
        record["vt_note"] = "Unsupported indicator type"
        return record

    url = f"{VT_BASE_URL}/{endpoint}"
    headers = {"x-apikey": api_key}

    try:
        response = session.get(
            url,
            headers=headers,
            timeout=REQUEST_TIMEOUT
        )

        if response.status_code == 429:
            record["vt_note"] = (
                "VirusTotal rate limit reached; try again later"
            )
            print(f"Rate limit reached for {indicator}")
            return record

        if response.status_code != 200:
            record["vt_note"] = (
                f"VirusTotal request failed: HTTP {response.status_code}"
            )
            print(f"VirusTotal lookup failed for {indicator}")
            return record

        payload = response.json()
        attributes = payload.get("data", {}).get("attributes", {})

        stats = attributes.get("last_analysis_stats", {})

        record["virustotal"] = {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0)
        }

        record["vt_malicious"] = stats.get("malicious", 0)
        record["vt_suspicious"] = stats.get("suspicious", 0)
        record["vt_reputation"] = attributes.get("reputation")
        record["vt_link"] = (
            f"https://www.virustotal.com/gui/"
            f"{gui_type}/{indicator}"
        )
        record["vt_note"] = "Enriched successfully"

        print(
            f"Enriched {indicator}: "
            f"malicious={record['vt_malicious']}, "
            f"suspicious={record['vt_suspicious']}"
        )

    except (requests.RequestException, ValueError) as error:
        record["vt_note"] = f"Enrichment error: {error}"
        print(f"VirusTotal error for {indicator}: {error}")

    return record


# ------------------------------------------------------------
# 3. Remove duplicate indicators
# ------------------------------------------------------------

def deduplicate_iocs(records):
    """Keep only one record for each indicator and type."""

    unique_records = []
    seen = set()

    for record in records:
        key = (
            record.get("indicator", "").lower(),
            record.get("type", "").lower()
        )

        if key not in seen:
            seen.add(key)
            unique_records.append(record)

    return unique_records


# ------------------------------------------------------------
# 4. Save results to a JSON file
# ------------------------------------------------------------

def save_results(records):
    """Save collected and enriched records as JSON."""

    output = {
        "project": "Threat Intelligence Aggregator",
        "generated_at_utc": datetime.now(
            timezone.utc
        ).isoformat(),
        "data_note": (
    "Indicators collected from the Feodo Tracker live feed. "
    "OTX provides supplementary indicator information, and "
    "VirusTotal provides enrichment results. Detection counts "
    "do not by themselves prove an indicator is safe."
),
        "total_indicators": len(records),
        "results": records
    }

    with open(OUTPUT_FILE, "w", encoding="utf-8") as file:
        json.dump(output, file, indent=4)

    print(f"\nSaved {len(records)} records to {OUTPUT_FILE}")


# ------------------------------------------------------------
# 5. Run the complete aggregator
# ------------------------------------------------------------

def run_aggregator():
    """Collect, deduplicate, enrich and export indicators."""

    if not OTX_API_KEY:
        print("ERROR: OTX_API_KEY environment variable is missing.")
        return

    if not VT_API_KEY:
        print("ERROR: VT_API_KEY environment variable is missing.")
        return

    print("=" * 55)
    print("THREAT INTELLIGENCE AGGREGATOR")
    print("=" * 55)

    records = collect_live_iocs(OTX_API_KEY)
    records = deduplicate_iocs(records)

    print(f"\nUnique indicators: {len(records)}")
    print("\nStarting VirusTotal enrichment...")

    for index, record in enumerate(records):
        print(
            f"\nProcessing {index + 1}/{len(records)}: "
            f"{record['indicator']}"
        )

        enrich_with_virustotal(record, VT_API_KEY)

        # Avoid sending requests too quickly.
        if index < len(records) - 1:
            time.sleep(SLEEP_BETWEEN_VT_REQUESTS)

    save_results(records)

    print("\nTHREAT INTELLIGENCE SUMMARY")
    print("-" * 55)

    for record in records:
        print(f"\nIndicator: {record['indicator']}")
        print(f"Type: {record['type']}")
        print(f"Source: {record['source']}")
        print(f"OTX reputation: {record.get('otx_reputation')}")
        print(f"VirusTotal malicious: {record.get('vt_malicious', 'N/A')}")
        print(f"VirusTotal suspicious: {record.get('vt_suspicious', 'N/A')}")
        print(f"Status: {record.get('vt_note', 'Not enriched')}")

    print("\nAggregator execution completed.")


if __name__ == "__main__":
    run_aggregator()
