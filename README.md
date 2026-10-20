# Threat Intelligence Aggregator

## Project Description

Threat Intelligence Aggregator is a Python-based defensive security tool that collects Indicators of Compromise (IoCs) from a live threat-intelligence feed, retrieves supplementary indicator information from AlienVault Open Threat Exchange (OTX), and enriches supported indicators using VirusTotal API v3.

The application normalizes indicator records, removes duplicates, collects threat-intelligence metadata, displays a summary, and exports the results to a JSON file.

The current implementation uses Feodo Tracker as its live feed, OTX for supplementary indicator lookups, and VirusTotal for analysis statistics. OTX subscribed-pulse retrieval is not currently used because the endpoint returned an authentication error in the tested environment.

## Technologies Used

- Python 3.10 or later
- Requests library for HTTPS API calls
- Feodo Tracker threat-intelligence feed
- AlienVault OTX API
- VirusTotal API v3
- JSON for storing results
- Jupyter Notebook for interactive execution

## Dataset and Data Sources

This project uses a live threat-intelligence feed and API lookups rather than relying exclusively on a fixed demonstration dataset.

- **Feodo Tracker:** https://feodotracker.abuse.ch/
- **Feodo Tracker JSON feed:** https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json
- **AlienVault OTX:** https://otx.alienvault.com/
- **OTX API documentation:** https://otx.alienvault.com/api
- **VirusTotal:** https://www.virustotal.com/
- **VirusTotal API v3 documentation:** https://docs.virustotal.com/reference/overview

Feed contents, API availability, and rate limits may change over time and depend on the providers' services and account plans.

## Setup and Installation

### Requirements

- Python 3.10 or later
- Internet access
- A valid AlienVault OTX API key
- A valid VirusTotal API key

### Install Dependencies

Open a terminal in the project directory and run:

```bash
python -m pip install -r requirements.txt
```

### Configure API Keys

Create API keys through the providers' official websites. Configure them as environment variables rather than hard-coding them in the source code.

**Windows PowerShell:**

```powershell
$env:OTX_API_KEY = Read-Host "Enter OTX API key"
$env:VT_API_KEY = Read-Host "Enter VirusTotal API key"
```

**macOS / Linux:**

```bash
export OTX_API_KEY="your_otx_api_key"
export VT_API_KEY="your_virustotal_api_key"
```

Do not publish real API keys in source code, notebooks, reports, screenshots, or public repositories.

## Running the Application

### Run the Python Script

From the project directory, run:

```bash
python main.py
```

The script retrieves indicators from the configured live feed, looks up supplementary information through OTX, enriches indicators through VirusTotal, prints a summary, and saves the results to:

`threat_intelligence_results.json`

### Run the Jupyter Notebook

Open the project notebook in Jupyter Notebook or VS Code and execute its cells in order.

**Note:** The notebook should be updated to use the same live-feed workflow as `main.py` before the two are described as equivalent implementations.

## Main Workflow

1. Read the OTX and VirusTotal API keys from environment variables.
2. Retrieve indicator records from the Feodo Tracker live feed.
3. Extract supported IP address indicators and relevant feed metadata.
4. Request supplementary indicator details from OTX.
5. Normalize and deduplicate indicator records.
6. Enrich indicators using VirusTotal API v3.
7. Display the enrichment summary.
8. Export the collected information to JSON.

## Output Fields

Depending on the information returned by each provider, the output can include:

- Indicator value and type
- Source feed
- Feed status, hostname, and malware-family information
- OTX reputation
- VirusTotal malicious, suspicious, harmless, and undetected statistics
- VirusTotal reputation
- VirusTotal lookup URL
- Enrichment status and execution timestamp

Some fields may be unavailable for particular indicators.

## Limitations

- The current live-feed implementation collects a limited number of IP indicators per run.
- OTX subscribed-pulse retrieval is not currently implemented in the working script; OTX is used for supplementary indicator lookups.
- OTX or VirusTotal requests may fail due to network issues, permissions, rate limits, or provider changes.
- VirusTotal statistics reflect the returned analysis data and do not independently establish that an indicator is safe or malicious.
- Feed entries may change or disappear over time.
- Results should be reviewed in context before making defensive security decisions.
- This project is intended for defensive security research and authorized environments only.

## Project Report

Refer to `Shourya_Ashatkar_ProjectReport.docx` for the project documentation.
