# Automated Threat Intelligence Aggregator

## Overview
This tool is an advanced, command-line Threat Intelligence Platform (TIP) that automates the process of gathering intelligence on IP addresses. It queries multiple reputable sources via their APIs and aggregates the data into a single, consolidated report.

This project demonstrates expertise in API integration, data correlation, configuration management, and the development of professional-grade security tools. It is designed to streamline the initial investigation of an Indicator of Compromise (IOC).

---

## Features
- **Multi-Source Intelligence:** Gathers data from the following industry-standard services:
    - **VirusTotal:** For reputation, ownership, and malware-related detections.
    - **AbuseIPDB:** For abuse reports, confidence score, and ISP information.
- **IOC Support:** Currently supports analysis of IP addresses.
- **Secure Configuration:** Uses an external `config.ini` file to manage API keys, keeping secrets out of the source code.
- **Professional CLI:** Built with `argparse` for a clean and user-friendly command-line interface.
- **Consolidated Reporting:** Presents a clear, structured report combining data from all sources.

---

## Technologies Used
- **Language:** Python 3
- **Core Libraries:**
    - `requests`: For making HTTP requests to external APIs.
    - `configparser`: For managing the configuration file.
    - `argparse`: For creating the command-line interface.

---

## Setup & Configuration

### 1. Clone the Repository
```bash
git clone [https://github.com/YourUsername/Threat-Intel-Aggregator.git](https://github.com/YourUsername/Threat-Intel-Aggregator.git)
cd Threat-Intel-Aggregator
```

### 2. Install Dependencies
Install the required Python libraries using the `requirements.txt` file.
```bash
pip install -r requirements.txt
```

### 3. Obtain API Keys
This tool requires API keys from the following services. Free tiers are available for both.
- [VirusTotal API](https://developers.virustotal.com/reference/overview)
- [AbuseIPDB API](https://www.abuseipdb.com/api)

### 4. Configure the Tool
Create a file named `config.ini` in the same directory and paste the following content into it. Replace the placeholder text with your actual API keys.
```ini
[virustotal]
api_key = YOUR_VIRUSTOTAL_API_KEY_HERE

[abuseipdb]
api_key = YOUR_ABUSEIPDB_API_KEY_HERE
```

---

## Usage
Run the tool from the command line, providing the IP address you wish to investigate using the `--ip` flag.

**Example:**
```bash
python threat_intel_tool.py --ip 8.8.8.8
```

---

## Sample Output
```
[INFO] Querying VirusTotal for IP: 8.8.8.8
[INFO] Querying AbuseIPDB for IP: 8.8.8.8

======================================================================
      Threat Intelligence Report for IP: 8.8.8.8
======================================================================

--- [ VirusTotal Summary ] ---
  Malicious Detections: 0
  Harmless Detections: 72
  Suspicious Detections: 0
  Owner/ASN: Google LLC
  Country: US

--- [ AbuseIPDB Summary ] ---
  Abuse Confidence Score: 0%
  Total Reports: 25
  Country: US
  ISP: Google LLC

======================================================================
End of Report
======================================================================
```
