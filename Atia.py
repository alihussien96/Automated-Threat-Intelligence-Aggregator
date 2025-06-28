import requests
import configparser
import argparse
import json

# --- Configuration Loading ---
def load_config(config_file='config.ini'):
    """Loads API keys from the configuration file."""
    config = configparser.ConfigParser()
    config.read(config_file)
    try:
        vt_key = config['virustotal']['api_key']
        abuse_key = config['abuseipdb']['api_key']
        return vt_key, abuse_key
    except KeyError:
        print("[ERROR] Could not read API keys from config.ini. Make sure the file exists and is formatted correctly.")
        return None, None

# --- API Query Functions ---
def query_virustotal_ip(ip_address, api_key):
    """Queries VirusTotal for a given IP address."""
    print(f"[INFO] Querying VirusTotal for IP: {ip_address}")
    url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip_address}'
    headers = {'x-apikey': api_key}
    
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()  # Raise an exception for bad status codes (4xx or 5xx)
        return response.json()
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 404:
            return {"error": "IP address not found in VirusTotal."}
        return {"error": f"VirusTotal API Error: {e}"}
    except Exception as e:
        return {"error": f"An unexpected error occurred with VirusTotal: {e}"}

def query_abuseipdb(ip_address, api_key):
    """Queries AbuseIPDB for a given IP address."""
    print(f"[INFO] Querying AbuseIPDB for IP: {ip_address}")
    url = 'https://api.abuseipdb.com/api/v2/check'
    params = {'ipAddress': ip_address, 'maxAgeInDays': '90'}
    headers = {'Accept': 'application/json', 'Key': api_key}
    
    try:
        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.HTTPError as e:
        return {"error": f"AbuseIPDB API Error: {e}"}
    except Exception as e:
        return {"error": f"An unexpected error occurred with AbuseIPDB: {e}"}

# --- Report Generation ---
def display_report(ip, vt_data, abuse_data):
    """Displays a consolidated report from all data sources."""
    print("\n" + "="*70)
    print(f"      Threat Intelligence Report for IP: {ip}")
    print("="*70 + "\n")

    # VirusTotal Report Section
    print("--- [ VirusTotal Summary ] ---")
    if "error" in vt_data:
        print(f"  Error: {vt_data['error']}\n")
    else:
        attributes = vt_data.get('data', {}).get('attributes', {})
        last_analysis = attributes.get('last_analysis_stats', {})
        malicious = last_analysis.get('malicious', 0)
        harmless = last_analysis.get('harmless', 0)
        suspicious = last_analysis.get('suspicious', 0)
        
        print(f"  Malicious Detections: {malicious}")
        print(f"  Harmless Detections: {harmless}")
        print(f"  Suspicious Detections: {suspicious}")
        print(f"  Owner/ASN: {attributes.get('as_owner', 'N/A')}")
        print(f"  Country: {attributes.get('country', 'N/A')}\n")

    # AbuseIPDB Report Section
    print("--- [ AbuseIPDB Summary ] ---")
    if "error" in abuse_data:
        print(f"  Error: {abuse_data['error']}\n")
    elif 'data' in abuse_data:
        data = abuse_data.get('data', {})
        print(f"  Abuse Confidence Score: {data.get('abuseConfidenceScore', 0)}%")
        print(f"  Total Reports: {data.get('totalReports', 0)}")
        print(f"  Country: {data.get('countryCode', 'N/A')}")
        print(f"  ISP: {data.get('isp', 'N/A')}\n")
    
    print("="*70)
    print("End of Report")
    print("="*70)


# --- Main Execution Block with Argument Parsing ---
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Automated Threat Intelligence Aggregator.")
    parser.add_argument('--ip', required=True, help="The IP address to investigate.")
    
    args = parser.parse_args()
    
    vt_api_key, abuse_api_key = load_config()
    
    if vt_api_key and abuse_api_key:
        # Query all sources
        virustotal_result = query_virustotal_ip(args.ip, vt_api_key)
        abuseipdb_result = query_abuseipdb(args.ip, abuse_api_key)
        
        # Display the final report
        display_report(args.ip, virustotal_result, abuseipdb_result)
