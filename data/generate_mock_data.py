import json
import random
from datetime import datetime, timedelta

# --- 1. Generate STIX 2.1 Threat Intel Feed ---
def generate_stix_feed():
    stix_bundle = {
        "type": "bundle",
        "id": "bundle--8a86571b-7a32-4d2b-98f5-3c07297e5fc7",
        "objects": [
            {
                "type": "indicator",
                "spec_version": "2.1",
                "id": "indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
                "name": "Known Malicious IP - APT29",
                "description": "This IP is associated with known command and control (C2) servers.",
                "pattern": "[ipv4-addr:value = '198.51.100.42']",
                "pattern_type": "stix",
                "valid_from": "2024-01-01T00:00:00Z"
            }
        ]
    }
    
    with open("stix_intel_feed.json", "w") as f:
        json.dump(stix_bundle, f, indent=4)
    print("[+] Created STIX 2.1 Intel Feed: stix_intel_feed.json")

# --- 2. Generate Synthetic Nginx Logs ---
def generate_nginx_logs():
    logs = []
    base_time = datetime.now() - timedelta(hours=1)
    
    normal_ips = ["192.168.1.10", "192.168.1.15", "10.0.0.5", "172.16.0.8"]
    stix_ip = "198.51.100.42" # The malicious one
    brute_ip = "203.0.113.7"  # The velocity attacker
    
    # 1. Generate Normal Traffic
    for i in range(50):
        t = base_time + timedelta(minutes=i)
        ip = random.choice(normal_ips)
        time_str = t.strftime("%d/%b/%Y:%H:%M:%S +0000")
        logs.append(f'{ip} - - [{time_str}] "GET /index.html HTTP/1.1" 200 1024 "-" "Mozilla/5.0"')

    # 2. Inject STIX Known Threat (Layer 1 test)
    t_stix = base_time + timedelta(minutes=15)
    logs.append(f'{stix_ip} - - [{t_stix.strftime("%d/%b/%Y:%H:%M:%S +0000")}] "GET /admin/env HTTP/1.1" 403 512 "-" "curl/7.68.0"')

    # 3. Inject Brute Force Velocity Attack (Layer 1 test)
    t_brute = base_time + timedelta(minutes=30)
    for i in range(25): # 25 requests in 2 seconds
        t = t_brute + timedelta(seconds=(i * 0.1))
        time_str = t.strftime("%d/%b/%Y:%H:%M:%S +0000")
        logs.append(f'{brute_ip} - - [{time_str}] "POST /login HTTP/1.1" 401 256 "-" "Python-urllib/3.8"')

    # 4. Inject Behavioral Anomaly for ML (Layer 2 test)
    # E.g., a normal internal IP suddenly doing a massive data pull on a weird endpoint at 3 AM.
    t_ml = base_time + timedelta(minutes=45)
    logs.append(f'192.168.1.10 - - [{t_ml.strftime("%d/%b/%Y:%H:%M:%S +0000")}] "GET /api/v1/users/export HTTP/1.1" 200 9999999 "-" "CustomScraper/1.0"')

    # Sort logs by time just in case, though they are mostly chronological
    with open("access.log", "w") as f:
        for log in logs:
            f.write(log + "\n")
    print("[+] Created Synthetic Nginx Log: access.log")

if __name__ == "__main__":
    generate_stix_feed()
    generate_nginx_logs()