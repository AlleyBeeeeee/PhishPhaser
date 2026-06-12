import os
import sys
import re
import urllib.request
import json

def check_ip_reputation(ip):
    # simulate a live api query to a threat intelligence database
    malicious_database = ["192.168.56.101", "203.0.113.50", "198.51.100.12"]

    if ip in malicious_database:
        return {"is_malicious": True, "score": 85, "category": "Botnet/Spam Source"}
    return {"is_malicious": False, "score": 0, "category": "Clean/Unknown"}

print("--- PhishPhaser Cyber Tool Initialized ---")

# check if user provided file argument
if len(sys.argv) < 2:
    print("Error: Please provide target email header file.")
    print("Usage: python3 phisher_phaser.py <filename>")
    sys.exit(1)

# define the path to the target email header file
file_name = sys.argv[1]

print(f"Analyzing target file: {file_name}...")

# open the file safely using a with statement
with open(file_name, "r") as folder_file:
    all_lines = folder_file.readlines()

# count how many lines loaded successfully
line_count = len(all_lines)
print(f"Successfully loaded {line_count} lines of header data.")

# extraction stage
print("\n--- Extracting Indicators of Compromise (IoCs) ---")

# initialize empty variables to hold the data found
sender_from = "Not Found"
return_path = "Not Found"
source_ip = "Not Found"

# loop through every line loaded from file
for line in all_lines:
    # look for from line and grab the email inside the angle brackets
    if line.startswith("From:"):
        match = re.search(r'<(.*?)>', line)
        if match: 
            sender_from = match.group(1)

    # look for the return path line
    if line.startswith("Return-Path:"):
        match = re.search(r'<(.*?)>', line)
        if match:
            return_path = match.group(1)

    # look for received line and grab the ip address inside the brackets
    if line.startswith("Received:"):
        match = re.search(r'\[(.*?)\]', line)
        if match: 
            source_ip = match.group(1)

# print out findings
print(f"[+] Cleaned From Address: {sender_from}")
print(f"[+] Cleaned Return-Path:  {return_path}")
print(f"[+] Source Server IP:     {source_ip}")

# threat analysis stage
print("\n--- PhishPhaser Security Threat Analysis ---")

# initialize the data dictionary for structural logging
result_data = {
    "status": "CLEAN",
    "phishing_risk": "LOW",
    "source_ip": source_ip,
    "from_domain": "Unknown",
    "return_domain": "Unknown",
    "action_required": "None"
}

# run the threat intelligence ip check out in the open
ip_report = check_ip_reputation(source_ip)
result_data["threat_intel"] = ip_report

# evaluate the domains and the ip reputation together
if sender_from != "Not Found" and return_path != "Not Found":
    from_domain = sender_from.split('@')[-1]
    return_domain = return_path.split('@')[-1]
    result_data["from_domain"] = from_domain
    result_data["return_domain"] = return_domain

    # check if domains mismatch or if the threat intel database flagged the ip
    if from_domain != return_domain or ip_report["is_malicious"]:
        print("[🚨 ALERT] HIGH PHISHING RISK DETECTED!")
        result_data["status"] = "ALERT"
        result_data["phishing_risk"] = "HIGH"
        result_data["action_required"] = f"Block traffic from Source IP {source_ip} immediately."
        
        if from_domain != return_domain:
            print(f"    Reason: Sender domain ({from_domain}) does NOT match Return-Path domain ({return_domain}).")
        if ip_report["is_malicious"]:
            print(f"    Reason: Source IP {source_ip} found on Threat Intel Blocklist! (Category: {ip_report['category']}, Abuse Score: {ip_report['score']}%).")
    else:
        print("[✅ CLEAN] Sender domain matches Return-Path domain and IP is clean.")

else:
    print("[⚠️ WARNING] Unable to verify domains due to missing header fields.")
    result_data["status"] = "WARNING"
    
    # check ip status separately if domain fields are missing
    if ip_report["is_malicious"]:
        print("[🚨 ALERT] HIGH PHISHING RISK DETECTED!")
        print(f"    Reason: Source IP {source_ip} found on Threat Intel Blocklist! (Category: {ip_report['category']}, Abuse Score: {ip_report['score']}%).")
        result_data["status"] = "ALERT"
        result_data["phishing_risk"] = "HIGH"
        result_data["action_required"] = f"Block traffic from Source IP {source_ip} immediately."

# automation output
with open("phish_alert.json", "w") as json_file:
    json.dump(result_data, json_file, indent=4)

print("[+] Automation data written cleanly to phish_alert.json")