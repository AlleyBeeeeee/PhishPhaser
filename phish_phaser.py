import os
import sys
import re

print("--- PhishPhaser Cyber Tool Initialized ---")

#check if user provided file argument
if len(sys.argv) <2:
    print("Error: Please provide target email header file.")
    print("Usage: python3 phisher_phaser.py <filename>")
    sys.exit(1) #stops script completely

#define the path to our target email header file
file_name = sys.argv[1]

print(f"Analyzing target file: {file_name}...")

#open the file safely using a with statement
with open(file_name, "r") as folder_file:
    #read all line from the file into a list
    all_lines = folder_file.readlines()

#count how many lines loaded successfully
line_count = len(all_lines)
print(f"Successfully loaded {line_count} lines of header data.")

# *extraction stage*
print("\n--- Extracting Indicators of Compromise (IoCs) ---")

#initialize empty variables to hold the data we find
sender_from = "Not Found"
return_path = "Not Found"
source_ip = "Not Found"

#loop through every line loaded from file
for line in all_lines:
    #lookf or from line and grab the email inside the angle brackets
    if line.startswith("From:"):
        match = re.search(r'<(.*?)>', line)
        if match: 
            sender_from = match.group(1)

    #look for the return path line
    if line.startswith("Return-Path:"):
        match = re.search(r'<(.*?)>', line)
        if match:
            return_path = match.group(1)

    #look for received line and grab the IP address inside the brackets
    if line.startswith("Received:"):
        # this regex searches for an IP address pattern
        match = re.search(r'\[(.*?)\]', line)
        if match: 
            source_ip = match.group(1)


# Print out our findings
print(f"[+] Cleaned From Address: {sender_from}")
print(f"[+] Cleaned Return-Path:  {return_path}")
print(f"[+] Source Server IP:     {source_ip}")

# --- Threat Analysis Stage ---
print("\n--- PhishPhaser Security Threat Analysis ---")

#logic check: if the from address domain doesnt match the reutrn path domain, flag it
#split the email strings to grab just the domain part after the @
if sender_from != "Not Found" and return_path != "Not Found":
    from_domain = sender_from.split('@')[-1]
    return_domain = return_path.split('@')[-1]

    if from_domain != return_domain:
        print("[🚨 ALERT] HIGH PHISHING RISK DETECTED!")
        print(f"    Reason: Sender domain ({from_domain}) does NOT match Return-Path domain ({return_domain}).")
        print(f"    Action: Block traffic from Source IP {source_ip} immediately.")
    else:
        print("[✅ CLEAN] Sender domain matches Return-Path domain.")
else:
    print("[⚠️ WARNING] Unable to verify domains due to missing header fields.")