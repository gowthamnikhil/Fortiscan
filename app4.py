import os
import csv
import json
import re
import base64
import requests
from flask import Flask, request, jsonify, render_template
from datetime import datetime, timedelta
from urllib.parse import urlparse
from transformers import BertTokenizerFast, BertForSequenceClassification
import torch
from flask_cors import CORS
import uuid
import boto3

# Optionally, load environment variables from a .env file
# from dotenv import load_dotenv
# load_dotenv()

app = Flask(__name__)
CORS(app)

# ---------------------------
# Load the Fine-Tuned BERT Model and Tokenizer
# ---------------------------
MODEL_DIR = "./cyber_threat_model_online"
tokenizer = BertTokenizerFast.from_pretrained(MODEL_DIR)
model = BertForSequenceClassification.from_pretrained(MODEL_DIR)

LABEL_MAPPING = {
    0: "Phishing (Email Scam, Fake Websites, Spear Phishing)",
    1: "Malware (Trojan, Ransomware, Spyware)",
    2: "Social Engineering (Pretexting, Baiting, Quid Pro Quo)",
    3: "Denial of Service (DoS/DDoS)",
    4: "SQL Injection (Classic, Blind, Time-Based)",
    5: "Cross-Site Scripting (XSS)",
    6: "Man-in-the-Middle (MitM)",
    7: "Identity Theft (Account Takeover, Financial Fraud, Medical Identity Theft)",
    8: "Brute Force Attacks (Credential Stuffing, Dictionary Attack, Reverse Brute Force)",
    9: "Zero-Day Exploit (Software Vulnerability, Hardware Exploit)",
    10: "Insider Threats (Malicious Insider, Negligent Insider)",
    11: "Rogue Software (Fake Antivirus, Scareware)",
    12: "Clickjacking (UI Redressing, Overlay Attack)",
    13: "Cryptojacking (Unauthorized Cryptocurrency Mining)",
    14: "Keylogging (Hardware Keyloggers, Software Keyloggers)",
    15: "Trojan Horse (Backdoor, Rootkit)",
    16: "Supply Chain Attacks (Software Update Attack, Hardware Compromise)",
    17: "Deepfake Attacks (Fake Identity, Voice Spoofing)",
    18: "Business Email Compromise (BEC) (CEO Fraud, Invoice Scam)",
    19: "Fake News & Disinformation (Misinformation, Manipulated Media)"
}

BLACKLISTED_DOMAINS = {"malicious-example.com", "phishing-site.org", "badwebsite.net"}
MALWARE_DOMAINS = {"malware.wicar.org", "testmalware.com"}
THREAT_HISTORY_FILE = "threat_history.json"
PHISHTANK_FEED_URL = "http://data.phishtank.com/data/online-valid.csv"
PHISHTANK_CACHE_FILE = "phishtank.csv"
PHISHTANK_CACHE_DURATION = timedelta(hours=1)

# ---------------------------
# Initialize DynamoDB Resource
# ---------------------------
# Replace 'us-east-1' with your table's region if different.
dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
# Ensure the table name matches what you created in AWS.
threat_logs_table = dynamodb.Table('ThreatLogs')

def save_threat_log(log_data):
    """
    Save a single threat log to the DynamoDB ThreatLogs table.
    log_data should be a dict with keys like:
      - threat
      - severity
      - type
      - subtype
      - site
    """
    try:
        log_id = str(uuid.uuid4())
        timestamp = datetime.utcnow().isoformat()
        item = {
            'logId': log_id,
            'timestamp': timestamp,
            **log_data
        }
        threat_logs_table.put_item(Item=item)
        return True, item
    except Exception as e:
        print("Error saving log to DynamoDB:", e)
        return False, str(e)

def check_domain_reputation(url):
    if not url:
        return False
    try:
        parsed = urlparse(url)
        if not parsed.hostname:
            return False
        domain = parsed.hostname.lower()
        return domain in BLACKLISTED_DOMAINS
    except Exception as e:
        print("Domain parsing error:", e)
        return False

def is_malware_domain(url):
    try:
        domain = urlparse(url).hostname.lower()
        return domain in MALWARE_DOMAINS
    except Exception:
        return False

def download_phishtank_feed():
    try:
        response = requests.get(PHISHTANK_FEED_URL)
        if response.status_code == 200:
            with open(PHISHTANK_CACHE_FILE, "wb") as f:
                f.write(response.content)
            print("PhishTank feed downloaded and cached.")
        else:
            print(f"Error downloading PhishTank feed: {response.status_code}")
    except Exception as e:
        print("Exception during PhishTank feed download:", e)

def is_feed_fresh():
    if not os.path.exists(PHISHTANK_CACHE_FILE):
        return False
    mod_time = datetime.fromtimestamp(os.path.getmtime(PHISHTANK_CACHE_FILE))
    return datetime.now() - mod_time < PHISHTANK_CACHE_DURATION

def get_phishtank_report(url):
    if not is_feed_fresh():
        download_phishtank_feed()
    if not os.path.exists(PHISHTANK_CACHE_FILE):
        return {"error": "Unable to retrieve PhishTank data."}
    try:
        parsed_url = urlparse(url)
        input_domain = parsed_url.hostname.lower()
    except Exception as e:
        return {"error": "Invalid URL", "details": str(e)}
    found = False
    try:
        with open(PHISHTANK_CACHE_FILE, newline='', encoding="utf-8") as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                phishing_url = row.get("url", "").strip().lower()
                if phishing_url == url.lower() or input_domain in phishing_url:
                    found = True
                    break
    except Exception as e:
        return {"error": "Error processing PhishTank data", "details": str(e)}
    if found:
        return {
            "url": url,
            "domain": input_domain,
            "threat_level": "High",
            "details": "URL found in PhishTank feed. Likely a phishing site."
        }
    else:
        return {
            "url": url,
            "domain": input_domain,
            "threat_level": "Low",
            "details": "URL not found in PhishTank feed."
        }

@app.route('/threatIntel', methods=['POST'])
def threat_intel():
    data = request.get_json()
    url = data.get("url", "")
    if not url:
        return jsonify({"error": "URL is required"}), 400
    intel_report = get_phishtank_report(url)
    return jsonify(intel_report)

@app.route('/analyze', methods=['POST'])
def analyze_text():
    data = request.get_json()
    text = data.get("text", "")
    url = data.get("url", "")
    if url and check_domain_reputation(url):
        return jsonify([{
            "label": "Domain Reputation Threat Detected",
            "severity": "Critical",
            "type": "Reputation",
            "subtype": "Blacklisted Domain",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }])
    if not text:
        return jsonify([])
    inputs = tokenizer(text, truncation=True, padding="max_length", max_length=128, return_tensors="pt")
    outputs = model(**inputs)
    logits = outputs.logits
    probabilities = torch.softmax(logits, dim=1)
    predicted_class = torch.argmax(probabilities, dim=1).item()
    confidence = probabilities[0][predicted_class].item()
    predicted_label = LABEL_MAPPING.get(predicted_class, "unknown")
    result = {
        "prediction": predicted_label,
        "confidence": confidence,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    return jsonify(result)

@app.route('/analyzeImage', methods=['POST'])
def analyze_image():
    data = request.get_json()
    images = data.get("images", [])
    threats = []
    for img_url in images:
        if "threat" in img_url.lower() or "malware" in img_url.lower():
            threats.append({
                "label": "Suspicious Image Detected",
                "severity": "High",
                "type": "Malware Image",
                "subtype": "Infection/Exploitation",
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            })
    return jsonify(threats)

def load_threat_history():
    if os.path.exists(THREAT_HISTORY_FILE):
        with open(THREAT_HISTORY_FILE, "r") as f:
            try:
                return json.load(f)
            except Exception as e:
                print("Error loading threat history:", e)
                return []
    return []

def save_threat_history(history):
    with open(THREAT_HISTORY_FILE, "w") as f:
        json.dump(history, f, indent=2)

@app.route('/submitHistory', methods=['POST'])
def submit_history():
    data = request.get_json()
    new_history = data.get("threatHistory", [])
    if not isinstance(new_history, list):
        return jsonify({"error": "Invalid data format"}), 400

    # Load existing history from threat_history.json
    history = load_threat_history()
    # Append new logs
    history.extend(new_history)
    # Save back to threat_history.json
    save_threat_history(history)

    # Also save each threat log to DynamoDB (if configured)
    for log in new_history:
        success, result = save_threat_log(log)
        if not success:
            print("Error saving log to DynamoDB:", result)

    return jsonify({"message": "Threat history updated", "total": len(history)})


@app.route('/api/threatHistory', methods=['GET'])
def get_threat_history():
    history = load_threat_history()
    return jsonify(history)

@app.route('/reportThreat', methods=['POST'])
def report_threat():
    data = request.get_json()
    if not data:
        return jsonify({"error": "No JSON data received."}), 400
    
    # The key we expect is 'threatInfo' with details about the threat/site
    threat_info = data.get("threatInfo", "No details provided.")

    # Read your Gmail credentials from environment variables
    EMAIL_ADDRESS = os.environ.get('GMAIL_USER')      # e.g. "myaccount@gmail.com"
    EMAIL_PASSWORD = os.environ.get('GMAIL_PASSWORD') # e.g. "mypassword" or an App Password

    # If you haven't set these environment variables, you'll get an error
    if not EMAIL_ADDRESS or not EMAIL_PASSWORD:
        return jsonify({"error": "Missing Gmail credentials in environment variables."}), 500

    from email.message import EmailMessage
    msg = EmailMessage()
    msg['Subject'] = 'Threat Report Triggered'
    msg['From'] = EMAIL_ADDRESS
    msg['To'] = 'gowthamnikhil10@gmail.com'  # <--- Replace with the actual email you want to receive alerts on

    # The email content
    msg.set_content(f"Threat detected on page:\n\n{threat_info}")

    # Attempt to send the email
    try:
        import smtplib
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
            smtp.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            smtp.send_message(msg)
        return jsonify({"message": "Report sent successfully!"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/dashboard')
def dashboard():
    return render_template("dashboard.html")

if __name__ == '__main__':
    if not os.path.exists(THREAT_HISTORY_FILE):
        save_threat_history([])
    app.run(port=5001, debug=True)
