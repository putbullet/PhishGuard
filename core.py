#!/usr/bin/env python3
"""
PhishGuard: Advanced Email Phishing Detection System
Author: [putbullet]
Description: A sophisticated tool for analyzing .eml files to detect phishing attempts using
             header analysis, content inspection, machine learning, and external threat intelligence.
"""

import os
import re
import json
import logging
import hashlib
from datetime import datetime
import time
from urllib.parse import urlparse

import requests
from email import policy
from email.parser import BytesParser
from bs4 import BeautifulSoup
from transformers import pipeline, AutoTokenizer, AutoModelForSequenceClassification

import GUI

VT_URL = "https://www.virustotal.com/api/v3/urls"
VT_API_KEY = os.getenv("VT_API_KEY", "YOUR_API_KEY_HERE")

log_filename = f"email_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_filename),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

try:
    logger.info("Initializing phishing detection model...")
    phishing_pipeline = pipeline("text-classification", model="dima806/phishing-email-detection")
    tokenizer = AutoTokenizer.from_pretrained("dima806/phishing-email-detection")
    model = AutoModelForSequenceClassification.from_pretrained("dima806/phishing-email-detection")
    logger.info("Model loaded successfully")
except Exception as e:
    logger.error(f"Model initialization failed: {e}")
    raise

def extract_headers(msg):
    """
    Extract and analyze key email headers for suspicious patterns.
    Returns a dictionary of headers with sender IP and anomalies.
    """
    headers = {}
    key_headers = [
        'subject', 'from', 'to', 'cc', 'bcc', 'date', 'message-id', 'reply-to',
        'x-mailer', 'received', 'received-spf', 'authentication-results',
        'dkim-signature', 'content-type'
    ]
    
    for header in key_headers:
        if header.lower() in msg:
            headers[header] = msg[header]
    
    headers['sender_ip'] = extract_sender_ip(msg)
    headers['anomalies'] = check_header_anomalies(msg)
    return headers

def extract_sender_ip(msg):
    """
    Extract sender IP address from email headers.
    Attempts to find IP from SPF or Received headers.
    """
    if 'received-spf' in msg:
        spf_match = re.search(r"client-ip=([\d\.:a-fA-F]+)", msg['received-spf'])
        if spf_match:
            return spf_match.group(1)
    
    if 'received' in msg:
        received = msg.get_all('received', [])[-1] if msg.get_all('received') else ''
        for pattern in [r"\[([\d\.:a-fA-F]+)\]", r"from\s+\S+\s+\(([\d\.:a-fA-F]+)\)"]:
            match = re.search(pattern, received)
            if match:
                return match.group(1)
    return "Unknown IP"

def check_header_anomalies(msg):
    """
    Identify suspicious anomalies in email headers.
    Checks for domain mismatches and authentication failures.
    """
    anomalies = []
    
    if 'from' in msg and 'reply-to' in msg:
        from_domain = extract_domain(msg['from'])
        reply_to_domain = extract_domain(msg['reply-to'])
        if from_domain and reply_to_domain and from_domain != reply_to_domain:
            anomalies.append(f"Mismatched domains: From ({from_domain}) vs Reply-To ({reply_to_domain})")
    
    if 'message-id' not in msg:
        anomalies.append("Missing Message-ID")
    elif not re.match(r"<[^@]+@[^>]+>", msg['message-id']):
        anomalies.append("Malformed Message-ID")
    
    if 'authentication-results' in msg and 'fail' in msg['authentication-results'].lower():
        anomalies.append("Authentication failure detected")
    
    return anomalies

def extract_domain(address):
    """
    Extract domain name from an email address.
    Returns None if no domain is found.
    """
    match = re.search(r"@([^>]+)", address or "")
    return match.group(1).strip() if match else None

def extract_email_content(eml_path):
    """
    Parse .eml file and extract content and metadata.
    Returns email data dictionary and parsed message object.
    """
    try:
        with open(eml_path, "rb") as eml_file:
            msg = BytesParser(policy=policy.default).parse(eml_file)
    except Exception as e:
        logger.error(f"Failed to parse EML file: {e}")
        return None, None
    
    email_data = initialize_email_data(msg)
    process_email_parts(msg, email_data)
    return email_data, msg

def initialize_email_data(msg):
    """
    Initialize email data structure with default values.
    Sets up dictionary with basic email metadata.
    """
    return {
        "subject": msg.get("subject", "No Subject"),
        "from": msg.get("from", "Unknown Sender"),
        "to": msg.get("to", "Unknown Recipient"),
        "date": msg.get("date", "Unknown Date"),
        "headers": extract_headers(msg),
        "links": [],
        "images": [],
        "attachments": [],
        "tracking_elements": [],
        "body_plain": "",
        "body_html": "",
        "body_text": "",
        "suspicious_elements": []
    }

def process_email_parts(msg, email_data):
    """
    Process email parts to extract content and attachments.
    Populates email_data with body text and attachments.
    """
    for part in msg.walk():
        content_type = part.get_content_type()
        try:
            if part.get_content_disposition() == "attachment":
                process_attachment(part, email_data)
                continue
            
            content = part.get_payload(decode=True)
            if content:
                decoded_content = content.decode(errors="ignore")
                if content_type == "text/plain":
                    email_data["body_plain"] = decoded_content.strip()
                elif content_type == "text/html":
                    email_data["body_html"] = decoded_content
                    analyze_html_content(decoded_content, email_data)
        except Exception as e:
            logger.warning(f"Error processing email part: {e}")
    
    if not email_data["body_plain"] and email_data["body_html"]:
        email_data["body_text"] = BeautifulSoup(email_data["body_html"], "html.parser").get_text(separator=' ', strip=True)
    else:
        email_data["body_text"] = re.sub(r'\s+', ' ', email_data["body_plain"].strip())

def process_attachment(part, email_data):
    """
    Extract metadata from email attachments.
    Adds attachment details to email_data dictionary.
    """
    filename = part.get_filename()
    if filename:
        _, ext = os.path.splitext(filename)
        email_data["attachments"].append({
            "filename": filename,
            "content_type": part.get_content_type(),
            "extension": ext.lower(),
            "size": len(part.get_payload(decode=True) or b'')
        })

def analyze_html_content(html_content, email_data):
    """
    Analyze HTML content for links, images, and suspicious elements.
    Updates email_data with findings from HTML parsing.
    """
    soup = BeautifulSoup(html_content, "html.parser")
    
    email_data["links"] = extract_links(soup)
    email_data["images"] = extract_images(soup, email_data)
    detect_suspicious_elements(soup, email_data)

def extract_links(soup):
    """
    Extract and analyze hyperlinks from HTML content.
    Returns list of link dictionaries with suspicion flags.
    """
    links = []
    for a in soup.find_all("a", href=True):
        href = a["href"].strip()
        if not href:
            continue
        
        link_data = {
            "url": href,
            "text": a.get_text(strip=True),
            "domain": extract_url_domain(href),
            "suspicious": False,
            "reasons": []
        }
        
        if link_data["text"] and href != link_data["text"] and not href.startswith("mailto:"):
            if link_data["text"].lower() in ["click here", "login", "verify", "update", "account"]:
                link_data["suspicious"] = True
                link_data["reasons"].append("Generic phishing trigger word")
        
        links.append(link_data)
    return links

def extract_images(soup, email_data):
    """
    Extract image metadata and detect tracking pixels.
    Returns list of image dictionaries and updates tracking elements.
    """
    images = []
    for img in soup.find_all("img", src=True):
        src = img["src"].strip()
        if not src:
            continue
        
        image_data = {
            "src": src,
            "alt": img.get("alt", ""),
            "dimensions": {"width": img.get("width", ""), "height": img.get("height", "")},
            "is_tracking_pixel": False
        }
        
        if "track" in src.lower() or "pixel" in src.lower():
            image_data["is_tracking_pixel"] = True
            email_data["tracking_elements"].append({"type": "tracking_pixel", "url": src})
        
        images.append(image_data)
    return images

def detect_suspicious_elements(soup, email_data):
    """
    Detect potentially malicious HTML elements.
    Adds suspicious elements to email_data if found.
    """
    for tag, desc in [("script", "JavaScript code"), ("iframe", "iframe elements")]:
        elements = soup.find_all(tag)
        if elements:
            email_data["suspicious_elements"].append({
                "type": tag,
                "description": f"Contains {desc}",
                "count": len(elements)
            })

def extract_url_domain(url):
    """
    Extract domain from a URL.
    Returns empty string if parsing fails.
    """
    try:
        return urlparse(url).netloc
    except Exception:
        return ""

def scan_url_virustotal(url):
    """
    Scan URL using VirusTotal API.
    Returns scan results or error status.
    """
    headers = {"x-apikey": VT_API_KEY}
    try:
        response = requests.post(VT_URL, headers=headers, data={"url": url})
        response.raise_for_status()
        analysis_id = response.json().get("data", {}).get("id")
        
        if analysis_id:
            report = requests.get(f"{VT_URL}/{analysis_id}", headers=headers).json()
            return report if report.get("data", {}).get("attributes", {}).get("status") == "completed" else {"status": "pending"}
    except requests.RequestException as e:
        logger.error(f"VirusTotal URL scan failed: {e}")
        return {"error": str(e)}

def scan_file_virustotal(file_data, filename):
    """
    Scan file content using VirusTotal API.
    Returns scan results or error status.
    """
    VT_FILES_URL = "https://www.virustotal.com/api/v3/files"
    headers = {"x-apikey": VT_API_KEY}
    
    try:
        file_hash = hashlib.sha256(file_data).hexdigest()
        response = requests.get(f"{VT_FILES_URL}/{file_hash}", headers=headers)
        if response.status_code == 200:
            return response.json()
        
        files = {"file": (filename, file_data)}
        response = requests.post(VT_FILES_URL, headers=headers, files=files)
        analysis_id = response.json().get("data", {}).get("id")
        
        if analysis_id:
            return poll_virustotal_report(analysis_id, headers)
    except requests.RequestException as e:
        logger.error(f"VirusTotal file scan failed: {e}")
        return {"error": str(e)}

def poll_virustotal_report(analysis_id, headers):
    """
    Poll VirusTotal for file scan results.
    Returns completed report or pending status after attempts.
    """
    report_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    for attempt in range(5):
        time.sleep(5 * (attempt + 1))
        report = requests.get(report_url, headers=headers).json()
        if report.get("data", {}).get("attributes", {}).get("status") == "completed":
            return report
    return {"status": "pending"}

def analyze_text_with_bert(text, max_length=512):
    """
    Classify text using BERT-based phishing detection model.
    Returns classification result with confidence score.
    """
    try:
        text = text[:max_length] if len(text) > max_length else text
        results = phishing_pipeline(text, top_k=None)
        return {
            "classification": results[0]["label"],
            "confidence": results[0]["score"],
            "details": results
        }
    except Exception as e:
        logger.error(f"BERT analysis failed: {e}")
        return {"classification": "unknown", "confidence": 0, "error": str(e)}

def check_suspicious_patterns(email_data):
    """
    Detect common phishing patterns in email content.
    Returns list of detected suspicious patterns.
    """
    patterns = []
    text = email_data["body_text"].lower()
    subject = email_data["subject"].lower()
    
    urgent_words = ["urgent", "immediately", "alert", "attention", "important"]
    for word in urgent_words:
        if word in subject or word in text:
            patterns.append({"type": "urgent_language", "description": f"Detected '{word}'"})
    
    return patterns

def analyze_eml_file(eml_path):
    """
    Perform comprehensive analysis of an email file.
    Returns detailed analysis results including risk assessment.
    """
    logger.info(f"Starting analysis of {eml_path}")
    email_data, msg = extract_email_content(eml_path)
    if not email_data:
        return {"error": "Email processing failed"}
    
    email_data["suspicious_patterns"] = check_suspicious_patterns(email_data)
    email_data["phishing_analysis"] = analyze_text_with_bert(email_data["body_text"])
    if email_data["subject"] != "No Subject":
        email_data["subject_analysis"] = analyze_text_with_bert(email_data["subject"])
    
    email_data["scan_results"] = {link["url"]: scan_url_virustotal(link["url"]) 
                                 for link in email_data["links"][:3] if link["suspicious"]}
    
    email_data["risk_score"] = min(calculate_risk_score(email_data), 10)
    email_data["risk_level"] = "High" if email_data["risk_score"] > 7 else "Medium" if email_data["risk_score"] > 4 else "Low"
    email_data["summary"] = generate_summary(email_data)
    
    return email_data

def calculate_risk_score(email_data):
    """
    Calculate a weighted risk score based on multiple indicators.
    Returns numerical score reflecting phishing likelihood.
    """
    score = 0
    if email_data["phishing_analysis"]["classification"] == "PHISHING EMAIL":
        score += email_data["phishing_analysis"]["confidence"] * 5
    score += len(email_data["suspicious_elements"]) * 0.5
    score += len(email_data["suspicious_patterns"]) * 0.7
    return score

def generate_summary(email_data):
    """
    Generate a concise summary of the analysis findings.
    Returns dictionary with risk level and classification details.
    """
    return {
        "risk_assessment": {
            "level": email_data["risk_level"],
            "score": round(email_data["risk_score"], 1)
        },
        "ai_classification": {
            "result": email_data["phishing_analysis"]["classification"],
            "confidence": round(email_data["phishing_analysis"]["confidence"] * 100, 1)
        }
    }

def save_analysis_report(analysis_result, output_path=None):
    """
    Save analysis results to a JSON file.
    Returns path to saved report or None if failed.
    """
    output_path = output_path or f"email_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    try:
        with open(output_path, "w") as f:
            json.dump(analysis_result, f, indent=4)
        logger.info(f"Report saved to {output_path}")
        return output_path
    except Exception as e:
        logger.error(f"Failed to save report: {e}")
        return None

def on_upload_button_click():
    """
    Callback function triggered by the GUI upload button.
    Assumes GUI.py provides a method to get the uploaded .eml file path.
    """
    eml_path = GUI.get_uploaded_file_path()
    if eml_path and os.path.exists(eml_path):
        logger.info(f"File uploaded via GUI: {eml_path}")
        result = analyze_eml_file(eml_path)
        if "summary" in result:
            GUI.display_summary(json.dumps(result["summary"], indent=2))
        report_path = save_analysis_report(result)
        if report_path:
            GUI.show_report_path(report_path)
    else:
        logger.error("No valid .eml file selected!")
        GUI.show_error("Please select a valid .eml file!")

if __name__ == "__main__":
    """
    Main entry point initializing the GUI application.
    Connects the upload button callback and starts the Tkinter loop.
    """
    GUI.initialize_gui(on_upload_button_click)
    GUI.run()