import email
import os
import requests
import re
import torch
import json
import time
import logging
import hashlib
import subprocess
import sys
import shutil
import tempfile
from tkinter import filedialog, messagebox, Tk, Canvas, Entry, Text, Button, PhotoImage
from datetime import datetime
from urllib.parse import urlparse
from pathlib import Path
from email import policy
from email.parser import BytesParser
from bs4 import BeautifulSoup
from transformers import pipeline, AutoTokenizer, AutoModelForSequenceClassification

# Configure logging with timestamps and file output
log_filename = f"email_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
logging.basicConfig(
    level=logging.INFO, 
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_filename),
        logging.StreamHandler()
    ]
)

# VirusTotal API Key
VT_API_KEY = "YOUR_VIRUSTOTAL_API_KEY"
VT_URL = "https://www.virustotal.com/api/v3/urls"

# Load phishing detection model
try:
    pipe = pipeline("text-classification", model="dima806/phishing-email-detection")
    tokenizer = AutoTokenizer.from_pretrained("dima806/phishing-email-detection")
    model = AutoModelForSequenceClassification.from_pretrained("dima806/phishing-email-detection")
    logging.info("Successfully loaded phishing detection model")
except Exception as e:
    logging.error(f"Failed to load model: {e}")
    raise

# GUI-related variables and setup
uploaded_eml_files = []
OUTPUT_PATH = Path(__file__).parent
ASSETS_PATH = OUTPUT_PATH / Path(r"/home/putbullet/Desktop/Codes/PG/Codes/frame0")

def relative_to_assets(path: str) -> Path:
    return ASSETS_PATH / Path(path)

def open_settings():
    window.destroy()
    subprocess.Popen([sys.executable, "/home/putbullet/Desktop/Codes/PG/Codes/PgSettings/gui.py"])

def extract_headers(msg):
    """Extract and analyze email headers"""
    headers = {}
    for header in ['subject', 'from', 'to', 'cc', 'bcc', 'date', 'message-id', 'reply-to',
                  'x-mailer', 'received', 'received-spf', 'authentication-results', 
                  'dkim-signature', 'content-type']:
        if header.lower() in msg:
            headers[header] = msg[header]
    
    sender_ip = extract_sender_ip(msg)
    if sender_ip:
        headers['sender_ip'] = sender_ip
    
    headers['anomalies'] = check_header_anomalies(msg)
    return headers

def extract_sender_ip(msg):
    """Extract sender IP from various headers"""
    if 'received-spf' in msg:
        spf = msg['received-spf']
        ip_pattern = r"client-ip=([\d\.:a-fA-F]+)"
        ip_match = re.search(ip_pattern, spf)
        if ip_match:
            return ip_match.group(1)
    
    if 'received' in msg:
        received_headers = msg.get_all('received')
        if received_headers:
            first_received = received_headers[-1]
            ip_patterns = [
                r"\[([\d\.:a-fA-F]+)\]",
                r"from\s+\S+\s+\(([\d\.:a-fA-F]+)\)",
            ]
            for pattern in ip_patterns:
                ip_match = re.search(pattern, first_received)
                if ip_match:
                    return ip_match.group(1)
    return "Unknown IP"

def check_header_anomalies(msg):
    """Check for suspicious patterns in email headers"""
    anomalies = []
    if 'from' in msg and 'reply-to' in msg:
        from_domain = extract_domain(msg['from'])
        reply_to_domain = extract_domain(msg['reply-to'])
        if from_domain and reply_to_domain and from_domain != reply_to_domain:
            anomalies.append(f"Mismatched From ({from_domain}) and Reply-To ({reply_to_domain}) domains")
    if 'message-id' not in msg:
        anomalies.append("Missing Message-ID")
    elif not re.match(r"<[^@]+@[^>]+>", msg['message-id']):
        anomalies.append("Malformed Message-ID")
    if 'authentication-results' in msg:
        auth_results = msg['authentication-results']
        if 'spf=fail' in auth_results.lower():
            anomalies.append("SPF authentication failed")
        if 'dkim=fail' in auth_results.lower():
            anomalies.append("DKIM authentication failed")
    return anomalies

def extract_domain(address):
    """Extract domain from email address"""
    if not address:
        return None
    match = re.search(r"@([^>]+)", address)
    if match:
        return match.group(1).strip()
    return None

def extract_email_content(eml_path):
    """Extract content from an EML file and return both email data and the parsed message"""
    try:
        with open(eml_path, "rb") as eml_file:
            msg = BytesParser(policy=policy.default).parse(eml_file)
    except Exception as e:
        logging.error(f"Failed to parse EML file: {e}")
        return None, None
    
    headers = extract_headers(msg)
    email_data = {
        "subject": msg["subject"] if msg["subject"] else "No Subject",
        "from": msg["from"] if msg["from"] else "Unknown Sender",
        "to": msg["to"] if msg["to"] else "Unknown Recipient",
        "date": msg["date"] if msg["date"] else "Unknown Date",
        "headers": headers,
        "links": [],
        "images": [],
        "attachments": [],
        "tracking_elements": [],
        "body_plain": "",
        "body_html": "",
        "body_text": "",
        "suspicious_elements": []
    }

    email_body_plain = ""
    email_body_html = ""
    
    for part in msg.walk():
        content_type = part.get_content_type()
        try:
            if part.get_content_disposition() == "attachment":
                filename = part.get_filename()
                if filename:
                    _, ext = os.path.splitext(filename)
                    try:
                        file_size = len(part.get_payload(decode=True) or b'')
                    except:
                        file_size = 0
                    email_data["attachments"].append({
                        "filename": filename,
                        "content_type": part.get_content_type(),
                        "extension": ext.lower(),
                        "size": file_size
                    })
                continue
                
            content = part.get_payload(decode=True)
            if content:
                decoded_content = content.decode(errors="ignore")
                if content_type == "text/plain":
                    email_body_plain = decoded_content
                elif content_type == "text/html":
                    email_body_html = decoded_content
        except Exception as e:
            logging.warning(f"Error decoding email content: {e}")

    email_data["body_plain"] = email_body_plain.strip()
    email_data["body_html"] = email_body_html
    
    if not email_body_plain and email_body_html:
        soup = BeautifulSoup(email_body_html, "html.parser")
        email_body_plain = soup.get_text(separator=' ', strip=True)
    
    email_data["body_text"] = re.sub(r'\s+', ' ', email_body_plain.strip())
    if email_body_html:
        analyze_html_content(email_body_html, email_data)
    
    return email_data, msg

def analyze_html_content(html_content, email_data):
    """Analyze HTML content for links, images, and suspicious elements"""
    soup = BeautifulSoup(html_content, "html.parser")
    
    links = []
    for a in soup.find_all("a", href=True):
        href = a["href"].strip()
        link_text = a.get_text(strip=True)
        if not href:
            continue
        link_data = {
            "url": href,
            "text": link_text,
            "domain": extract_url_domain(href),
            "suspicious": False,
            "reasons": []
        }
        if link_text and href and link_text != href and not href.startswith("mailto:"):
            if link_text.lower() in ["click here", "login", "verify", "update", "account"]:
                link_data["suspicious"] = True
                link_data["reasons"].append("Generic phishing link text")
            url_in_text = re.search(r'https?://[^\s<>"]+', link_text)
            if url_in_text and url_in_text.group(0) != href:
                link_data["suspicious"] = True
                link_data["reasons"].append("URL in text doesn't match href")
        if "url=" in href or "redirect" in href.lower():
            link_data["suspicious"] = True
            link_data["reasons"].append("Possible redirect link")
        links.append(link_data)
    
    email_data["links"] = links
    
    images = []
    for img in soup.find_all("img"):
        src = img.get("src", "")
        if not src:
            continue
        dimensions = {
            "width": img.get("width", ""),
            "height": img.get("height", "")
        }
        image_data = {
            "src": src,
            "alt": img.get("alt", ""),
            "dimensions": dimensions,
            "is_tracking_pixel": False
        }
        if (dimensions["width"] in ["0", "1", "2"] or 
            dimensions["height"] in ["0", "1", "2"] or
            "track" in src.lower() or
            "pixel" in src.lower()):
            image_data["is_tracking_pixel"] = True
            email_data["tracking_elements"].append({
                "type": "tracking_pixel",
                "url": src
            })
        images.append(image_data)
    
    email_data["images"] = images
    
    if soup.find_all("script"):
        email_data["suspicious_elements"].append({
            "type": "script",
            "description": "Contains JavaScript code",
            "count": len(soup.find_all("script"))
        })
    if soup.find_all("iframe"):
        email_data["suspicious_elements"].append({
            "type": "iframe",
            "description": "Contains iframe elements",
            "count": len(soup.find_all("iframe"))
        })
    hidden_elements = soup.select("[style*='display:none'], [style*='display: none'], [style*='visibility:hidden'], [style*='visibility: hidden'], [hidden]")
    if hidden_elements:
        email_data["suspicious_elements"].append({
            "type": "hidden_content",
            "description": "Contains hidden elements",
            "count": len(hidden_elements)
        })
    forms = soup.find_all("form")
    if forms:
        for form in forms:
            action = form.get("action", "")
            email_data["suspicious_elements"].append({
                "type": "form",
                "description": "Contains form element",
                "action": action,
                "inputs": len(form.find_all("input"))
            })
    base64_patterns = re.findall(r'base64,[a-zA-Z0-9+/=]{100,}', html_content)
    if base64_patterns:
        email_data["suspicious_elements"].append({
            "type": "base64_encoding",
            "description": "Contains base64 encoded content",
            "count": len(base64_patterns)
        })
    meta_tags = soup.find_all("meta")
    for meta in meta_tags:
        if "content" in meta.attrs and ("microsoft" in meta.get("content", "").lower() or 
                                      "google" in meta.get("content", "").lower() or
                                      "apple" in meta.get("content", "").lower()):
            email_data["suspicious_elements"].append({
                "type": "meta_tag",
                "description": "Contains meta tags that may suggest brand spoofing",
                "content": meta.get("content", "")
            })

def extract_url_domain(url):
    """Extract domain from URL"""
    try:
        parsed_url = urlparse(url)
        return parsed_url.netloc
    except:
        return ""

def scan_url_virustotal(url):
    headers = {"x-apikey": VT_API_KEY}
    data = {"url": url}
    try:
        response = requests.post(VT_URL, headers=headers, data=data)
        response.raise_for_status()
        result = response.json()
        analysis_id = result.get("data", {}).get("id")
        if analysis_id:
            report_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
            report_response = requests.get(report_url, headers=headers)
            if report_response.status_code == 200:
                return report_response.json()
        return result
    except requests.exceptions.RequestException as e:
        logging.error(f"VirusTotal API request failed: {e}")
        return {"error": "Failed to scan URL"}

def scan_file_virustotal(file_data, filename):
    VT_FILES_URL = "https://www.virustotal.com/api/v3/files"
    headers = {"x-apikey": VT_API_KEY}
    try:
        file_hash = hashlib.sha256(file_data).hexdigest()
        check_url = f"{VT_FILES_URL}/{file_hash}"
        response = requests.get(check_url, headers=headers)
        if response.status_code == 200:
            logging.info(f"File {filename} found in VirusTotal database")
            return response.json()
        logging.info(f"Submitting file {filename} to VirusTotal for analysis")
        files = {"file": (filename, file_data)}
        response = requests.post(VT_FILES_URL, headers=headers, files=files)
        response.raise_for_status()
        result = response.json()
        analysis_id = result.get("data", {}).get("id")
        if analysis_id:
            report_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
            max_attempts = 5
            for attempt in range(max_attempts):
                logging.info(f"Polling for analysis results, attempt {attempt+1}/{max_attempts}")
                time.sleep(5 * (attempt + 1))
                report_response = requests.get(report_url, headers=headers)
                if report_response.status_code == 200:
                    report_data = report_response.json()
                    status = report_data.get("data", {}).get("attributes", {}).get("status")
                    if status == "completed":
                        return report_data
            return {"status": "pending", "message": "Analysis in progress, check back later"}
        return result
    except requests.exceptions.RequestException as e:
        logging.error(f"VirusTotal API request failed: {e}")
        return {"error": "Failed to scan file", "details": str(e)}

def check_ip(ip_address):
    """Scan an IP address using VirusTotal API"""
    url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip_address}'
    headers = {'x-apikey': VT_API_KEY}
    try:
        logging.info(f"Scanning IP address: {ip_address}")
        response = requests.get(url, headers=headers)
        if response.status_code != 200:
            raise requests.exceptions.RequestException(f"API request failed with status code {response.status_code}")
        response_json = response.json()
        if 'data' not in response_json:
            raise ValueError("Invalid response structure")
        attributes = response_json['data']['attributes']
        
        as_owner = attributes.get('as_owner')
        country = attributes.get('country')
        stat_analysis = attributes.get('last_analysis_stats')
        
        malicious = stat_analysis.get('malicious')
        suspicious = stat_analysis.get('suspicious')
        undetected = stat_analysis.get('undetected')
        harmless = stat_analysis.get('harmless')
        
        total = int(malicious) + int(suspicious) + int(undetected) + int(harmless)

        result = {
            'IP Address': ip_address,
            'Country': country,
            'Owner': as_owner,
            'Malicious': malicious,
            'Suspicious': suspicious,
            'Undetected': undetected,
            'Harmless': harmless,
            'Total': total
        }
        logging.info(f"IP scan completed for {ip_address}: Malicious={malicious}, Suspicious={suspicious}")
        return result
    except Exception as e:
        logging.error(f"Failed to scan IP {ip_address}: {e}")
        return {"error": str(e), "IP Address": ip_address}

def analyze_text_with_bert(text, max_length=512):
    try:
        if len(text) > max_length:
            text = text[:max_length]
        results = pipe(text, top_k=None)
        return {
            "classification": results[0]["label"],
            "confidence": results[0]["score"],
            "details": results
        }
    except Exception as e:
        logging.error(f"BERT analysis failed: {e}")
        return {"classification": "unknown", "confidence": 0, "error": str(e)}

def check_suspicious_patterns(email_data):
    """Check for suspicious patterns in email content"""
    patterns = []
    urgent_words = ["urgent", "immediately", "alert", "attention", "important", 
                    "verify", "suspended", "locked", "validate", "security"]
    text = email_data["body_text"].lower()
    subject = email_data["subject"].lower()
    
    for word in urgent_words:
        if word in subject:
            patterns.append({
                "type": "urgent_language",
                "location": "subject",
                "description": f"Urgent language: '{word}'"
            })
        if word in text:
            patterns.append({
                "type": "urgent_language",
                "location": "body",
                "description": f"Urgent language: '{word}'"
            })
    
    info_patterns = [
        (r'password', "Requests password"),
        (r'username', "Requests username"),
        (r'credit card', "Requests credit card"),
        (r'ssn|social security', "Requests Social Security Number"),
        (r'bank account', "Requests bank account information")
    ]
    for pattern, description in info_patterns:
        if re.search(pattern, text, re.IGNORECASE):
            patterns.append({
                "type": "personal_info_request",
                "description": description
            })
    return patterns

def analyze_eml_file(eml_path):
    """Analyze an EML file for phishing and other risks, including IP scanning"""
    logging.info(f"Analyzing {eml_path}")
    email_data, msg = extract_email_content(eml_path)
    if not email_data or not msg:
        return {"error": "Failed to process email"}
    
    email_data["suspicious_patterns"] = check_suspicious_patterns(email_data)
    email_data["phishing_analysis"] = analyze_text_with_bert(email_data["body_text"])
    if email_data["subject"] != "No Subject":
        email_data["subject_analysis"] = analyze_text_with_bert(email_data["subject"])
    
    scan_results = {}
    suspicious_link_count = 0
    for link in email_data["links"]:
        if link["suspicious"]:
            suspicious_link_count += 1
            url = link["url"]
            if re.match(r"^https?://", url):
                scan_results[url] = scan_url_virustotal(url)
            if suspicious_link_count >= 3:
                break
    email_data["scan_results"] = scan_results
    
    sender_ip = email_data["headers"].get("sender_ip", "Unknown IP")
    if sender_ip != "Unknown IP":
        ip_scan_result = check_ip(sender_ip)
        email_data["ip_scan_result"] = ip_scan_result
    else:
        email_data["ip_scan_result"] = {"error": "No sender IP found"}

    risk_score = calculate_risk_score(email_data)
    email_data["risk_score"] = min(risk_score, 10)
    email_data["risk_level"] = "High" if risk_score > 7 else "Medium" if risk_score > 4 else "Low"
    
    content_hash = hashlib.sha256((email_data["body_plain"] + email_data["body_html"]).encode()).hexdigest()
    email_data["content_hash"] = content_hash
    
    email_data["summary"] = generate_summary(email_data)
    
    attachment_scan_results = {}
    for attachment in email_data["attachments"]:
        try:
            for part in msg.walk():
                if part.get_content_disposition() == "attachment" and part.get_filename() == attachment["filename"]:
                    file_data = part.get_payload(decode=True)
                    if file_data:
                        logging.info(f"Scanning attachment: {attachment['filename']}")
                        scan_result = scan_file_virustotal(file_data, attachment["filename"])
                        attachment_scan_results[attachment["filename"]] = scan_result
                    break
        except Exception as e:
            logging.error(f"Failed to scan attachment {attachment['filename']}: {e}")
            attachment_scan_results[attachment["filename"]] = {"error": str(e)}
    
    email_data["attachment_scan_results"] = attachment_scan_results
    return email_data

def calculate_risk_score(email_data):
    """Calculate risk score based on multiple factors, including IP scan"""
    risk_score = 0
    
    if email_data["phishing_analysis"]["classification"] == "PHISHING EMAIL":
        risk_score += email_data["phishing_analysis"]["confidence"] * 5
    if "subject_analysis" in email_data and email_data["subject_analysis"]["classification"] == "PHISHING EMAIL":
        risk_score += email_data["subject_analysis"]["confidence"] * 2
    risk_score += len(email_data["suspicious_elements"]) * 0.5
    risk_score += len(email_data["suspicious_patterns"]) * 0.7
    if "headers" in email_data and "anomalies" in email_data["headers"]:
        risk_score += len(email_data["headers"]["anomalies"]) * 0.8
    suspicious_links = [link for link in email_data["links"] if link["suspicious"]]
    risk_score += len(suspicious_links) * 0.6
    risk_score += len(email_data["tracking_elements"]) * 0.3
    
    risky_extensions = [".exe", ".js", ".vbs", ".bat", ".cmd", ".scr", ".pif"]
    for attachment in email_data["attachments"]:
        if "extension" in attachment and attachment["extension"].lower() in risky_extensions:
            risk_score += 2
    
    if "ip_scan_result" in email_data and "Malicious" in email_data["ip_scan_result"]:
        risk_score += email_data["ip_scan_result"]["Malicious"] * 1.5
        risk_score += email_data["ip_scan_result"]["Suspicious"] * 0.5
    
    return risk_score

def generate_summary(email_data):
    """Generate a JSON-formatted summary of the analysis"""
    summary = {
        "risk_assessment": {
            "level": email_data['risk_level'],
            "score": round(email_data['risk_score'], 1)
        },
        "ai_classification": {
            "result": email_data["phishing_analysis"]["classification"],
            "confidence": round(email_data["phishing_analysis"]["confidence"] * 100, 1)
        },
        "key_concerns": []
    }
    
    if "headers" in email_data and "anomalies" in email_data["headers"] and email_data["headers"]["anomalies"]:
        summary["key_concerns"].append({
            "type": "header_anomalies",
            "items": email_data["headers"]["anomalies"]
        })
    if email_data["suspicious_elements"]:
        summary["key_concerns"].append({
            "type": "suspicious_elements",
            "items": [{"element": element["type"], "description": element["description"]} 
                     for element in email_data["suspicious_elements"]]
        })
    if email_data["suspicious_patterns"]:
        summary["key_concerns"].append({
            "type": "suspicious_patterns",
            "items": [pattern["description"] for pattern in email_data["suspicious_patterns"]]
        })
    suspicious_links = [link for link in email_data["links"] if link["suspicious"]]
    if suspicious_links:
        summary["key_concerns"].append({
            "type": "suspicious_links",
            "count": len(suspicious_links),
            "items": [{"url": link["url"], "reasons": link["reasons"]} for link in suspicious_links]
        })
    if email_data["tracking_elements"]:
        summary["key_concerns"].append({
            "type": "tracking_elements",
            "count": len(email_data["tracking_elements"]),
            "items": email_data["tracking_elements"]
        })
    
    risky_attachments = []
    for attachment in email_data["attachments"]:
        if "extension" in attachment and attachment["extension"].lower() in [".exe", ".js", ".vbs", ".bat", ".cmd", ".scr", ".pif"]:
            risky_attachments.append(attachment["filename"])
    if risky_attachments:
        summary["key_concerns"].append({
            "type": "risky_attachments",
            "items": risky_attachments
        })
    
    if "ip_scan_result" in email_data and "error" not in email_data["ip_scan_result"]:
        ip_concern = {
            "type": "ip_analysis",
            "ip_address": email_data["ip_scan_result"]["IP Address"],
            "country": email_data["ip_scan_result"]["Country"],
            "owner": email_data["ip_scan_result"]["Owner"],
            "malicious": email_data["ip_scan_result"]["Malicious"],
            "suspicious": email_data["ip_scan_result"]["Suspicious"]
        }
        summary["key_concerns"].append(ip_concern)
    elif "ip_scan_result" in email_data and "error" in email_data["ip_scan_result"]:
        summary["key_concerns"].append({
            "type": "ip_analysis",
            "error": email_data["ip_scan_result"]["error"]
        })
    
    return summary

def save_analysis_report(analysis_result, output_path=None):
    """Save analysis results to a JSON file"""
    if not output_path:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = f"email_analysis_{timestamp}.json"
    
    try:
        with open(output_path, "w") as f:
            json.dump(analysis_result, f, indent=4)
        logging.info(f"Analysis report saved to {output_path}")
        return output_path
    except Exception as e:
        logging.error(f"Failed to save analysis report: {e}")
        return None

def upload_eml_files():
    """Upload EML files and trigger analysis"""
    global uploaded_eml_files
    
    filetypes = [("EML files", "*.eml"), ("All files", "*.*")]
    file_paths = filedialog.askopenfilenames(title="Select EML Files", filetypes=filetypes)
    
    if not file_paths:
        return
    
    save_dir = os.path.join(OUTPUT_PATH, "uploaded_emails")
    if not os.path.exists(save_dir):
        os.makedirs(save_dir)
    
    uploaded_eml_files = []
    for file_path in file_paths:
        file_name = os.path.basename(file_path)
        save_path = os.path.join(save_dir, file_name)
        shutil.copy2(file_path, save_path)
        uploaded_eml_files.append(save_path)
    
    messagebox.showinfo("Files Uploaded", f"{len(uploaded_eml_files)} EML files have been uploaded successfully")
    
    with open(os.path.join(OUTPUT_PATH, "uploaded_files.txt"), "w") as f:
        for file_path in uploaded_eml_files:
            f.write(f"{file_path}\n")
    
    # Trigger analysis on the first uploaded file
    if uploaded_eml_files:
        eml_file_path = uploaded_eml_files[0]
        if os.path.exists(eml_file_path):
            analysis_result = analyze_eml_file(eml_file_path)
            if "summary" in analysis_result:
                print("\n" + "="*50)
                print("ANALYSIS SUMMARY")
                print("="*50)
                print(json.dumps(analysis_result["summary"], indent=2))
                print("="*50 + "\n")
            report_path = save_analysis_report(analysis_result)
            if report_path:
                messagebox.showinfo("Analysis Complete", f"Analysis completed. Full report saved to: {report_path}")
            else:
                messagebox.showerror("Analysis Failed", "Failed to save the analysis report.")
        else:
            messagebox.showerror("File Error", "Uploaded EML file not found!")
    
    return uploaded_eml_files

# GUI Setup
window = Tk()
window.title("PhishGuard")
window.geometry("737x707")
window.configure(bg="#FFFFFF")

canvas = Canvas(
    window,
    bg="#FFFFFF",
    height=707,
    width=737,
    bd=0,
    highlightthickness=0,
    relief="ridge"
)
canvas.place(x=0, y=0)
canvas.create_rectangle(
    0.0,
    0.0,
    737.0,
    701.0,
    fill="#D9D9D9",
    outline="")

button_image_1 = PhotoImage(file=relative_to_assets("button_1.png"))
button_1 = Button(
    image=button_image_1,
    borderwidth=0,
    highlightthickness=0,
    command=upload_eml_files,
    relief="flat"
)
button_1.place(
    x=218.0,
    y=602.0,
    width=301.0,
    height=77.0
)

canvas.create_rectangle(
    0.0,
    0.0,
    737.0,
    591.0,
    fill="#3776FF",
    outline="")

image_image_1 = PhotoImage(file=relative_to_assets("image_1.png"))
image_1 = canvas.create_image(
    270.0,
    315.0,
    image=image_image_1
)

button_image_2 = PhotoImage(file=relative_to_assets("button_2.png"))
button_2 = Button(
    image=button_image_2,
    borderwidth=0,
    highlightthickness=0,
    bg="#3776FF",
    activebackground="#3776FF",
    command=open_settings,
    relief="flat"
)
button_2.place(
    x=10.0,
    y=14.0,
    width=24.0,
    height=24.0
)

image_image_2 = PhotoImage(file=relative_to_assets("image_2.png"))
image_2 = canvas.create_image(
    240.0,
    102.0,
    image=image_image_2
)

image_image_3 = PhotoImage(file=relative_to_assets("image_3.png"))
image_3 = canvas.create_image(
    587.0,
    315.0,
    image=image_image_3
)

window.resizable(False, False)

if __name__ == "__main__":
    window.mainloop()