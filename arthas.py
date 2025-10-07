#!/usr/bin/env python3
"""
Email Phishing Analyzer CLI Tool
Analyzes .eml files searching for phishing indicators such as:
- Suspicious links (VirusTotal check)
- Sender spoofing (envelope vs header comparison)
- Domain age
- Header inconsistencies
"""

import re
import email
import email.policy
from email.header import decode_header
import requests
import hashlib
import os
import whois
from datetime import datetime
import sys
from bs4 import BeautifulSoup

# Config
VIRUSTOTAL_API_KEY = "<apikeyhere>"
HEADER_ANALYSIS_RULES = {
    'spf_fail': {'pattern': r'SPF=(fail|softfail)', 'message': 'SPF validation failed', 'invert': False},
    'missing_dkim': {'pattern': r'DKIM-Signature:', 'message': 'Missing DKIM signature', 'invert': True},
    'x_mailer': {'pattern': r'X-Mailer:', 'message': 'Client mailer information', 'invert': False},
}

def get_envelope_sender(msg):
    """Extract real sender from email envelope"""
    return_path = msg.get('Return-Path', '')
    if return_path:
        return return_path.strip('<>')

    received_headers = msg.get_all('Received', [])
    if received_headers:
        first_received = received_headers[0]
        matches = re.search(r'from\s+([^\s]+)', first_received, re.IGNORECASE)
        if matches:
            return matches.group(1)
    
    return None

def extract_domain(email_address):
    """Extract domain from email address"""
    if not email_address or '@' not in email_address:
        return None
    domain_part = email_address.split('@')[-1].lower().strip('>')
    return re.sub(r'[^a-z0-9.-]', '', domain_part)

def check_domain_age(domain):
    """Check domain age using WHOIS"""
    if not domain:
        return None
    try:
        domain_info = whois.whois(domain)
        creation_date = domain_info.creation_date
        
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        
        if creation_date:
            return (datetime.now() - creation_date).days
    except Exception:
        return None
    return None

def check_virustotal(url):
    """Check URL reputation via VirusTotal"""
    if not VIRUSTOTAL_API_KEY:
        return False

    url_id = hashlib.sha256(url.encode()).hexdigest()
    headers = {'x-apikey': VIRUSTOTAL_API_KEY}
    
    try:
        response = requests.get(
            f'https://www.virustotal.com/api/v3/urls/{url_id}',
            headers=headers,
            timeout=10
        )
        if response.status_code == 200:
            result = response.json()
            return result['data']['attributes']['last_analysis_stats']['malicious'] > 0
    except requests.RequestException:
        pass
    
    return False

def analyze_headers(headers):
    """Check for suspicious headers"""
    findings = []
    headers_str = '\n'.join(f"{k}: {v}" for k, v in headers.items())

    for rule_name, rule in HEADER_ANALYSIS_RULES.items():
        has_match = bool(re.search(rule['pattern'], headers_str, re.IGNORECASE))
        if (has_match and not rule['invert']) or (not has_match and rule['invert']):
            findings.append(f"⚠️ {rule['message']}")

    return findings

def parse_eml(file_path):
    """Parse .eml and extract key components"""
    with open(file_path, 'rb') as f:
        try:
            msg = email.message_from_binary_file(f, policy=email.policy.default)
        except ValueError as e:
            print(f"[!] Warning: Failed to parse with default policy: {e}")
            print("[!] Falling back to compat32 policy...")
            f.seek(0)  # Rewind file pointer
            msg = email.message_from_binary_file(f, policy=email.policy.compat32)


    sender = msg.get('From', '')
    subject = decode_header(msg.get('Subject', ''))[0][0]
    if isinstance(subject, bytes):
        subject = subject.decode(errors='ignore')

    links = set()
    body = ""

    for part in msg.walk():
        content_type = part.get_content_type()
        payload = part.get_payload(decode=True)
        if payload:
            content = payload.decode(errors='ignore')
            if content_type == 'text/plain':
                body += content
                # Extract links from plain text with regex
                url_pattern = r'(?:(?:https?|ftp)://|www\.)[^\s<>"]+'
                links.update(re.findall(url_pattern, content, re.IGNORECASE))
            elif content_type == 'text/html':
                # Extract links from HTML with BeautifulSoup
                soup = BeautifulSoup(content, 'html.parser')
                for tag in soup.find_all('a', href=True):
                    href = tag['href']
                    links.add(href)
                # Add visible text for possible secondary analysis
                body += soup.get_text(separator=' ', strip=True)

    return {
        'sender': sender,
        'envelope_sender': get_envelope_sender(msg),
        'subject': subject,
        'links': list(links),
        'headers': dict(msg.items()),
        'body': body,
        'msg_obj': msg  # Added to pass original email message object for IP extraction
    }

# NEW - Extract sender IP from Received headers
def get_sender_ip(msg):
    """Extract originating IP from Received headers"""
    received_headers = msg.get_all('Received', [])
    if not received_headers:
        return None

    for header in reversed(received_headers):
        ip_match = re.search(r'\b(\d{1,3}(?:\.\d{1,3}){3})\b', header)
        if ip_match:
            ip = ip_match.group(1)
            octets = ip.split('.')
            if all(0 <= int(octet) <= 255 for octet in octets):
                return ip
    return None

# NEW - Check IP reputation in VirusTotal
def check_ip_virustotal(ip):
    """Check IP reputation via VirusTotal"""
    if not VIRUSTOTAL_API_KEY:
        return False

    headers = {'x-apikey': VIRUSTOTAL_API_KEY}

    try:
        response = requests.get(
            f'https://www.virustotal.com/api/v3/ip_addresses/{ip}',
            headers=headers,
            timeout=10
        )
        if response.status_code == 200:
            result = response.json()
            return result['data']['attributes']['last_analysis_stats']['malicious'] > 0
    except requests.RequestException:
        pass
    return False

def analyze_email(file_path):
    """Run full email analysis"""
    data = parse_eml(file_path)
    msg_obj = data.get('msg_obj')

    print(f"\n📧 Email Analysis: {file_path}")
    print(f"📌 Subject: {data['subject']}")
    print(f"👤 From: {data['sender']}")
    print(f"📮 Envelope From: {data['envelope_sender'] or 'Not available'}")

    from_domain = extract_domain(data['sender'])
    envelope_domain = extract_domain(data['envelope_sender'])

    if from_domain and envelope_domain and (from_domain != envelope_domain):
        print("\n🚨 SENDER SPOOFING DETECTED!")
        print(f"  - Displayed domain: {from_domain}")
        print(f"  - Actual domain: {envelope_domain}")

    if from_domain:
        domain_age = check_domain_age(from_domain)
        if domain_age is not None:
            if domain_age < 30:
                print(f"⚠️ Suspicious: Domain '{from_domain}' is only {domain_age} days old")
            else:
                print(f"✓ Domain age: {domain_age} days")
        else:
            print(f"⚠️ Could not verify domain age for '{from_domain}'")

    header_findings = analyze_headers(data['headers'])
    if header_findings:
        print("\n🔍 Header Analysis:")
        for finding in header_findings:
            print(f"  - {finding}")

    malicious_links = []
    if data['links']:
        print("\n🔗 Found Links:")
        for link in data['links']:
            if check_virustotal(link):
                malicious_links.append(link)
                print(f"  - 🚨 MALICIOUS: {link}")
            else:
                print(f"  - ✓ Clean: {link}")

    # NEW - Extract and analyze sender IP
    sender_ip = get_sender_ip(msg_obj)
    if sender_ip:
        print(f"\n🌐 Sender IP detected: {sender_ip}")
        if check_ip_virustotal(sender_ip):
            print(f"🚨 ALERT: Sender IP {sender_ip} is flagged as malicious on VirusTotal")
        else:
            print(f"✓ Sender IP {sender_ip} appears clean according to VirusTotal")
    else:
        print("\n🌐 Sender IP not found in Received headers")

    print("\n📊 Summary:")
    print(f"  - Total links: {len(data['links'])}")
    print(f"  - Malicious links: {len(malicious_links)}")
    print(f"  - Header warnings: {len(header_findings)}")

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: python3 arthas.py <email_file.eml>")
        sys.exit(1)

    if not os.path.exists(sys.argv[1]):
        print(f"Error: File '{sys.argv[1]}' not found")
        sys.exit(1)

    analyze_email(sys.argv[1])
