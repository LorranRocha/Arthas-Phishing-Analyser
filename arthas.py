#!/usr/bin/env python3
"""
Email Phishing Analyzer CLI Tool
Analyzes .eml files for phishing indicators including:
- Suspicious links (VirusTotal check)
- Sender spoofing (envelope vs header comparison)
- Domain age analysis
- Header inconsistencies
"""

import re
import email
import email.policy
from email.header import decode_header
import requests
import hashlib
import os
import socket
import whois
from datetime import datetime
from dotenv import load_dotenv
from urllib.parse import urlparse
import sys

# Configuration
load_dotenv()
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
HEADER_ANALYSIS_RULES = {
    'spf_fail': {'pattern': r'SPF=(fail|softfail)', 'message': 'SPF validation failed', 'invert': False},
    'missing_dkim': {'pattern': r'DKIM-Signature:', 'message': 'Missing DKIM signature', 'invert': True},
    'x_mailer': {'pattern': r'X-Mailer:', 'message': 'Client mailer information', 'invert': False},
}

def get_envelope_sender(msg):
    """Extracts actual sender from email envelope"""
    # 1. Check Return-Path first
    return_path = msg.get('Return-Path', '')
    if return_path:
        return return_path.strip('<>')

    # 2. Parse Received headers as fallback
    received_headers = msg.get_all('Received', [])
    if received_headers:
        first_received = received_headers[0]
        matches = re.search(r'from\s+([^\s]+)', first_received, re.IGNORECASE)
        if matches:
            return matches.group(1)
    
    return None

def extract_domain(email_address):
    """Extracts domain from email address"""
    if not email_address or '@' not in email_address:
        return None
    domain_part = email_address.split('@')[-1].lower().strip('>')
    # Clean domain by removing any % signs and other special characters
    return re.sub(r'[^a-z0-9.-]', '', domain_part)

def check_domain_age(domain):
    """Checks domain registration age using WHOIS"""
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
    """Checks URL reputation with VirusTotal"""
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
    """Checks for suspicious email headers"""
    findings = []
    headers_str = '\n'.join(f"{k}: {v}" for k, v in headers.items())

    for rule_name, rule in HEADER_ANALYSIS_RULES.items():
        has_match = bool(re.search(rule['pattern'], headers_str, re.IGNORECASE))
        if (has_match and not rule['invert']) or (not has_match and rule['invert']):
            findings.append(f"⚠️ {rule['message']}")

    return findings

def parse_eml(file_path):
    """Parses .eml file and extracts key components"""
    with open(file_path, 'rb') as f:
        msg = email.message_from_binary_file(f, policy=email.policy.default)

    # Extract basic info
    sender = msg.get('From', '')
    subject = decode_header(msg.get('Subject', ''))[0][0]
    if isinstance(subject, bytes):
        subject = subject.decode(errors='ignore')
    
    # Extract links from all parts
    links = set()
    body = ""
    
    for part in msg.walk():
        if part.get_content_type() == 'text/plain':
            body += part.get_payload(decode=True).decode(errors='ignore')

    url_pattern = r'(?:(?:https?|ftp)://|www\.)[^\s<>"]+?(?=(?:[\s<>"]|$))'
    links.update(re.findall(url_pattern, body, re.IGNORECASE))

    return {
        'sender': sender,
        'envelope_sender': get_envelope_sender(msg),
        'subject': subject,
        'links': list(links),
        'headers': dict(msg.items()),
        'body': body
    }

def analyze_email(file_path):
    """Runs complete email analysis"""
    data = parse_eml(file_path)
    
    print(f"\n📧 Email Analysis: {file_path}")
    print(f"📌 Subject: {data['subject']}")
    print(f"👤 From: {data['sender']}")
    print(f"📮 Envelope From: {data['envelope_sender'] or 'Not available'}")

    # Sender analysis
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

    # Header analysis
    header_findings = analyze_headers(data['headers'])
    if header_findings:
        print("\n🔍 Header Analysis:")
        for finding in header_findings:
            print(f"  - {finding}")

    # Link analysis
    malicious_links = []
    if data['links']:
        print("\n🔗 Found Links:")
        for link in data['links']:
            if check_virustotal(link):
                malicious_links.append(link)
                print(f"  - 🚨 MALICIOUS: {link}")
            else:
                print(f"  - ✓ Clean: {link}")

    # Summary
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
