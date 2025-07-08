
# 📧 Email Phishing Analyzer CLI Tool

A command-line tool to analyze `.eml` files and detect possible **phishing** indicators and **malicious behaviors**.

---

## 🔍 Features

- **Sender Spoofing Detection**  
  Compares the envelope sender (Return-Path) with the visible sender (From).

- **Suspicious Links Analysis**  
  Extracts URLs from the email body and checks their reputation using the [VirusTotal](https://www.virustotal.com/) API.

- **Domain Age Verification**  
  Uses WHOIS to check how many days the sender's domain has been registered.

- **Header Analysis**  
  Detects inconsistencies and suspicious practices such as:
  - SPF failure
  - Missing DKIM
  - Presence of unusual headers like `X-Mailer`

---

## ⚙️ Requirements

- Python 3.6 or higher
- `.eml` file of the email to be analyzed
- [VirusTotal API Key](https://developers.virustotal.com/reference/overview) (optional but recommended)

---

## 📦 Installation

Create a virtual environment (optional but recommended):

```bash
python3 -m venv venv
source venv/bin/activate  # or venv\Scripts\activate on Windows
```

Install dependencies:

```bash
pip install -r requirements.txt
```

> If you don't have a `requirements.txt`, you can create one with:

```text
requests
python-whois
python-dotenv
```

---

## 🛠️ Configuration

Create a `.env` file in the same directory with your VirusTotal API key:

```dotenv
VIRUSTOTAL_API_KEY=your_api_key_here
```

---

## 🚀 Usage

Run the script with the path to the `.eml` file:

```bash
python3 arthas.py path/to/email.eml
```

### Example:

```bash
python3 arthas.py suspicious_phishing.eml
```

---

## 📄 Sample Output

```
📧 Email Analysis: suspicious_phishing.eml
📌 Subject: Urgent Account Update
👤 From: support@micr0s0ft.com
📮 Envelope From: bounce@unknowndomain.xyz

🚨 SENDER SPOOFING DETECTED!
  - Displayed domain: micr0s0ft.com
  - Actual domain: unknowndomain.xyz
⚠️ Suspicious: Domain 'micr0s0ft.com' is only 5 days old

🔍 Header Analysis:
  - ⚠️ SPF validation failed
  - ⚠️ Missing DKIM signature

🔗 Found Links:
  - 🚨 MALICIOUS: http://bit.ly/fake-update
  - ✓ Clean: https://legitimate-site.com

📊 Summary:
  - Total links: 2
  - Malicious links: 1
  - Header warnings: 2
```

---

## 📌 Notes

- The script **does not execute attachments** or perform sandboxing — only static analysis.
- Without a VirusTotal API key, link reputation **will not be checked**.

---

## 🛡️ Legal Disclaimer

This project is intended solely for **educational and defensive security purposes**.  
Use it responsibly and only on files you have **legal permission** to analyze.

---

## 👨‍💻 Author

Lorran Rocha

---

## 📃 License

MIT License © 2025
