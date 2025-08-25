🛡️ Threat Recon Tool

A simple Python-based threat reconnaissance tool for gathering intelligence about domains, subdomains, and potential threats using multiple OSINT sources.

🚀 Features
🔎 Domain & Subdomain Enumeration – Queries popular OSINT services to extract subdomains.
🛠 Integrated APIs:
VirusTotal (requires API key)
AlienVault OTX
ThreatCrowd
Anubis
Sonar
BufferOver (fallback/manual fix required)

⚡ Error handling for unavailable services or broken APIs.

🧰 Designed for pentesters, bug bounty hunters, and security researchers.

📦 Requirements

Python 3.8+

requests library

Valid VirusTotal API key

🔑 Usage
python threat_recon.py -d example.com

📌 Example Output
[+] Scanning domain: tryhackme.com
[+] Found Subdomains:
 - blog.tryhackme.com
 - labs.tryhackme.com
 - api.tryhackme.com

🔧 Setup & Run
1. Clone the Repository
git clone https://github.com/<your-username>/<repo-name>.git
cd <repo-name>

2. Create & Activate Virtual Environment (optional but recommended)

python -m venv venv
source venv/bin/activate   # Linux/Mac
venv\Scripts\activate      # Windows

4. Install Requirements
pip install -r requirements.txt

5. Add Your API Keys

Open config.json (or .env if you’re using it).

Add your API keys for services (VirusTotal, AbuseIPDB, OTX, etc.).

Example:

{
  "virustotal": "your_api_key_here",
  "abuseipdb": "your_api_key_here"
}

5. Run the Tool
python main.py -d example.com

6. Example Commands

Scan domain:

python main.py -d example.com


Scan IP:

python main.py -i 8.8.8.8

⚠️ Notes

Some APIs (e.g., BufferOver, ThreatCrowd) may no longer work or require manual fixes due to deprecated endpoints / SSL issues.

This tool is meant for educational and research purposes only. Do not use it on targets without authorization.
