# 🛡️ Threat Intelligence Dashboard

A SOC portfolio project that provides real-time threat analysis of IP addresses, domains, and file hashes using VirusTotal and Shodan APIs — displayed in a clean, interactive Streamlit web UI.

---

## 📸 Features

- 🔍 **IP Analysis** — Reputation score, malicious detections, geolocation, open ports, running services, known CVEs
- 🌐 **Domain Analysis** — Registrar info, category classification, malicious engine detections
- 🦠 **File Hash Analysis** — Malware name, file type, AV engine detections (MD5/SHA1/SHA256)
- 🗺️ **Live Map** — Geolocation of IP addresses plotted on an interactive map
- 🤖 **Auto Verdict** — Automatically classifies threats as `MALICIOUS`, `SUSPICIOUS`, or `CLEAN`
- 📡 **Shodan Integration** — Open ports, hostnames, OS detection, CVE exposure

---

## 🛠️ Tech Stack

| Tool | Purpose |
|---|---|
| Python | Core language |
| Streamlit | Web UI framework |
| VirusTotal API v3 | Malware & reputation analysis |
| Shodan API | Port scanning & CVE intelligence |
| ipapi.co | IP geolocation (no key needed) |
| python-dotenv | Secure API key management |

---

## ⚙️ Installation & Setup

### 1. Clone the repository
```bash
https://github.com/navanee7h/Threat-Intelligence-Dashboard.git
cd Threat-Intelligence-Dashboard
```

### 2. Install dependencies
```bash
pip install -r requirement.txt
```

### 3. Get your API keys

| Service | Link | Cost |
|---|---|---|
| VirusTotal | https://virustotal.com → Sign up → Profile → API Key | Free |
| Shodan | https://shodan.io → My Account → API Key | Free (limited) |

### 4. Create a `.env` file in the project root
```
VT_API_KEY=your_virustotal_api_key_here
SHODAN_API_KEY=your_shodan_api_key_here
```
> ⚠️ Never commit your `.env` file to GitHub. It is already listed in `.gitignore`.

### 5. Run the app
```bash
# Option 1 (recommended on Windows)
python -m streamlit run app.py

# Option 2
streamlit run app.py
```

### 6. Open in browser
```
http://localhost:8501
```

---

## 🧪 Sample Test Inputs

| Type | Input | Expected Result |
|---|---|---|
| Malicious IP | `185.220.101.45` | 🔴 Malicious (Tor exit node) |
| Clean IP | `8.8.8.8` | 🟢 Clean (Google DNS) |
| Malicious Domain | `malware.wicar.org` | 🔴 Malicious |
| EICAR Test Hash | Search "eicar md5 hash" on Google | 🔴 Malicious |

---

## 📁 Project Structure

```
threat-intel-dashboard/
├── app.py               # Main Streamlit application
├── .env                 # API keys (never commit this)
├── .gitignore           # Excludes .env from git
├── requirements.txt     # Python dependencies
└── README.md            # Project documentation
```

---

## 🔐 Security Note

This project uses `.env` for API key management. The `.gitignore` file ensures your keys are never pushed to GitHub. Always keep your API keys private.

---

## 📦 requirements.txt

```
streamlit
requests
shodan
python-dotenv
```

---

## 🚀 How This Relates to SOC Work

This project simulates core L1 SOC analyst tasks:

- **Alert Triage** — Quickly determine if an IP/domain/hash is malicious
- **Threat Intelligence** — Enrich indicators with VirusTotal + Shodan data
- **IOC Investigation** — Look up open ports, CVEs, and geolocation during incident response
- **Tool Building** — Demonstrates initiative to automate manual lookup tasks

---

## 👤 Author

**Navaneeth Krishna C**  
MCA Graduate | Aspiring SOC Analyst  
📧 navaneeth364@gmail.com  
🔗 [linkedin.com/in/navaneethkrishnac](https://linkedin.com/in/navaneethkrishnac)

---

## 📄 License

This project is open source and available under the [MIT License](LICENSE).
