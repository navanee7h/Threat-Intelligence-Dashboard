# 🛡️ SOC Threat Intelligence Dashboard

A real-time, multi-source threat intelligence platform built for SOC analyst workflows. Investigate suspicious IPs, domains, and file hashes — and monitor your AWS cloud environment for live threats — all from a single dashboard.

> Built as a portfolio project simulating L1 SOC analyst triage workflows using industry-standard security APIs and AWS cloud security services.

---

---

## ✨ Features

### 🔍 Tab 1 — IOC Analyzer
| Feature | Description |
|---|---|
| VirusTotal Analysis | Checks IP/domain/hash across 91 AV engines with MALICIOUS / SUSPICIOUS / CLEAN verdict |
| Shodan InternetDB | Pulls open ports, hostnames, running services, tags, and known CVEs — no paid key required |
| Geolocation Mapping | Shows country, city, ISP, timezone with live interactive map |
| IP Intelligence | Owner, reputation score, country from VirusTotal |
| Domain Intelligence | Registrar, categories, last analysis date |
| File Hash Intelligence | File name, type, size, threat label, AV tags |

### ☁️ Tab 2 — AWS GuardDuty
| Feature | Description |
|---|---|
| Live Findings | Pulls real-time threat findings from your AWS environment |
| Auto Triage | Classifies findings as TRUE POSITIVE / INVESTIGATE / FALSE POSITIVE based on severity |
| Severity Filter | Filter by All / High (7+) / Medium+ (4+) |
| VirusTotal Cross-Check | One-click IP reputation check on any suspicious IP found in a GuardDuty finding |
| Recommended Actions | Auto-generated SOC response steps per finding severity |
| Summary Metrics | Total / High / Medium / Low finding counts |

### 📋 Tab 3 — CloudTrail Monitor
| Feature | Description |
|---|---|
| API Activity Feed | Pulls latest AWS API calls from CloudTrail |
| Suspicious Event Detection | Flags high-risk API calls: StopLogging, CreateUser, AttachUserPolicy, CreateAccessKey, DeleteTrail etc. |
| User Attribution | Shows which IAM user performed each action |
| Analyst Guidance | Explains why each suspicious event is flagged and recommended next steps |

---

## 🛠️ Tech Stack

| Tool | Purpose |
|---|---|
| Python | Core language |
| Streamlit | Web UI framework |
| VirusTotal API v3 | Malware & reputation analysis (91 engines) |
| Shodan InternetDB | Free port scanning & CVE intelligence |
| ipapi.co + ip-api.com | IP geolocation (dual fallback, no key needed) |
| AWS GuardDuty | Cloud threat detection findings |
| AWS CloudTrail | AWS API activity audit logs |
| boto3 | AWS Python SDK |
| python-dotenv | Secure API key management |

---

## ⚙️ Installation & Setup

### 1. Clone the repository
```bash
git clone https://github.com/navanee7h/Threat-Intelligence-Dashboard.git
cd Threat-Intelligence-Dashboard
```

### 2. Install dependencies
```bash
pip install -r requirements.txt
```

### 3. Get your API keys

| Service | Link | Cost |
|---|---|---|
| VirusTotal | https://virustotal.com → Sign up → Profile → API Key | Free |
| AWS Account | https://aws.amazon.com/free | Free tier |

> ℹ️ Shodan now uses the free InternetDB API — no API key required!

### 4. AWS Setup

**Enable GuardDuty:**
```
AWS Console → GuardDuty → Get Started → Enable GuardDuty
```

**Create IAM user for API access:**
```
AWS Console → IAM → Users → Add User
Username: soc-dashboard-user
Attach policies:
  → AmazonGuardDutyReadOnlyAccess
  → AWSCloudTrail_ReadOnlyAccess
  → AmazonS3ReadOnlyAccess
→ Create User → Download credentials CSV
```

**Configure AWS credentials:**
```bash
aws configure
# Enter Access Key ID, Secret Access Key, region (ap-south-1)
```

**Generate sample GuardDuty findings for testing:**
```
GuardDuty → Settings → Generate Sample Findings → Generate
```

### 5. Create a `.env` file in the project root
```
VT_API_KEY=your_virustotal_api_key_here
AWS_REGION=ap-south-1
```
> ⚠️ Never commit your `.env` file to GitHub. It is listed in `.gitignore`.

### 6. Run the app
```bash
# Recommended on Windows
python -m streamlit run app.py

# Linux/Mac
streamlit run app.py
```

### 7. Open in browser
```
http://localhost:8501
```

---

## 🧪 Sample Test Inputs

### IOC Analyzer
| Type | Input | Expected Result |
|---|---|---|
| Malicious IP | `185.220.101.45` | 🔴 Malicious — Tor exit node |
| Suspicious IP | `45.33.32.156` | 🟡 Suspicious — scanme.nmap.org with CVEs |
| Clean IP | `8.8.8.8` | 🟢 Clean — Google DNS |
| Malicious Domain | `malware.wicar.org` | 🔴 Malicious |
| EICAR Test Hash | Search "eicar md5 hash" | 🔴 Malicious |

### GuardDuty
```
After generating sample findings:
→ Load findings → filter High Only (7+)
→ Open any finding with suspicious IP
→ Click "Check IP on VirusTotal"
→ Cross-referenced verdict appears instantly
```

### CloudTrail
```
→ Go to AWS Console → IAM → Create a test user
→ Come back to CloudTrail tab → Load Events
→ "CreateUser" appears flagged as SUSPICIOUS
```

---

## 📁 Project Structure

```
threat-intel-dashboard/
├── app.py                  # Main Streamlit application
├── .env                    # API keys (never commit this)
├── .gitignore              # Excludes .env from git
├── requirements.txt        # Python dependencies
├── README.md               # Project documentation
└── screenshots/            # Dashboard screenshots
    ├── ioc_analyzer.png
    ├── guardduty.png
    └── cloudtrail.png
```

---

## 📦 requirements.txt

```
streamlit
requests
boto3
awscli
python-dotenv
```

---

## 🔐 Security Notes

- API keys managed via `.env` — never hardcoded
- `.gitignore` ensures credentials are never pushed to GitHub
- AWS IAM user has read-only permissions — no write access
- Shodan InternetDB used instead of paid API — no sensitive key required
- All AWS operations use least-privilege access principles

---

## 🚀 How This Relates to SOC Work

This project directly simulates core L1 SOC analyst responsibilities:

| SOC Task | How Dashboard Covers It |
|---|---|
| Alert Triage | Auto-verdict (True/False Positive) based on severity |
| IOC Investigation | VirusTotal + Shodan enrichment of suspicious indicators |
| Threat Intelligence | IP reputation, CVEs, open ports, geolocation |
| Cloud Monitoring | Live GuardDuty findings with severity classification |
| Audit Log Review | CloudTrail suspicious API call detection |
| Escalation Decision | Auto-recommended actions per finding severity |
| Cross-tool Correlation | GuardDuty finding → VirusTotal IP check in one click |

---

## 🎯 Key SOC Concepts Demonstrated

- **True Positive vs False Positive** classification
- **IOC enrichment** using multiple threat intel sources
- **Alert triage** workflow from detection to action
- **Cloud security monitoring** (AWS GuardDuty + CloudTrail)
- **Privilege escalation detection** via CloudTrail API monitoring
- **Defense evasion detection** (StopLogging, DeleteTrail)
- **Threat intelligence correlation** across VirusTotal + Shodan

---

## 👤 Author

**Navaneeth Krishna C**
MCA Graduate | Aspiring SOC Analyst
📧 navaneeth364@gmail.com
🔗 [linkedin.com/in/navaneethkrishnac](https://linkedin.com/in/navaneethkrishnac)
🐙 [github.com/navanee7h](https://github.com/navanee7h)

---

## 📄 License

This project is open source and available under the [MIT License](LICENSE).
