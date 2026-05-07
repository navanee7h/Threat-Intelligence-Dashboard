import streamlit as st
import requests
import shodan
import boto3
import os
import json
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

VT_API_KEY     = os.getenv("VT_API_KEY")
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")
AWS_REGION     = os.getenv("AWS_REGION")
os.environ["AWS_ACCESS_KEY_ID"]     = os.getenv("AWS_ACCESS_KEY_ID")
os.environ["AWS_SECRET_ACCESS_KEY"] = os.getenv("AWS_SECRET_ACCESS_KEY")

# ─────────────────────────────────────────
# VirusTotal Functions
# ─────────────────────────────────────────

def vt_check_ip(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VT_API_KEY}
    r = requests.get(url, headers=headers)
    return r.json()

def vt_check_domain(domain):
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": VT_API_KEY}
    r = requests.get(url, headers=headers)
    return r.json()

def vt_check_hash(file_hash):
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": VT_API_KEY}
    r = requests.get(url, headers=headers)
    return r.json()

def parse_vt_stats(data):
    try:
        return data["data"]["attributes"]["last_analysis_stats"]
    except:
        return None

# ─────────────────────────────────────────
# Shodan Function
# ─────────────────────────────────────────

def shodan_lookup(ip):
    try:
        # InternetDB - completely free, no API key needed
        r = requests.get(
            f"https://internetdb.shodan.io/{ip}",
            timeout=10
        )
        if r.status_code == 200:
            return r.json()
        elif r.status_code == 404:
            return {"error": "No data found for this IP"}
        else:
            return {"error": f"HTTP {r.status_code}"}
    except Exception as e:
        return {"error": str(e)}

# ─────────────────────────────────────────
# Geolocation
# ─────────────────────────────────────────

def get_geolocation(ip):
    try:
        # Try ipapi.co first
        r = requests.get(
            f"https://ipapi.co/{ip}/json/",
            timeout=10
        )
        if r.status_code == 200:
            data = r.json()
            if "error" not in data:
                return data

        # Fallback to ip-api.com (free, no key)
        r2 = requests.get(
            f"http://ip-api.com/json/{ip}",
            timeout=10
        )
        if r2.status_code == 200:
            data2 = r2.json()
            # Normalize field names to match our display
            return {
                "country_name" : data2.get("country"),
                "city"         : data2.get("city"),
                "region"       : data2.get("regionName"),
                "org"          : data2.get("isp"),
                "timezone"     : data2.get("timezone"),
                "postal"       : data2.get("zip"),
                "latitude"     : data2.get("lat"),
                "longitude"    : data2.get("lon"),
            }
    except Exception as e:
        return {}

# ─────────────────────────────────────────
# AWS GuardDuty Functions
# ─────────────────────────────────────────

def get_guardduty_findings(max_findings=20):
    try:
        gd = boto3.client("guardduty", region_name=AWS_REGION)

        # Get detector ID
        detectors = gd.list_detectors()
        if not detectors["DetectorIds"]:
            return None, "No GuardDuty detector found. Please enable GuardDuty in AWS Console."

        detector_id = detectors["DetectorIds"][0]

        # Get finding IDs sorted by severity
        response = gd.list_findings(
            DetectorId=detector_id,
            FindingCriteria={
                "Criterion": {
                    "severity": {
                        "Gte": 1
                    }
                }
            },
            SortCriteria={
                "AttributeName": "severity",
                "OrderBy": "DESC"
            },
            MaxResults=max_findings
        )

        finding_ids = response.get("FindingIds", [])
        if not finding_ids:
            return [], None

        # Get full details
        details = gd.get_findings(
            DetectorId=detector_id,
            FindingIds=finding_ids
        )

        return details["Findings"], None

    except Exception as e:
        return None, str(e)

def get_severity_label(severity):
    if severity >= 7:
        return "HIGH", "🔴"
    elif severity >= 4:
        return "MEDIUM", "🟡"
    else:
        return "LOW", "🔵"

def get_verdict(severity):
    if severity >= 7:
        return "TRUE POSITIVE — Escalate to L2", "error"
    elif severity >= 4:
        return "LIKELY TRUE POSITIVE — Investigate Further", "warning"
    else:
        return "FALSE POSITIVE — Monitor Only", "success"

def extract_ip_from_finding(finding):
    try:
        return finding["Service"]["Action"]["NetworkConnectionAction"]\
               ["RemoteIpDetails"]["IpAddressV4"]
    except:
        try:
            return finding["Service"]["Action"]["AwsApiCallAction"]\
                   ["RemoteIpDetails"]["IpAddressV4"]
        except:
            return None

# ─────────────────────────────────────────
# AWS CloudTrail Functions
# ─────────────────────────────────────────

def get_cloudtrail_events(max_events=15):
    try:
        ct = boto3.client("cloudtrail", region_name=AWS_REGION)

        response = ct.lookup_events(
            MaxResults=max_events
        )

        return response.get("Events", []), None

    except Exception as e:
        return None, str(e)

def is_suspicious_event(event_name):
    suspicious = [
        "StopLogging", "DeleteTrail", "UpdateTrail",
        "CreateUser", "DeleteUser", "AttachUserPolicy",
        "CreateAccessKey", "DeleteAccessKey",
        "PutBucketPolicy", "DeleteBucketPolicy",
        "AuthorizeSecurityGroupIngress",
        "ConsoleLoginFailure", "PasswordPolicyUpdated"
    ]
    return event_name in suspicious

# ─────────────────────────────────────────
# Streamlit UI
# ─────────────────────────────────────────

st.set_page_config(
    page_title="SOC Threat Intelligence Dashboard",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ SOC Threat Intelligence Dashboard")
st.markdown("*Real-time threat analysis powered by VirusTotal, Shodan & AWS Security Services*")
st.divider()

# Navigation Tabs
tab1, tab2, tab3 = st.tabs([
    "🔍 IOC Analyzer",
    "☁️ AWS GuardDuty",
    "📋 CloudTrail Monitor"
])

# ══════════════════════════════════════════
# TAB 1: IOC ANALYZER
# ══════════════════════════════════════════

with tab1:
    st.subheader("🔍 IOC Analyzer — IP / Domain / File Hash")
    st.caption("Investigate suspicious indicators using VirusTotal, Shodan InternetDB & Geolocation")

    col1, col2 = st.columns([2, 1])
    with col1:
        query = st.text_input(
            "Enter IP Address, Domain, or File Hash",
            placeholder="e.g. 8.8.8.8 or google.com or <md5/sha256>"
        )
    with col2:
        query_type = st.selectbox(
            "Query Type",
            ["IP Address", "Domain", "File Hash"]
        )

    analyze_btn = st.button("🔎 Analyze IOC", use_container_width=True)

    if analyze_btn and query:
        st.divider()

        # ── VirusTotal ──
        st.subheader("🦠 VirusTotal Analysis")
        with st.spinner("Querying VirusTotal..."):

            if query_type == "IP Address":
                vt_data = vt_check_ip(query)
            elif query_type == "Domain":
                vt_data = vt_check_domain(query)
            else:
                vt_data = vt_check_hash(query)

            stats = parse_vt_stats(vt_data)

            if stats:
                total      = sum(stats.values())
                malicious  = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                clean      = stats.get("undetected", 0)

                # Verdict banner
                if malicious > 5:
                    st.error(
                        f"🔴 MALICIOUS — "
                        f"Flagged by {malicious}/{total} engines"
                    )
                elif malicious > 0 or suspicious > 0:
                    st.warning(
                        f"🟡 SUSPICIOUS — "
                        f"Flagged by {malicious + suspicious}/{total} engines"
                    )
                else:
                    st.success(
                        f"🟢 CLEAN — "
                        f"0/{total} engines flagged this"
                    )

                # Metrics
                c1, c2, c3, c4 = st.columns(4)
                c1.metric("🔴 Malicious",     malicious)
                c2.metric("🟡 Suspicious",    suspicious)
                c3.metric("🟢 Clean",         clean)
                c4.metric("📊 Total Engines", total)

                # IP specific info
                if query_type == "IP Address":
                    try:
                        attrs = vt_data["data"]["attributes"]
                        st.markdown(
                            f"**Owner:** "
                            f"{attrs.get('as_owner', 'N/A')}"
                        )
                        st.markdown(
                            f"**Country:** "
                            f"{attrs.get('country', 'N/A')}"
                        )
                        st.markdown(
                            f"**Reputation Score:** "
                            f"{attrs.get('reputation', 'N/A')}"
                        )
                    except:
                        pass

                # Domain specific info
                if query_type == "Domain":
                    try:
                        attrs = vt_data["data"]["attributes"]
                        st.markdown(
                            f"**Registrar:** "
                            f"{attrs.get('registrar', 'N/A')}"
                        )
                        cats = attrs.get("categories", {})
                        if cats:
                            st.markdown(
                                f"**Categories:** "
                                f"{', '.join(cats.values())}"
                            )
                        # Last analysis date
                        last_analysis = attrs.get(
                            "last_analysis_date", None
                        )
                        if last_analysis:
                            from datetime import datetime
                            dt = datetime.utcfromtimestamp(
                                last_analysis
                            ).strftime('%Y-%m-%d %H:%M UTC')
                            st.markdown(f"**Last Analyzed:** {dt}")
                    except:
                        pass

                # Hash specific info
                if query_type == "File Hash":
                    try:
                        attrs = vt_data["data"]["attributes"]
                        st.markdown(
                            f"**File Name:** "
                            f"{attrs.get('meaningful_name', 'N/A')}"
                        )
                        st.markdown(
                            f"**File Type:** "
                            f"{attrs.get('type_description', 'N/A')}"
                        )
                        st.markdown(
                            f"**File Size:** "
                            f"{attrs.get('size', 'N/A')} bytes"
                        )
                        tags = attrs.get("tags", [])
                        if tags:
                            st.markdown(
                                f"**Tags:** "
                                f"{', '.join(tags)}"
                            )
                        # Threat label
                        threat = attrs.get(
                            "popular_threat_classification", {}
                        )
                        if threat:
                            label = threat.get(
                                "suggested_threat_label", "N/A"
                            )
                            st.error(f"☠️ Threat Label: {label}")
                    except:
                        pass

            else:
                st.error(
                    "❌ Could not retrieve VirusTotal data. "
                    "Check your API key or input."
                )

        st.divider()

        # ── Shodan InternetDB (IP only) ──
        if query_type == "IP Address":
            st.subheader("🔭 Shodan Intelligence")
            with st.spinner("Querying Shodan InternetDB..."):
                shodan_data = shodan_lookup(query)

                if "error" in shodan_data:
                    st.warning(f"Shodan: {shodan_data['error']}")
                else:
                    # Open ports
                    ports = shodan_data.get("ports", [])
                    if ports:
                        st.markdown(
                            f"**🔓 Open Ports:** "
                            f"`{', '.join(map(str, ports))}`"
                        )
                    else:
                        st.info("No open ports found")

                    # Hostnames
                    hostnames = shodan_data.get("hostnames", [])
                    if hostnames:
                        st.markdown(
                            f"**🌐 Hostnames:** "
                            f"{', '.join(hostnames)}"
                        )

                    # Tags
                    tags = shodan_data.get("tags", [])
                    if tags:
                        st.markdown(
                            f"**🏷️ Tags:** "
                            f"`{', '.join(tags)}`"
                        )

                    # Vulnerabilities
                    vulns = shodan_data.get("vulns", [])
                    if vulns:
                        st.error(
                            f"⚠️ Known CVEs: "
                            f"{', '.join(vulns[:5])}"
                        )
                    else:
                        st.success("✅ No known CVEs found")

                    # Services / CPEs
                    cpes = shodan_data.get("cpes", [])
                    if cpes:
                        st.markdown("**📡 Detected Services:**")
                        for cpe in cpes[:5]:
                            st.code(cpe)

            st.divider()

            # ── Geolocation (IP only) ──
            st.subheader("🌍 Geolocation")
            with st.spinner("Fetching geolocation..."):
                geo = get_geolocation(query)

                if geo and "error" not in geo:
                    g1, g2, g3, g4 = st.columns(4)
                    g1.metric("Country", geo.get("country_name", "N/A"))
                    g2.metric("City",    geo.get("city",         "N/A"))
                    g3.metric("Region",  geo.get("region",       "N/A"))
                    g4.metric("ISP",     geo.get("org",          "N/A"))

                    # Extra details
                    col1, col2 = st.columns(2)
                    with col1:
                        st.markdown(
                            f"**Timezone:** "
                            f"{geo.get('timezone', 'N/A')}"
                        )
                        st.markdown(
                            f"**Postal Code:** "
                            f"{geo.get('postal', 'N/A')}"
                        )
                    with col2:
                        st.markdown(
                            f"**Currency:** "
                            f"{geo.get('currency_name', 'N/A')}"
                        )
                        st.markdown(
                            f"**Calling Code:** "
                            f"+{geo.get('country_calling_code', 'N/A')}"
                        )

                    # Map
                    lat = geo.get("latitude")
                    lon = geo.get("longitude")
                    if lat and lon:
                        st.map(
                            data={"lat": [lat], "lon": [lon]},
                            zoom=4
                        )
                else:
                    st.warning("Could not fetch geolocation data.")

    elif analyze_btn and not query:
        st.warning("⚠️ Please enter an IOC to analyze.")
# ══════════════════════════════════════════
# TAB 2: AWS GUARDDUTY
# ══════════════════════════════════════════

with tab2:
    st.subheader("☁️ AWS GuardDuty — Live Threat Findings")
    st.caption("Pulls real-time threat findings from your AWS environment")

    # Initialize session state
    if "gd_findings" not in st.session_state:
        st.session_state.gd_findings = None
    if "gd_error" not in st.session_state:
        st.session_state.gd_error = None

    col1, col2 = st.columns([1, 1])
    with col1:
        max_findings = st.slider("Max findings to load", 5, 40, 20)
    with col2:
        severity_filter = st.selectbox(
            "Filter by Severity",
            ["All", "High Only (7+)", "Medium+ (4+)"]
        )

    load_btn = st.button("🔄 Load GuardDuty Findings", use_container_width=True)

    # Load findings and store in session state
    if load_btn:
        with st.spinner("Connecting to AWS GuardDuty..."):
            findings, error = get_guardduty_findings(max_findings)
            st.session_state.gd_findings = findings
            st.session_state.gd_error    = error

    # Display findings from session state (persists across reruns)
    if st.session_state.gd_error:
        st.error(f"❌ AWS Error: {st.session_state.gd_error}")
        st.info("Make sure your AWS credentials are configured correctly in .env")

    elif st.session_state.gd_findings is not None:
        findings = st.session_state.gd_findings

        if not findings:
            st.info("✅ No findings found. Your AWS environment looks clean!")
        else:
            # Apply filter
            if severity_filter == "High Only (7+)":
                findings = [f for f in findings if f["Severity"] >= 7]
            elif severity_filter == "Medium+ (4+)":
                findings = [f for f in findings if f["Severity"] >= 4]

            # Summary metrics
            high   = sum(1 for f in findings if f["Severity"] >= 7)
            medium = sum(1 for f in findings if 4 <= f["Severity"] < 7)
            low    = sum(1 for f in findings if f["Severity"] < 4)

            m1, m2, m3, m4 = st.columns(4)
            m1.metric("📊 Total Findings", len(findings))
            m2.metric("🔴 High Severity",  high)
            m3.metric("🟡 Medium Severity", medium)
            m4.metric("🔵 Low Severity",   low)

            st.divider()

            # Display each finding
            for i, finding in enumerate(findings):
                severity              = finding["Severity"]
                sev_label, sev_icon   = get_severity_label(severity)
                verdict, verdict_type = get_verdict(severity)
                suspicious_ip         = extract_ip_from_finding(finding)

                # Session state keys for this finding
                vt_key  = f"vt_result_{i}"
                btn_key = f"vt_btn_{i}"

                if vt_key not in st.session_state:
                    st.session_state[vt_key] = None

                with st.expander(
                    f"{sev_icon} [{sev_label}] {finding['Title']} "
                    f"| Severity: {severity}",
                    expanded=(severity >= 7)
                ):
                    col1, col2 = st.columns(2)
                    with col1:
                        st.markdown(f"**📌 Finding Type:** `{finding['Type']}`")
                        st.markdown(f"**🖥️ Resource:** {finding['Resource']['ResourceType']}")
                        st.markdown(f"**🕐 Detected:** {finding.get('CreatedAt','N/A')}")
                        st.markdown(f"**🔁 Count:** {finding['Service'].get('Count',1)} occurrence(s)")
                    with col2:
                        st.markdown("**📝 Description:**")
                        st.info(finding.get("Description","N/A"))

                    # Verdict banner
                    if verdict_type == "error":
                        st.error(f"🚨 SOC Verdict: {verdict}")
                    elif verdict_type == "warning":
                        st.warning(f"⚠️ SOC Verdict: {verdict}")
                    else:
                        st.success(f"✅ SOC Verdict: {verdict}")

                    # VirusTotal IP check
                    if suspicious_ip:
                        st.markdown(f"**🌐 Suspicious IP Detected:** `{suspicious_ip}`")

                        if st.button(
                            f"🔍 Check IP on VirusTotal",
                            key=btn_key
                        ):
                            with st.spinner(f"Checking {suspicious_ip}..."):
                                vt_result = vt_check_ip(suspicious_ip)
                                st.session_state[vt_key] = parse_vt_stats(vt_result)

                        # Show VT result if fetched — persists across reruns
                        if st.session_state[vt_key] is not None:
                            vt_stats = st.session_state[vt_key]
                            mal = vt_stats.get("malicious", 0)
                            sus = vt_stats.get("suspicious", 0)
                            tot = sum(vt_stats.values())

                            st.divider()
                            st.markdown("**🦠 VirusTotal Result:**")

                            if mal > 5:
                                st.error(
                                    f"🔴 CONFIRMED MALICIOUS — "
                                    f"Flagged by {mal}/{tot} engines"
                                )
                            elif mal > 0 or sus > 0:
                                st.warning(
                                    f"🟡 SUSPICIOUS — "
                                    f"Flagged by {mal+sus}/{tot} engines"
                                )
                            else:
                                st.success(
                                    f"🟢 CLEAN — "
                                    f"0/{tot} engines flagged this IP"
                                )

                    # Recommended actions
                    st.markdown("**🛡️ Recommended Actions:**")
                    if severity >= 7:
                        st.markdown("""
                        - 🔴 Immediately escalate to L2 analyst
                        - 🔒 Isolate affected resource if possible
                        - 📋 Open high-priority Jira ticket
                        - 🔍 Preserve CloudTrail logs for forensics
                        """)
                    elif severity >= 4:
                        st.markdown("""
                        - 🟡 Investigate within 4 hours
                        - 📋 Open medium-priority Jira ticket
                        - 🔍 Cross-reference with CloudTrail logs
                        """)
                    else:
                        st.markdown("""
                        - 🔵 Log and monitor — no immediate action
                        - 📋 Document as informational finding
                        """)
# ══════════════════════════════════════════
# TAB 3: CLOUDTRAIL MONITOR
# ══════════════════════════════════════════

with tab3:
    st.subheader("📋 CloudTrail — API Activity Monitor")
    st.caption("Monitors AWS API calls and flags suspicious activity")

    max_events = st.slider("Events to load", 10, 50, 15)
    ct_btn = st.button("🔄 Load CloudTrail Events", use_container_width=True)

    if ct_btn:
        with st.spinner("Fetching CloudTrail events..."):
            events, error = get_cloudtrail_events(max_events)

        if error:
            st.error(f"❌ CloudTrail Error: {error}")

        elif not events:
            st.info("No recent CloudTrail events found.")

        else:
            # Count suspicious events
            suspicious_count = sum(
                1 for e in events
                if is_suspicious_event(e.get("EventName",""))
            )

            c1, c2, c3 = st.columns(3)
            c1.metric("📊 Total Events", len(events))
            c2.metric("⚠️ Suspicious Events", suspicious_count)
            c3.metric("✅ Normal Events", len(events) - suspicious_count)

            if suspicious_count > 0:
                st.error(
                    f"🚨 {suspicious_count} suspicious API calls detected! "
                    f"Review immediately."
                )

            st.divider()

            # Display events
            for event in events:
                event_name = event.get("EventName", "Unknown")
                username   = event.get("Username", "Unknown")
                event_time = event.get("EventTime", "N/A")
                suspicious = is_suspicious_event(event_name)

                if suspicious:
                    with st.expander(
                        f"⚠️ SUSPICIOUS: {event_name} by {username}",
                        expanded=True
                    ):
                        col1, col2 = st.columns(2)
                        with col1:
                            st.markdown(f"**Event:** `{event_name}`")
                            st.markdown(f"**User:** `{username}`")
                            st.markdown(f"**Time:** {event_time}")
                        with col2:
                            st.error("🚨 This event is flagged as suspicious")
                            st.markdown("**Why flagged:** This API call is commonly "
                                       "associated with privilege escalation, "
                                       "defense evasion, or unauthorized access")
                        st.markdown("**Recommended Action:** Cross-check with "
                                   "GuardDuty findings and escalate if unauthorized")
                else:
                    st.markdown(
                        f"✅ `{event_name}` — by **{username}** "
                        f"at {event_time}"
                    )

# Footer
st.divider()
st.caption(
    "🛡️ SOC Threat Intelligence Dashboard | "
    "VirusTotal + Shodan + AWS GuardDuty + CloudTrail | "
    "Built by Navaneeth Krishna C"
)
