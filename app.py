import streamlit as st
import requests
import shodan
import os
from dotenv import load_dotenv

load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY")
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")

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
        stats = data["data"]["attributes"]["last_analysis_stats"]
        return stats
    except:
        return None

# ─────────────────────────────────────────
# Shodan Function
# ─────────────────────────────────────────

def shodan_lookup(ip):
    try:
        api = shodan.Shodan(SHODAN_API_KEY)
        result = api.host(ip)
        return result
    except shodan.APIError as e:
        return {"error": str(e)}

# ─────────────────────────────────────────
# Geolocation Function (free, no key needed)
# ─────────────────────────────────────────

def get_geolocation(ip):
    try:
        r = requests.get(f"https://ipapi.co/{ip}/json/")
        return r.json()
    except:
        return {}

# ─────────────────────────────────────────
# Streamlit UI
# ─────────────────────────────────────────

st.set_page_config(
    page_title="Threat Intelligence Dashboard",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ Threat Intelligence Dashboard")
st.markdown("Analyze IPs, Domains, and File Hashes using VirusTotal + Shodan")
st.divider()

# Input Section
col1, col2 = st.columns([2, 1])

with col1:
    query = st.text_input("🔍 Enter IP Address, Domain, or File Hash", 
                           placeholder="e.g. 8.8.8.8 or google.com or <md5/sha256>")

with col2:
    query_type = st.selectbox("Query Type", ["IP Address", "Domain", "File Hash"])

analyze_btn = st.button("🔎 Analyze", use_container_width=True)

# ─────────────────────────────────────────
# Results
# ─────────────────────────────────────────

if analyze_btn and query:

    st.divider()

    # ── VirusTotal Results ──
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
            total = sum(stats.values())
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            clean = stats.get("undetected", 0)

            # Verdict banner
            if malicious > 5:
                st.error(f"🔴 MALICIOUS — Flagged by {malicious} / {total} engines")
            elif malicious > 0 or suspicious > 0:
                st.warning(f"🟡 SUSPICIOUS — Flagged by {malicious + suspicious} / {total} engines")
            else:
                st.success(f"🟢 CLEAN — 0 / {total} engines flagged this")

            # Stats columns
            c1, c2, c3, c4 = st.columns(4)
            c1.metric("🔴 Malicious", malicious)
            c2.metric("🟡 Suspicious", suspicious)
            c3.metric("🟢 Clean", clean)
            c4.metric("📊 Total Engines", total)

            # Extra info for IP
            if query_type == "IP Address":
                try:
                    attrs = vt_data["data"]["attributes"]
                    st.markdown(f"**Owner:** {attrs.get('as_owner', 'N/A')}")
                    st.markdown(f"**Country:** {attrs.get('country', 'N/A')}")
                    st.markdown(f"**Reputation Score:** {attrs.get('reputation', 'N/A')}")
                except:
                    pass

            # Extra info for Domain
            if query_type == "Domain":
                try:
                    attrs = vt_data["data"]["attributes"]
                    st.markdown(f"**Registrar:** {attrs.get('registrar', 'N/A')}")
                    cats = attrs.get("categories", {})
                    if cats:
                        st.markdown(f"**Categories:** {', '.join(cats.values())}")
                except:
                    pass

            # Extra info for Hash
            if query_type == "File Hash":
                try:
                    attrs = vt_data["data"]["attributes"]
                    st.markdown(f"**File Name:** {attrs.get('meaningful_name', 'N/A')}")
                    st.markdown(f"**File Type:** {attrs.get('type_description', 'N/A')}")
                    st.markdown(f"**File Size:** {attrs.get('size', 'N/A')} bytes")
                    tags = attrs.get("tags", [])
                    if tags:
                        st.markdown(f"**Tags:** {', '.join(tags)}")
                except:
                    pass

        else:
            st.error("❌ Could not retrieve VirusTotal data. Check your API key or input.")

    st.divider()

    # ── Shodan Results (IP only) ──
    if query_type == "IP Address":
        st.subheader("🔭 Shodan Intelligence")

        with st.spinner("Querying Shodan..."):
            shodan_data = shodan_lookup(query)

            if "error" in shodan_data:
                st.warning(f"Shodan: {shodan_data['error']}")
            else:
                s1, s2, s3 = st.columns(3)
                s1.metric("🌍 Country", shodan_data.get("country_name", "N/A"))
                s2.metric("🏢 Org", shodan_data.get("org", "N/A"))
                s3.metric("🖥️ OS", shodan_data.get("os", "Unknown"))

                # Open ports
                ports = shodan_data.get("ports", [])
                if ports:
                    st.markdown(f"**🔓 Open Ports:** `{', '.join(map(str, ports))}`")

                # Hostnames
                hostnames = shodan_data.get("hostnames", [])
                if hostnames:
                    st.markdown(f"**🌐 Hostnames:** {', '.join(hostnames)}")

                # Vulnerabilities
                vulns = shodan_data.get("vulns", [])
                if vulns:
                    st.error(f"⚠️ Known CVEs Found: {', '.join(list(vulns)[:5])}")
                else:
                    st.success("✅ No known CVEs found")

                # Services
                st.markdown("**📡 Detected Services:**")
                for item in shodan_data.get("data", [])[:5]:
                    port = item.get("port")
                    transport = item.get("transport", "tcp")
                    product = item.get("product", "Unknown service")
                    st.code(f"Port {port}/{transport} — {product}")

        st.divider()

    # ── Geolocation (IP only) ──
    if query_type == "IP Address":
        st.subheader("🌍 Geolocation")

        with st.spinner("Fetching geolocation..."):
            geo = get_geolocation(query)

            if geo and "error" not in geo:
                g1, g2, g3, g4 = st.columns(4)
                g1.metric("Country", geo.get("country_name", "N/A"))
                g2.metric("City", geo.get("city", "N/A"))
                g3.metric("Region", geo.get("region", "N/A"))
                g4.metric("ISP", geo.get("org", "N/A"))

                lat = geo.get("latitude")
                lon = geo.get("longitude")
                if lat and lon:
                    st.map(data={"lat": [lat], "lon": [lon]}, zoom=4)
            else:
                st.warning("Could not fetch geolocation data.")

elif analyze_btn and not query:
    st.warning("⚠️ Please enter an IP address, domain, or file hash to analyze.")

# Footer
st.divider()
st.caption("Built with VirusTotal API + Shodan API + Streamlit | SOC Portfolio Project by Navaneeth Krishna C")