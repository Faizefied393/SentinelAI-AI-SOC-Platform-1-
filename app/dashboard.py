import json
import os
import requests
import streamlit as st

API = os.getenv("SENTINEL_API", "http://127.0.0.1:8000").rstrip("/")
st.set_page_config(page_title="SentinelAI Enterprise", layout="wide")
st.title("SentinelAI Enterprise")
st.caption("Local AI SOC investigation and security validation lab — analyst review required")
page = st.sidebar.radio("Workflows", ["Overview", "Import Logs", "Investigate", "CVE Intelligence"])

def get(path):
    r = requests.get(API + path, timeout=20)
    r.raise_for_status()
    return r.json()

def post(path, payload=None):
    r = requests.post(API + path, json=payload, timeout=190)
    r.raise_for_status()
    return r.json()

try:
    if page == "Overview":
        alerts = get("/alerts")
        events = get("/events")
        a, b = st.columns(2)
        a.metric("Stored events (latest 200)", len(events))
        b.metric("Alerts (latest 100)", len(alerts))
        st.dataframe(alerts, use_container_width=True)
    elif page == "Import Logs":
        st.write("Upload JSON formatted as {\"events\": [ ... ]}. Maximum 500 events and 1 MB.")
        uploaded = st.file_uploader("Choose JSON file", type=["json"])
        if uploaded and st.button("Import and detect"):
            if uploaded.size > 1_000_000:
                st.error("File exceeds 1 MB")
            else:
                payload = json.loads(uploaded.getvalue())
                st.json(post("/events/import", payload))
    elif page == "Investigate":
        alerts = get("/alerts")
        st.dataframe(alerts, use_container_width=True)
        alert_id = st.number_input("Alert ID", min_value=1, step=1)
        if st.button("Investigate with local AI"):
            with st.spinner("Investigating..."):
                st.json(post(f"/alerts/{int(alert_id)}/investigate"))
    else:
        cve = st.text_input("CVE ID", "CVE-2021-44228")
        if st.button("Look up CVE"):
            st.json(get(f"/intelligence/{cve.strip()}"))
except (requests.RequestException, ValueError) as exc:
    st.error(f"Request failed: {exc}")
