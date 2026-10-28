import streamlit as st
import boto3
import json
import hashlib
import os
import datetime

st.set_page_config(page_title="Forensic Investigator UI", layout="wide")

s3 = boto3.client(
    's3',
    endpoint_url=os.getenv('MINIO_ENDPOINT'),
    aws_access_key_id=os.getenv('MINIO_ACCESS_KEY'),
    aws_secret_access_key=os.getenv('MINIO_SECRET_KEY')
)

tab1, tab2 = st.tabs(["🔒 Cold Path (Forensic Timeline)", "🔥 Hot Path (Real-Time Alerts)"])

with tab1:
    st.header("Forensic Timeline & Integrity Verification")
    search_id = st.text_input("Enter Trace ID or Actor ID to reconstruct timeline:")

    if "timeline_data" not in st.session_state:
        st.session_state.timeline_data = []
        
    if "last_search" not in st.session_state:
        st.session_state.last_search = ""

    if st.button("Reconstruct Timeline") and search_id:
        st.session_state.timeline_data = []
        st.session_state.last_search = search_id
        objects = s3.list_objects_v2(Bucket='evidence-vault').get('Contents', [])
        
        for obj in objects:
            if not obj['Key'].startswith('evidence-'):
                continue
                
            response = s3.get_object(Bucket='evidence-vault', Key=obj['Key'])
            record = json.loads(response['Body'].read().decode('utf-8'))
            
            # Timeline filter
            if search_id in str(record.get('event', '')):
                canonical_event = json.dumps(record['event'], sort_keys=True)
                recomputed_hash = hashlib.sha256((canonical_event + record['previous_hash']).encode()).hexdigest()
                is_valid = recomputed_hash == record['hash']
                
                st.session_state.timeline_data.append({
                    "record": record,
                    "is_valid": is_valid,
                    "recomputed_hash": recomputed_hash
                })
                
    # Render the timeline from session state
    for item in st.session_state.timeline_data:
        record = item["record"]
        is_valid = item["is_valid"]
        with st.expander(f"Event: {record['event'].get('action', 'UNKNOWN')} at {record['event'].get('timestamp', 'UNKNOWN')}"):
            if is_valid:
                st.success(f"Verified: {item['recomputed_hash']}")
            else:
                st.error(f"Tampered! Expected: {record['hash']}, Computed: {item['recomputed_hash']}")
            st.json(record['event'])

    if st.session_state.timeline_data:
        st.markdown("---")
        st.subheader("Court-Admissible Export")
        st.write("Generate a cryptographically verified JSON export of this timeline for legal proceedings.")
        
        export_payload = json.dumps([item["record"] for item in st.session_state.timeline_data], indent=2)
        
        def log_audit():
            audit_log = {
                "action": "EVIDENCE_EXPORTED",
                "investigator_id": "investigator-01",
                "search_query": st.session_state.last_search,
                "records_exported": len(st.session_state.timeline_data),
                "timestamp": datetime.datetime.utcnow().isoformat() + "Z"
            }
            s3.put_object(
                Bucket='evidence-vault', 
                Key=f"audit-{int(datetime.datetime.now().timestamp())}.json", 
                Body=json.dumps(audit_log),
                ObjectLockMode='COMPLIANCE',
                ObjectLockRetainUntilDate='2030-01-01T00:00:00Z'
            )
            
        st.download_button(
            label="Download Evidence Bundle (JSON)",
            data=export_payload,
            file_name=f"forensic_export_{st.session_state.last_search}.json",
            mime="application/json",
            on_click=log_audit
        )

with tab2:
    st.header("Wazuh SIEM Security Alerts")
    st.write("Displaying the latest security events from the Hot Path.")
    
    alert_file = '/var/ossec/logs/alerts/alerts.json'
    
    if st.button("Refresh Alerts"):
        pass # Streamlit natively re-runs the script on button click
        
    if os.path.exists(alert_file):
        try:
            # Read the last 20 lines (alerts) from the JSON file
            with open(alert_file, 'r') as f:
                lines = f.readlines()
                latest_alerts = lines[-20:]
                
            for line in reversed(latest_alerts):
                if line.strip():
                    alert = json.loads(line)
                    rule_desc = alert.get('rule', {}).get('description', 'Unknown Alert')
                    level = alert.get('rule', {}).get('level', 0)
                    
                    # Highlight high severity alerts
                    if level >= 7:
                        st.error(f"🚨 Level {level}: {rule_desc}")
                    elif level >= 3:
                        st.warning(f"⚠️ Level {level}: {rule_desc}")
                    else:
                        st.info(f"ℹ️ Level {level}: {rule_desc}")
                        
                    with st.expander("View Raw Alert Data"):
                        st.json(alert)
        except Exception as e:
            st.error(f"Error reading alerts: {e}")
    else:
        st.warning("No alerts generated yet or waiting for Wazuh volume to mount.")
