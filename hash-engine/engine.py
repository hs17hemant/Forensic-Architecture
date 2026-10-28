from fastapi import FastAPI, Request
import hashlib
import json
import boto3
import os

app = FastAPI()
s3 = boto3.client(
    's3',
    endpoint_url=os.getenv('MINIO_ENDPOINT'),
    aws_access_key_id=os.getenv('MINIO_ACCESS_KEY'),
    aws_secret_access_key=os.getenv('MINIO_SECRET_KEY')
)

previous_hash = "0000000000000000000000000000000000000000000000000000000000000000"

# Ensure WORM bucket exists
try:
    s3.create_bucket(Bucket='evidence-vault', ObjectLockEnabledForBucket=True)
except Exception:
    pass

@app.post("/preserve")
async def preserve_event(request: Request):
    global previous_hash
    payload = await request.json()
    
    # Extract ALL events from OTLP JSON trace batch
    event_strs = []
    try:
        for rs in payload.get('resourceSpans', []):
            for ss in rs.get('scopeSpans', []):
                for span in ss.get('spans', []):
                    for attr in span.get('attributes', []):
                        if attr.get('key') == 'event_payload':
                            val = attr.get('value', {}).get('stringValue')
                            if val:
                                event_strs.append(val)
    except Exception:
        pass

    if not event_strs:
        return {"status": "ignored", "detail": "No event_payload found in trace"}
        
    preserved_hashes = []
    
    import ast
    for event_str in event_strs:
        try:
            event_dict = ast.literal_eval(event_str)
        except:
            event_dict = {"raw": event_str}
            
        # 1. Deterministic ordering
        canonical_event = json.dumps(event_dict, sort_keys=True)
        
        # 2. SHA-256 Hash Chaining
        chained_input = canonical_event + previous_hash
        current_hash = hashlib.sha256(chained_input.encode('utf-8')).hexdigest()
        
        preservation_record = {
            "event": event_dict,
            "previous_hash": previous_hash,
            "hash": current_hash
        }
        
        # 3. WORM Storage Write
        object_key = f"evidence-{current_hash[:8]}.json"
        s3.put_object(
            Bucket='evidence-vault',
            Key=object_key,
            Body=json.dumps(preservation_record),
            ObjectLockMode='COMPLIANCE',
            ObjectLockRetainUntilDate='2030-01-01T00:00:00Z'
        )
        
        # 4. Proxy to SIEM Hot Path (Bypass OTel limitation for demo)
        try:
            wazuh_alert = {
                "rule": {
                    "level": 8,
                    "description": f"Forensic Alert: {event_dict.get('action', 'Unknown')} {event_dict.get('outcome', 'Unknown')} from {event_dict.get('actor_id', 'Unknown')}"
                },
                "full_log": canonical_event
            }
            with open("/var/ossec/logs/alerts/alerts.json", "a") as f:
                f.write(json.dumps(wazuh_alert) + "\n")
        except Exception as e:
            print(f"Error writing to hot path: {e}")
            
        previous_hash = current_hash
        preserved_hashes.append(current_hash)
        
    return {"status": "preserved", "hashes": preserved_hashes}
