import pandas as pd
import json
import os
from sklearn.ensemble import IsolationForest
from groq import Groq
from dotenv import load_dotenv

load_dotenv()
GROQ_API_KEY = os.getenv("GROQ_API_KEY")
client = Groq(api_key=GROQ_API_KEY)

def load_stix_ips():
    try:
        # In Docker, os.getcwd() is '/app'. Our volume maps to '/app/data'
        stix_path = os.path.join(os.getcwd(), "data", "stix_intel_feed.json")
        with open(stix_path, "r") as f:
            stix_data = json.load(f)
            
        return [obj["pattern"].split("'")[1] for obj in stix_data.get("objects", []) if "pattern" in obj]
    except Exception as e:
        print(f"--- [DEBUG] Could not load STIX IPs: {e} ---")
        return []

KNOWN_BAD_IPS = load_stix_ips()

def run_detection_pipeline(parsed_logs):
    if not parsed_logs: return []
    df = pd.DataFrame(parsed_logs)
    
    # Initialize Core Columns
    df['is_anomaly'] = False
    df['confidence_score'] = 0.0
    df['anomaly_reason'] = ""
    df['category'] = "Normal" # DETERMINISTIC CATEGORY
    df['signature'] = "" # Temporary column for tracking

    # ==========================================
    # LAYER 1: Deterministic Rules
    # ==========================================
    
    # 1. Threat Intel Check
    stix_mask = df['source_ip'].isin(KNOWN_BAD_IPS)
    df.loc[stix_mask, ['is_anomaly', 'category', 'confidence_score', 'anomaly_reason']] = [True, "Threat Intel", 100.0, "STIX Intel Match: Known Malicious IP."]

    # 2. Brute Force Check (Sliding Window Algorithm)
    # Sort chronologically, index by timestamp, and sum requests over a rolling 60-second window
    df = df.sort_values('timestamp')
    rolling_counts = (
        df.assign(req_count=1)
        .set_index('timestamp')
        .groupby('source_ip')['req_count']
        .rolling('60s')
        .sum()
        .reset_index()
    )
    
    # Find IPs that crossed the 50 request threshold inside any 60-second window
    brute_ips = rolling_counts[rolling_counts['req_count'] >= 50]['source_ip'].unique()
    bf_mask = df['source_ip'].isin(brute_ips) & ~df['is_anomaly']
    df.loc[bf_mask, ['is_anomaly', 'category', 'confidence_score', 'anomaly_reason']] = [True, "Brute Force", 99.0, "Velocity Rule: Possible Brute Force Attack (50+ reqs in 60s)."]

    # 3. Sensitive Probing Check
    sensitive_endpoints = ['/admin', '/.env', '/config', '/.git']
    sensitive_mask = df['endpoint'].apply(lambda x: any(sub in str(x) for sub in sensitive_endpoints)) & (df['status_code'] >= 400) & ~df['is_anomaly']
    df.loc[sensitive_mask, ['is_anomaly', 'category', 'confidence_score', 'anomaly_reason']] = [True, "Probing", 95.0, "Rule: Unauthorized access attempt to sensitive endpoint."]

    # ==========================================
    # LAYER 2: ML Behavioral Analysis
    # ==========================================
    normal_mask = ~df['is_anomaly']
    if normal_mask.sum() > 0:
        clf = IsolationForest(contamination=0.05, random_state=42)
        features = df.loc[normal_mask, ['status_code', 'response_size']]
        preds = clf.fit_predict(features)
        raw_scores = clf.decision_function(features)
        
        df.loc[normal_mask, 'ml_prediction'] = preds
        df.loc[normal_mask, 'raw_score'] = raw_scores
        ml_mask = normal_mask & (df['ml_prediction'] == -1)
        
        df.loc[ml_mask, ['is_anomaly', 'category', 'anomaly_reason']] = [True, "ML Behavioral", "ML Model (IsolationForest): Behavioral anomaly detected in payload size."]
        df.loc[ml_mask, 'confidence_score'] = df.loc[ml_mask, 'raw_score'].apply(lambda x: round(min(99.9, 75.0 + (abs(x) * 100)), 1))
        df = df.drop(columns=['ml_prediction', 'raw_score'])

    # ==========================================
    # LAYER 3: Signature Aggregation AI Enrichment
    # ==========================================
    print("\n--- [DEBUG] DETECTION: Starting Layer 3 (AI Enrichment) ---")
    anomalies_df = df[df['is_anomaly']].copy()
    
    if not anomalies_df.empty:
        # 1. OPTIMIZED SIGNATURE: Removed source_ip to massively compress botnet/distributed attacks
        df.loc[df['is_anomaly'], 'signature'] = anomalies_df['category'] + "|" + anomalies_df['http_method'] + "|" + anomalies_df['endpoint']
        
        # Refresh the working copy with the new signature column
        anomalies_df = df[df['is_anomaly']]
        grouped = anomalies_df.groupby('signature')
        
        unique_cases = []
        sig_mapping = {}
        
        print(f"--- [DEBUG] DETECTION: Compressed {len(anomalies_df)} anomalies into {len(grouped)} unique behavioral signatures ---")
        
        # 2. Extract strictly the unique signatures
        for idx, (sig, group) in enumerate(grouped):
            count = len(group)
            sample_row = group.iloc[0]
            
            unique_cases.append({
                "id": str(idx),
                "type": sample_row['category'],
                "target": f"{sample_row['http_method']} {sample_row['endpoint']}",
                "status_code": int(sample_row['status_code']),
                "volume": f"{count} attempts",
                "rule_reason": sample_row['anomaly_reason']
            })
            sig_mapping[str(idx)] = sig

        # 3. Process unique cases in chunks
        chunk_size = 15
        all_explanations = {}
        total_chunks = (len(unique_cases) + chunk_size - 1) // chunk_size
        
        print(f"--- [DEBUG] DETECTION: Sending {total_chunks} chunk(s) to Groq API ---")

        for i in range(0, len(unique_cases), chunk_size):
            chunk_num = (i // chunk_size) + 1
            print(f"--- [DEBUG] DETECTION: Processing chunk {chunk_num}/{total_chunks} ---")
            
            chunk = unique_cases[i:i + chunk_size]
            prompt = (
                "You are a Senior SOC Analyst. Analyze this batch of unique security threat signatures. "
                "For each ID, provide a 1-sentence tactical explanation of the risk, considering the volume of attempts. "
                "Return the result strictly as a JSON object where keys are the IDs and values are the explanations. "
                f"Data: {json.dumps(chunk)}"
            )

            try:
                chat = client.chat.completions.create(
                    messages=[{"role": "user", "content": prompt}],
                    model="llama-3.1-8b-instant",
                    response_format={"type": "json_object"}
                )
                
                chunk_explanations = json.loads(chat.choices[0].message.content)
                all_explanations.update(chunk_explanations)
                
            except Exception as e:
                print(f"--- [DEBUG] DETECTION: AI Enrichment Error on chunk {chunk_num}: {e} ---")
                for item in chunk:
                    all_explanations[item['id']] = item['rule_reason'] + " (AI enrichment bypass)"

        # 4. Broadcast explanations back to ALL matching rows in the master DataFrame
        for idx_str, explanation in all_explanations.items():
            if idx_str in sig_mapping:
                sig = sig_mapping[idx_str]
                match_mask = df['signature'] == sig
                df.loc[match_mask, 'anomaly_reason'] = f"🤖 AI Analyst: {explanation}"

    print("--- [DEBUG] DETECTION: Complete! ---")

    # Clean up temporary columns before returning to main.py
    columns_to_drop = ['signature']
    for col in columns_to_drop:
        if col in df.columns:
            df = df.drop(columns=[col])

    return df.to_dict(orient='records')