import pandas as pd
import json
import os
from sklearn.ensemble import IsolationForest
from groq import Groq
from dotenv import load_dotenv

# Load environment variables (Groq API Key)
load_dotenv()
GROQ_API_KEY = os.getenv("GROQ_API_KEY")
client = Groq(api_key=GROQ_API_KEY)

def load_stix_ips():
    """Loads known malicious IPs from our local STIX feed."""
    try:
        with open("../data/stix_intel_feed.json", "r") as f:
            stix_data = json.load(f)
            ips = []
            for obj in stix_data.get("objects", []):
                if "pattern" in obj:
                    ip = obj["pattern"].split("'")[1]
                    ips.append(ip)
            return ips
    except Exception as e:
        print(f"Error loading STIX feed: {e}")
        return []

KNOWN_BAD_IPS = load_stix_ips()

def run_detection_pipeline(parsed_logs):
    if not parsed_logs:
        return []

    df = pd.DataFrame(parsed_logs)
    df['is_anomaly'] = False
    df['confidence_score'] = 0.0
    df['anomaly_reason'] = None

    # ==========================================
    # LAYER 1: Rule-Based & STIX (Deterministic)
    # ==========================================
    stix_mask = df['source_ip'].isin(KNOWN_BAD_IPS)
    df.loc[stix_mask, 'is_anomaly'] = True
    df.loc[stix_mask, 'confidence_score'] = 100.0
    df.loc[stix_mask, 'anomaly_reason'] = "STIX Intel Match: Known Malicious IP."

    df['minute'] = df['timestamp'].dt.floor('min')
    ip_counts = df.groupby(['source_ip', 'minute']).size().reset_index(name='count')
    brute_ips = ip_counts[ip_counts['count'] > 15]['source_ip'].unique()
    
    bf_mask = df['source_ip'].isin(brute_ips) & ~df['is_anomaly']
    df.loc[bf_mask, 'is_anomaly'] = True
    df.loc[bf_mask, 'confidence_score'] = 99.0
    df.loc[bf_mask, 'anomaly_reason'] = "Velocity Rule: Possible Brute Force Attack."

    sensitive_endpoints = ['/admin', '/env', '/config', '/.git']
    sensitive_mask = df['endpoint'].apply(lambda x: any(sub in str(x) for sub in sensitive_endpoints)) & (df['status_code'] >= 400) & ~df['is_anomaly']
    df.loc[sensitive_mask, 'is_anomaly'] = True
    df.loc[sensitive_mask, 'confidence_score'] = 95.0
    df.loc[sensitive_mask, 'anomaly_reason'] = "Rule: Unauthorized access attempt to sensitive endpoint."

    # ==========================================
    # LAYER 2: Machine Learning (Probabilistic)
    # ==========================================
    normal_mask = ~df['is_anomaly']
    if normal_mask.sum() > 0:
        features = df.loc[normal_mask, ['status_code', 'response_size']]
        clf = IsolationForest(contamination=0.05, random_state=42) 
        preds = clf.fit_predict(features)
        raw_scores = clf.decision_function(features)
        
        df.loc[normal_mask, 'ml_prediction'] = preds
        df.loc[normal_mask, 'raw_score'] = raw_scores
        
        ml_mask = normal_mask & (df['ml_prediction'] == -1)
        df.loc[ml_mask, 'is_anomaly'] = True
        df.loc[ml_mask, 'anomaly_reason'] = "ML Model (IsolationForest): Behavioral anomaly detected in payload size."
        
        df.loc[ml_mask, 'confidence_score'] = df.loc[ml_mask, 'raw_score'].apply(
            lambda x: round(min(99.9, 75.0 + (abs(x) * 100)), 1)
        )
        df = df.drop(columns=['ml_prediction', 'raw_score'])

    # ==========================================
    # LAYER 3: Generative AI Enrichment (LLM)
    # ==========================================
    for index, row in df[df['is_anomaly']].iterrows():
        original_reason = row['anomaly_reason']
        sanitized_log = f"Method: {row['http_method']}, Endpoint: {row['endpoint']}, Status: {row['status_code']}, Size: {row['response_size']} bytes"
        
        prompt = (
            f"You are a Senior SOC Analyst. A detection engine flagged this web request: {sanitized_log}. "
            f"The engine flagged it because: '{original_reason}'. "
            "Write a 1 or 2 sentence explanation of what the attacker is trying to achieve. "
            "If the status is 200, explain that the attack likely SUCCEEDED (e.g., data stolen or payload executed). "
            "If the status is 4xx or 5xx, explain that they are probing or failing."
        )
        
        try:
            chat = client.chat.completions.create(
                messages=[{"role": "user", "content": prompt}],
                model="llama-3.1-8b-instant", 
            )
            explanation = chat.choices[0].message.content.strip()
            df.at[index, 'anomaly_reason'] = f"🤖 AI Analyst: {explanation}"
        except Exception as e:
            print(f"LLM Error: {e}")
            df.at[index, 'anomaly_reason'] = f"⚠️ {original_reason} (AI Explanation failed: Check API Key or Network)"

    df = df.drop(columns=['minute'])
    return df.to_dict(orient='records')