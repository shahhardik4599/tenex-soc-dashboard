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
        with open("../data/stix_intel_feed.json", "r") as f:
            stix_data = json.load(f)
            return [obj["pattern"].split("'")[1] for obj in stix_data.get("objects", []) if "pattern" in obj]
    except:
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

    # LAYER 1: Rules
    stix_mask = df['source_ip'].isin(KNOWN_BAD_IPS)
    df.loc[stix_mask, ['is_anomaly', 'category', 'confidence_score', 'anomaly_reason']] = [True, "Threat Intel", 100.0, "STIX Intel Match: Known Malicious IP."]

    df['minute'] = df['timestamp'].dt.floor('min')
    brute_ips = df.groupby(['source_ip', 'minute']).size().reset_index(name='count').query('count > 15')['source_ip'].unique()
    bf_mask = df['source_ip'].isin(brute_ips) & ~df['is_anomaly']
    df.loc[bf_mask, ['is_anomaly', 'category', 'confidence_score', 'anomaly_reason']] = [True, "Brute Force", 99.0, "Velocity Rule: Possible Brute Force Attack."]

    sensitive_endpoints = ['/admin', '/env', '/config', '/.git']
    sensitive_mask = df['endpoint'].apply(lambda x: any(sub in str(x) for sub in sensitive_endpoints)) & (df['status_code'] >= 400) & ~df['is_anomaly']
    df.loc[sensitive_mask, ['is_anomaly', 'category', 'confidence_score', 'anomaly_reason']] = [True, "Probing", 95.0, "Rule: Unauthorized access attempt to sensitive endpoint."]

    # LAYER 2: ML
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

    # LAYER 3: LLM Enrichment
    for index, row in df[df['is_anomaly']].iterrows():
        prompt = f"You are a Senior SOC Analyst. Explain this {row['category']} attack: {row['http_method']} {row['endpoint']}, Status {row['status_code']}, Size {row['response_size']} bytes. Reason: {row['anomaly_reason']}. Write 2 concise sentences."
        try:
            chat = client.chat.completions.create(messages=[{"role": "user", "content": prompt}], model="llama-3.1-8b-instant")
            df.at[index, 'anomaly_reason'] = f"🤖 AI Analyst: {chat.choices[0].message.content.strip()}"
        except:
            continue

    return df.drop(columns=['minute']).to_dict(orient='records')