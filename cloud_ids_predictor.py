import boto3
import requests
import time

# ========== CONFIGURATION ==========
LOG_GROUP_NAME = 'cloudloggroup'  # CloudWatch log group name
LOG_STREAM_NAME = 'eni-051f33bea4b62cb7b-all'  # Log stream name
FLASK_API_URL = 'http://16.16.253.44:5000/predict'  # Flask API endpoint
REGION = 'eu-north-1'

# ========== AWS CLIENT ==========
logs_client = boto3.client('logs', region_name=REGION)

# ========== FULL FEATURE SET ==========
original_feature_columns = [
    "Protocol", "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
    "Fwd Packets Length Total", "Bwd Packets Length Total", "Fwd Packet Length Max",
    "Fwd Packet Length Min", "Fwd Packet Length Mean", "Fwd Packet Length Std",
    "Bwd Packet Length Max", "Bwd Packet Length Min", "Bwd Packet Length Mean", "Bwd Packet Length Std",
    "Flow Bytes/s", "Flow Packets/s", "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min",
    "Fwd IAT Total", "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min",
    "Bwd IAT Total", "Bwd IAT Mean", "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min",
    "Fwd PSH Flags", "Bwd PSH Flags", "Fwd URG Flags", "Bwd URG Flags",
    "Fwd Header Length", "Bwd Header Length", "Fwd Packets/s", "Bwd Packets/s",
    "Packet Length Min", "Packet Length Max", "Packet Length Mean", "Packet Length Std",
    "Packet Length Variance", "FIN Flag Count", "SYN Flag Count", "RST Flag Count",
    "PSH Flag Count", "ACK Flag Count", "URG Flag Count", "CWE Flag Count", "ECE Flag Count",
    "Down/Up Ratio", "Avg Packet Size", "Avg Fwd Segment Size", "Avg Bwd Segment Size",
    "Fwd Avg Bytes/Bulk", "Fwd Avg Packets/Bulk", "Fwd Avg Bulk Rate",
    "Bwd Avg Bytes/Bulk", "Bwd Avg Packets/Bulk", "Bwd Avg Bulk Rate",
    "Subflow Fwd Packets", "Subflow Fwd Bytes", "Subflow Bwd Packets", "Subflow Bwd Bytes",
    "Init Fwd Win Bytes", "Init Bwd Win Bytes", "Fwd Act Data Packets",
    "Fwd Seg Size Min", "Active Mean", "Active Std", "Active Max", "Active Min",
    "Idle Mean", "Idle Std", "Idle Max", "Idle Min"
]

# ========== FETCH LOG EVENTS ==========
def fetch_log_events():
    response = logs_client.get_log_events(
        logGroupName=LOG_GROUP_NAME,
        logStreamName=LOG_STREAM_NAME,
        startFromHead=False
    )
    return [event['message'] for event in response['events']]

# ========== PARSE LOG LINE ==========
def parse_log_to_features(log_line):
    try:
        parts = log_line.split()
        src_ip = parts[3]
        protocol = int(parts[7])
        packets = int(parts[8])
        bytes_transferred = int(parts[9])
        start = int(parts[10])
        end = int(parts[11])
        duration = end - start if end > start else 1

        base_features = {
            "Protocol": protocol,
            "Flow Duration": duration,
            "Total Fwd Packets": packets,
            "Total Backward Packets": 0,
            "Fwd Packets Length Total": bytes_transferred,
            "Bwd Packets Length Total": 0,
            "Flow Bytes/s": bytes_transferred / duration,
            "Flow Packets/s": packets / duration
        }

        for col in original_feature_columns:
            if col not in base_features:
                base_features[col] = 0

        ordered_features = {k: base_features[k] for k in original_feature_columns}
        return ordered_features, src_ip

    except Exception as e:
        print(f"⚠️ Error parsing log line: {e}")
        return None, None

# ========== PREDICT ==========
def predict_with_model(features):
    try:
        response = requests.post(FLASK_API_URL, json=features, timeout=5)
        print("📨 API Response:", response.status_code, response.text)
        if response.status_code == 200:
            return response.json().get("prediction")
        else:
            return f"Error: {response.status_code} - {response.text}"
    except Exception as e:
        return f"Request failed: {e}"

# ========== MAIN ==========
if __name__ == "__main__":
    print("📡 Fetching VPC flow logs...")
    logs = fetch_log_events()

    for log in logs:
        features, src_ip = parse_log_to_features(log)
        if features:
            prediction = predict_with_model(features)
            print(f"🧠 Prediction: {prediction} | Source IP: {src_ip} | Log: {log}")
        time.sleep(1)  # Optional delay
