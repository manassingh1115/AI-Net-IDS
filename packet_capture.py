"""
AI-Net Day 11
Real-Time Network Packet Capture + Flow Aggregation

Purpose:
    Capture packets from a network interface, aggregate them into flows,
    calculate the same 10 features used by the trained AI-Net model, and
    classify each completed flow as BENIGN or DDoS.

Important:
    This is the first real packet-capture layer. It does not yet replace
    the Flask dashboard. The next step will connect this engine to Flask.

Windows:
    Scapy packet capture normally requires Npcap and an administrator
    terminal.
"""

import argparse
import csv
import os
import sqlite3
import time
from collections import defaultdict
from datetime import datetime

import joblib
import numpy as np
import pandas as pd
from scapy.all import (
    IP,
    TCP,
    UDP,
    sniff,
)


# ============================================================
# PATHS
# ============================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

MODEL_PATH = os.path.join(
    BASE_DIR,
    "models",
    "random_forest_model.pkl"
)

SCALER_PATH = os.path.join(
    BASE_DIR,
    "models",
    "scaler.pkl"
)

FEATURE_FILE = os.path.join(
    BASE_DIR,
    "model_features.txt"
)

LOG_DIR = os.path.join(
    BASE_DIR,
    "logs"
)

LIVE_LOG = os.path.join(
    LOG_DIR,
    "live_predictions.csv"
)

DB_PATH = os.path.join(
    LOG_DIR,
    "ai_net.db"
)


def ensure_detection_database():
    """Ensure the SQLite detection_events table exists for direct persistence."""
    os.makedirs(LOG_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=30)
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS detection_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_hash TEXT UNIQUE NOT NULL,
                timestamp TEXT,
                source_ip TEXT,
                destination_ip TEXT,
                source_port TEXT,
                destination_port TEXT,
                protocol TEXT,
                flow_duration REAL,
                packets REAL,
                fwd_packets REAL,
                bwd_packets REAL,
                prediction TEXT,
                confidence REAL,
                source TEXT,
                ingested_at TEXT NOT NULL
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_detection_timestamp ON detection_events(timestamp)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_detection_prediction ON detection_events(prediction)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_detection_source_ip ON detection_events(source_ip)")
        conn.commit()
    finally:
        conn.close()


def persist_detection_event(flow, result, timestamp):
    """Persist a completed live flow directly to SQLite."""
    ensure_detection_database()

    import hashlib

    duration = max(0.0, float(flow.get("last_seen", 0)) - float(flow.get("first_seen", 0)))
    event_key = "|".join([
        str(timestamp),
        str(flow.get("source_ip", "")),
        str(flow.get("destination_ip", "")),
        str(flow.get("source_port", "")),
        str(flow.get("destination_port", "")),
        str(flow.get("protocol", "")),
        str(flow.get("packet_count", 0)),
        str(result.get("prediction", "")),
        str(result.get("confidence", 0)),
    ])
    event_hash = hashlib.sha256(event_key.encode("utf-8")).hexdigest()

    conn = sqlite3.connect(DB_PATH, timeout=30)
    try:
        conn.execute(
            """INSERT OR IGNORE INTO detection_events
            (event_hash, timestamp, source_ip, destination_ip, source_port,
             destination_port, protocol, flow_duration, packets, fwd_packets,
             bwd_packets, prediction, confidence, source, ingested_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                event_hash,
                timestamp,
                flow.get("source_ip"),
                flow.get("destination_ip"),
                str(flow.get("source_port", "")),
                str(flow.get("destination_port", "")),
                flow.get("protocol"),
                duration,
                float(flow.get("packet_count", 0)),
                float(len(flow.get("fwd_lengths", []))),
                float(len(flow.get("bwd_lengths", []))),
                result.get("prediction"),
                float(result.get("confidence", 0)),
                "live_packet_capture",
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            )
        )
        conn.commit()
    finally:
        conn.close()


ensure_detection_database()


# ============================================================
# AI-NET MODEL FEATURES
# ============================================================

DEFAULT_FEATURES = [
    "Avg Bwd Segment Size",
    "Packet Length Variance",
    "Bwd Packet Length Max",
    "Max Packet Length",
    "Bwd Packet Length Std",
    "Packet Length Std",
    "Average Packet Size",
    "Subflow Fwd Packets",
    "act_data_pkt_fwd",
    "Bwd Packet Length Mean",
]


# ============================================================
# FLOW STORAGE
# ============================================================

flows = {}


# ============================================================
# LOAD MODEL
# ============================================================

def load_features():
    """
    Load the feature names used by the trained model.

    If model_features.txt contains a larger historical feature list,
    the 10-feature configuration used by the current AI-Net model is
    selected explicitly.
    """

    if os.path.exists(FEATURE_FILE):
        try:
            with open(
                FEATURE_FILE,
                "r",
                encoding="utf-8"
            ) as file:
                file_features = [
                    line.strip()
                    for line in file
                    if line.strip()
                ]

            if all(
                feature in file_features
                for feature in DEFAULT_FEATURES
            ):
                return DEFAULT_FEATURES

        except Exception as error:
            print(
                "Could not read model_features.txt:",
                error
            )

    return DEFAULT_FEATURES


FEATURES = load_features()


def load_ai_model():
    if not os.path.exists(MODEL_PATH):
        raise FileNotFoundError(
            f"Model not found: {MODEL_PATH}"
        )

    if not os.path.exists(SCALER_PATH):
        raise FileNotFoundError(
            f"Scaler not found: {SCALER_PATH}"
        )

    model = joblib.load(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)

    print("=" * 60)
    print("AI-Net Packet Capture Engine")
    print("=" * 60)
    print("Model:", MODEL_PATH)
    print("Scaler:", SCALER_PATH)
    print("Features:", len(FEATURES))
    print("=" * 60)

    return model, scaler


MODEL, SCALER = load_ai_model()


# ============================================================
# FLOW KEY
# ============================================================

def get_flow_key(packet):
    """
    Create a bidirectional flow key.

    TCP/UDP traffic:
        source IP, destination IP, source port, destination port,
        protocol

    The sorted endpoint representation makes both directions belong
    to the same flow.
    """

    if IP not in packet:
        return None

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    protocol = int(packet[IP].proto)

    src_port = 0
    dst_port = 0

    if TCP in packet:
        src_port = int(packet[TCP].sport)
        dst_port = int(packet[TCP].dport)

    elif UDP in packet:
        src_port = int(packet[UDP].sport)
        dst_port = int(packet[UDP].dport)

    endpoint_a = (
        src_ip,
        src_port
    )

    endpoint_b = (
        dst_ip,
        dst_port
    )

    if endpoint_a <= endpoint_b:
        return (
            endpoint_a,
            endpoint_b,
            protocol
        )

    return (
        endpoint_b,
        endpoint_a,
        protocol
    )


# ============================================================
# CREATE FLOW
# ============================================================

def create_flow(packet):
    """
    Store the first packet as the forward direction.
    """

    if IP not in packet:
        return None

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    src_port = 0
    dst_port = 0

    if TCP in packet:
        src_port = int(packet[TCP].sport)
        dst_port = int(packet[TCP].dport)

    elif UDP in packet:
        src_port = int(packet[UDP].sport)
        dst_port = int(packet[UDP].dport)

    protocol_name = "OTHER"

    if TCP in packet:
        protocol_name = "TCP"
    elif UDP in packet:
        protocol_name = "UDP"

    now = float(
        getattr(
            packet,
            "time",
            time.time()
        )
    )

    return {
        "first_seen": now,
        "last_seen": now,

        "source_ip": src_ip,
        "destination_ip": dst_ip,

        "source_port": src_port,
        "destination_port": dst_port,

        "protocol": protocol_name,

        "fwd_lengths": [],
        "bwd_lengths": [],

        "all_lengths": [],

        "active_fwd_packets": 0,

        "packet_count": 0,

        "last_packet_time": now,
    }


# ============================================================
# PACKET DIRECTION
# ============================================================

def is_forward(packet, flow):
    if IP not in packet:
        return True

    return (
        packet[IP].src == flow["source_ip"]
        and
        packet[IP].dst == flow["destination_ip"]
    )


# ============================================================
# UPDATE FLOW
# ============================================================

def update_flow(packet, flow):
    """
    Add one packet to an existing flow.
    """

    packet_length = int(
        len(packet)
    )

    packet_time = float(
        getattr(
            packet,
            "time",
            time.time()
        )
    )

    flow["last_seen"] = packet_time
    flow["last_packet_time"] = packet_time
    flow["packet_count"] += 1

    flow["all_lengths"].append(
        packet_length
    )

    if is_forward(packet, flow):

        flow["fwd_lengths"].append(
            packet_length
        )

        # Approximation of act_data_pkt_fwd:
        # count forward packets carrying payload data.
        has_payload = False

        if TCP in packet:
            try:
                has_payload = (
                    len(bytes(packet[TCP].payload)) > 0
                )
            except Exception:
                has_payload = False

        elif UDP in packet:
            try:
                has_payload = (
                    len(bytes(packet[UDP].payload)) > 0
                )
            except Exception:
                has_payload = False

        if has_payload:
            flow["active_fwd_packets"] += 1

    else:

        flow["bwd_lengths"].append(
            packet_length
        )


# ============================================================
# FEATURE HELPERS
# ============================================================

def safe_mean(values):
    if not values:
        return 0.0

    return float(
        np.mean(values)
    )


def safe_std(values):
    if len(values) < 2:
        return 0.0

    return float(
        np.std(
            values,
            ddof=1
        )
    )


def safe_variance(values):
    if len(values) < 2:
        return 0.0

    return float(
        np.var(
            values,
            ddof=1
        )
    )


# ============================================================
# FLOW -> MODEL FEATURES
# ============================================================

def flow_to_features(flow):
    """
    Convert an aggregated flow to the exact 10 features expected
    by the AI-Net model.

    These are the features currently used by the trained model.
    """

    all_lengths = flow["all_lengths"]
    bwd_lengths = flow["bwd_lengths"]
    fwd_lengths = flow["fwd_lengths"]

    bwd_mean = safe_mean(
        bwd_lengths
    )

    bwd_max = (
        max(bwd_lengths)
        if bwd_lengths
        else 0.0
    )

    bwd_std = safe_std(
        bwd_lengths
    )

    packet_variance = safe_variance(
        all_lengths
    )

    packet_std = safe_std(
        all_lengths
    )

    max_packet_length = (
        max(all_lengths)
        if all_lengths
        else 0.0
    )

    average_packet_size = safe_mean(
        all_lengths
    )

    values = {
        "Avg Bwd Segment Size": bwd_mean,

        "Packet Length Variance":
            packet_variance,

        "Bwd Packet Length Max":
            bwd_max,

        "Max Packet Length":
            max_packet_length,

        "Bwd Packet Length Std":
            bwd_std,

        "Packet Length Std":
            packet_std,

        "Average Packet Size":
            average_packet_size,

        "Subflow Fwd Packets":
            len(fwd_lengths),

        "act_data_pkt_fwd":
            flow["active_fwd_packets"],

        "Bwd Packet Length Mean":
            bwd_mean,
    }

    return [
        float(
            values.get(
                feature,
                0.0
            )
        )
        for feature in FEATURES
    ]


# ============================================================
# PREDICTION
# ============================================================

def predict_flow(flow):
    feature_values = flow_to_features(
        flow
    )

    frame = pd.DataFrame(
        [feature_values],
        columns=FEATURES
    )

    frame = frame.replace(
        [np.inf, -np.inf],
        np.nan
    )

    frame = frame.fillna(0)

    try:
        scaled = SCALER.transform(
            frame
        )
    except Exception as error:
        print(
            "\nSCALER ERROR:",
            error
        )
        return None

    prediction = MODEL.predict(
        scaled
    )[0]

    confidence = 0.0

    if hasattr(
        MODEL,
        "predict_proba"
    ):
        probabilities = MODEL.predict_proba(
            scaled
        )[0]

        confidence = float(
            np.max(probabilities)
        ) * 100

    if isinstance(
        prediction,
        (int, np.integer)
    ):
        label = (
            "DDoS"
            if int(prediction) == 1
            else "BENIGN"
        )
    else:
        label = str(
            prediction
        )

        if label.strip().lower() in {
            "1",
            "ddos",
            "attack"
        }:
            label = "DDoS"
        else:
            label = "BENIGN"

    return {
        "prediction": label,
        "confidence": round(
            confidence,
            2
        ),
        "features": feature_values
    }


# ============================================================
# SAVE PREDICTION
# ============================================================

def save_prediction(flow, result):
    os.makedirs(
        LOG_DIR,
        exist_ok=True
    )

    file_exists = os.path.exists(
        LIVE_LOG
    )

    timestamp = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    row = {
        "Timestamp": timestamp,
        "Source IP": flow["source_ip"],
        "Destination IP": flow["destination_ip"],
        "Source Port": flow["source_port"],
        "Destination Port": flow["destination_port"],
        "Protocol": flow["protocol"],
        "Packets": flow["packet_count"],
        "Fwd Packets": len(
            flow["fwd_lengths"]
        ),
        "Bwd Packets": len(
            flow["bwd_lengths"]
        ),
        "AI-Net Prediction":
            result["prediction"],
        "AI-Net Confidence (%)":
            result["confidence"],
    }

    with open(
        LIVE_LOG,
        "a",
        newline="",
        encoding="utf-8"
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=list(
                row.keys()
            )
        )

        if not file_exists:
            writer.writeheader()

        writer.writerow(row)

    # SQLite is now the primary persistent store for detection telemetry.
    try:
        persist_detection_event(flow, result, timestamp)
    except Exception as error:
        # Keep CSV capture operational even if SQLite is temporarily unavailable.
        print("SQLITE DETECTION PERSISTENCE WARNING:", error)


# ============================================================
# COMPLETE / EXPIRE FLOWS
# ============================================================

def process_expired_flows(
    timeout_seconds=15
):
    """
    Predict flows that have been inactive for timeout_seconds.
    """

    now = time.time()

    expired = []

    for key, flow in list(
        flows.items()
    ):

        if (
            now - flow["last_seen"]
            >= timeout_seconds
        ):
            expired.append(
                key
            )

    for key in expired:

        flow = flows.pop(
            key
        )

        if flow["packet_count"] < 2:
            continue

        result = predict_flow(
            flow
        )

        if result is None:
            continue

        save_prediction(
            flow,
            result
        )

        icon = (
            "🚨"
            if result["prediction"] == "DDoS"
            else "✓"
        )

        print(
            f"{icon} "
            f"{flow['source_ip']} -> "
            f"{flow['destination_ip']} | "
            f"{flow['protocol']} | "
            f"{result['prediction']} | "
            f"{result['confidence']:.2f}%"
        )


# ============================================================
# PACKET HANDLER
# ============================================================

def packet_handler(packet):
    """
    Called by Scapy for every captured packet.
    """

    if IP not in packet:
        return

    key = get_flow_key(
        packet
    )

    if key is None:
        return

    if key not in flows:

        flow = create_flow(
            packet
        )

        if flow is None:
            return

        flows[key] = flow

    update_flow(
        packet,
        flows[key]
    )


# ============================================================
# MAIN CAPTURE ENGINE
# ============================================================

def start_capture(
    interface=None,
    duration=60,
    flow_timeout=15
):
    """
    Capture packets for a fixed duration.

    If interface is None, Scapy chooses the default interface.
    """

    print()
    print("=" * 60)
    print("AI-Net REAL-TIME PACKET CAPTURE")
    print("=" * 60)

    if interface:
        print(
            "Interface:",
            interface
        )
    else:
        print(
            "Interface: default"
        )

    print(
        "Capture duration:",
        duration,
        "seconds"
    )

    print(
        "Flow timeout:",
        flow_timeout,
        "seconds"
    )

    print()
    print(
        "Press Ctrl+C to stop."
    )
    print("=" * 60)

    start_time = time.time()

    def stop_filter(_packet):
        return (
            time.time() - start_time
            >= duration
        )

    try:

        sniff(
            iface=interface,
            prn=packet_handler,
            store=False,
            stop_filter=stop_filter,
            timeout=duration
        )

    except PermissionError:

        print()
        print(
            "ERROR: Packet capture requires "
            "administrator privileges."
        )
        print(
            "On Windows, install Npcap and "
            "run VS Code/terminal as Administrator."
        )
        return

    except Exception as error:

        print()
        print(
            "PACKET CAPTURE ERROR:",
            error
        )
        return

    # Give remaining flows one final prediction.
    print()
    print(
        "Processing remaining flows..."
    )

    for key in list(
        flows.keys()
    ):

        flow = flows.pop(
            key
        )

        if flow["packet_count"] < 2:
            continue

        result = predict_flow(
            flow
        )

        if result is None:
            continue

        save_prediction(
            flow,
            result
        )

        icon = (
            "🚨"
            if result["prediction"] == "DDoS"
            else "✓"
        )

        print(
            f"{icon} "
            f"{flow['source_ip']} -> "
            f"{flow['destination_ip']} | "
            f"{flow['protocol']} | "
            f"{result['prediction']} | "
            f"{result['confidence']:.2f}%"
        )

    print()
    print("=" * 60)
    print("CAPTURE COMPLETE")
    print("=" * 60)
    print(
        "Live predictions saved to:"
    )
    print(
        LIVE_LOG
    )
    print("=" * 60)


# ============================================================
# COMMAND LINE
# ============================================================

def main():

    parser = argparse.ArgumentParser(
        description=(
            "AI-Net real-time packet capture "
            "and intrusion detection engine."
        )
    )

    parser.add_argument(
        "--interface",
        default=None,
        help=(
            "Network interface name. "
            "Leave empty for the default interface."
        )
    )

    parser.add_argument(
        "--duration",
        type=int,
        default=60,
        help=(
            "Capture duration in seconds "
            "(default: 60)."
        )
    )

    parser.add_argument(
        "--timeout",
        type=int,
        default=15,
        help=(
            "Flow inactivity timeout in seconds "
            "(default: 15)."
        )
    )

    args = parser.parse_args()

    start_capture(
        interface=args.interface,
        duration=args.duration,
        flow_timeout=args.timeout
    )


if __name__ == "__main__":
    main()
