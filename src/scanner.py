import subprocess
import json
import random
import math
import shutil
import time
import sqlite3
import os
import statistics
from datetime import datetime
from .threats import classify_threat, resolve_vendor
from .config import CONFIG

# --- HISTORY TRACKING FOR VELOCITY ---
# format: {bssid: [(timestamp, signal, lat, lon), ...]}
TARGET_HISTORY = {} 
HISTORY_MAX_LEN = 20

# --- TTS TRACKING ---
ANNOUNCED_THREATS = set()
LAST_ANNOUNCE_TIME = 0

WHITELIST = {"ignore_ssids": [], "ignore_macs": []}

def load_whitelist():
    """Loads the whitelist from config/whitelist.json."""
    global WHITELIST
    try:
        whitelist_path = os.path.join(os.path.dirname(__file__), "..", "config", "whitelist.json")
        if os.path.exists(whitelist_path):
            with open(whitelist_path, "r") as f:
                WHITELIST = json.load(f)
    except Exception as e:
        pass

def is_whitelisted(ssid, bssid):
    """Checks if a target is in the whitelist."""
    if ssid in WHITELIST.get("ignore_ssids", []):
        return True
    if bssid in WHITELIST.get("ignore_macs", []):
        return True
    return False

def init_db():
    """Initializes the SQLite database for logging."""
    # Ensure log_file points to a .db file
    log_file = CONFIG.get("log_file", "logs/intercepts.csv")
    if log_file.endswith(".csv"):
        log_file = log_file.replace(".csv", ".db")
        CONFIG["log_file"] = log_file
    
    db_path = log_file
    directory = os.path.dirname(db_path)
    if directory:
        os.makedirs(directory, exist_ok=True)
        
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS intercepts
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  timestamp TEXT,
                  ssid TEXT,
                  bssid TEXT,
                  vendor TEXT,
                  signal INTEGER,
                  freq TEXT,
                  encryption TEXT,
                  lat REAL,
                  lon REAL,
                  threat_label TEXT,
                  confidence TEXT,
                  is_mobile TEXT)''')
    conn.commit()
    conn.close()

# Initialize DB and Whitelist on import
load_whitelist()
init_db()

def announce_threat(text):
    """Announces a threat via TTS."""
    global LAST_ANNOUNCE_TIME
    now = time.time()
    
    # Don't overlap announcements too much
    if now - LAST_ANNOUNCE_TIME < 3: 
        return

    if shutil.which("termux-tts-speak"):
        try:
            subprocess.Popen(["termux-tts-speak", text])
            LAST_ANNOUNCE_TIME = now
        except:
            pass

def calculate_distance(signal_strength, freq_str="2.4G"):
    """
    Log-Distance Path Loss Model
    d = 10 ^ ((TxPower - RSSI) / (10 * n))
    """
    # Base params
    tx_power = -38 # Reference RSSI at 1 meter
    n = 2.5 # Path loss exponent (2.0=free space, 3.0=complex indoor)
    
    # Frequency adjustment
    if "5G" in freq_str:
        tx_power = -42 
        n = 3.0

    try:
        # We assume signal_strength is 0-100% (normalized)
        # Convert back to approx dBm: % = 2 * (dBm + 100) -> dBm = (% / 2) - 100
        rssi = (signal_strength / 2) - 100
            
        ratio = (tx_power - rssi) / (10 * n)
        dist = math.pow(10, ratio)
        return round(dist, 2)
    except:
        return 0.0

class Target:
    def __init__(self, ssid, bssid, signal, freq, encryption, lat=None, lon=None):
        self.ssid = ssid or "HIDDEN"
        self.bssid = bssid
        self.signal = int(signal)
        self.freq = freq
        self.encryption = encryption
        self.lat = lat
        self.lon = lon
        
        # Vendor Resolution
        self.vendor = resolve_vendor(bssid)
        
        # Advanced Signal Math: Distance Estimation
        self.dist_m = calculate_distance(self.signal, self.freq)
        
        self.is_threat, self.threat_label, self.confidence = classify_threat(self.ssid, self.bssid)
        self.is_mobile = False # Will be updated by history analysis
        self.is_pacing = False
        
        # Visuals (Random start position for radar blip)
        self.dist = max(0.1, 1.0 - (self.signal / 110.0))
        self.angle = random.uniform(0, 2 * math.pi)
        self.last_seen = 0

def normalize_rssi(dbm):
    try:
        val = int(dbm)
        percentage = 2 * (val + 100)
        return max(0, min(100, percentage))
    except:
        return 0

def get_gps_location():
    """Fetches GPS coordinates and speed via termux-location (Android) or returns None."""
    if not CONFIG.get("gps_enabled", False):
        return None, None, 0.0
    
    if shutil.which("termux-location"):
        try:
            out = subprocess.check_output("termux-location", shell=True, timeout=3).decode()
            data = json.loads(out)
            return data.get("latitude"), data.get("longitude"), data.get("speed", 0.0)
        except:
            return None, None, 0.0
    return None, None, 0.0

def analyze_mobility(target, my_speed=0.0):
    """
    Determines if a target is MOBILE or PACING based on signal/GPS variance.
    Updates TARGET_HISTORY and sets target.is_mobile.
    """
    global TARGET_HISTORY, ANNOUNCED_THREATS
    
    now = time.time()
    if target.bssid not in TARGET_HISTORY:
        TARGET_HISTORY[target.bssid] = []
    
    # Add current point
    history = TARGET_HISTORY[target.bssid]
    history.append((now, target.signal, target.lat, target.lon))
    
    # Prune old history
    if len(history) > HISTORY_MAX_LEN:
        history.pop(0)
    
    # Need at least 5 points (~10-15s) to determine velocity
    if len(history) < 5:
        return

    # Extract series
    signals = [x[1] for x in history]
    lats = [x[2] for x in history if x[2] is not None]
    
    # Calculate Variance
    sig_variance = statistics.variance(signals) if len(signals) > 1 else 0
    
    # GPS Variance (My movement)
    gps_variance = 0
    if len(lats) > 1:
        gps_variance = statistics.variance(lats) * 100000 # Scale up for small deg changes
    
    # Mobility Logic
    is_moving = False
    if gps_variance < 0.1 and sig_variance > 20:
        is_moving = True
    elif gps_variance > 1.0 and sig_variance < 10:
        is_moving = True
        
    target.is_mobile = is_moving
    
    # --- PACING DETECTION ---
    # Logic: My Speed > 10mph (4.5 m/s) AND Target Signal > 60% AND Duration > 15s
    # 15s check: First timestamp vs Now
    duration = now - history[0][0]
    avg_signal = sum(signals) / len(signals)
    
    if my_speed > 4.5 and avg_signal > 60 and duration > 15:
        target.is_pacing = True
        target.is_threat = True # Force threat status
        target.threat_label = "[PACING]"
        target.confidence = "HIGH"
        
        # Audio Alert for Pacing
        if target.bssid not in ANNOUNCED_THREATS:
            announce_threat("Alert. Pacing detected. Vehicle following.")
            ANNOUNCED_THREATS.add(target.bssid)

    # Audio Alert for High Confidence Threats
    if target.is_threat and target.confidence == "HIGH" and target.bssid not in ANNOUNCED_THREATS:
        clean_label = target.threat_label.replace("[", "").replace("]", "").replace(":", " ")
        announce_threat(f"Caution: {clean_label} detected.")
        ANNOUNCED_THREATS.add(target.bssid)

def log_threats(targets):
    """Logs detected threats to SQLite."""
    db_path = CONFIG.get("log_file", "logs/intercepts.db")
    
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    
    for t in targets:
        # Log threats, mobile targets, or everything if desired?
        # Prompt says "visualize ALL intercepts", so let's log everything or at least threats/mobile.
        # But heatmap usually implies mapping everything seen.
        # Original code logged only threats/mobile.
        # Let's log ALL for heatmap purposes, but maybe limit retention?
        # For now, I'll log everything to support "visualize all intercepts".
        
        c.execute("INSERT INTO intercepts (timestamp, ssid, bssid, vendor, signal, freq, encryption, lat, lon, threat_label, confidence, is_mobile) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                  (datetime.now().isoformat(),
                   t.ssid,
                   t.bssid,
                   t.vendor,
                   t.signal,
                   t.freq,
                   t.encryption,
                   t.lat,
                   t.lon,
                   t.threat_label,
                   t.confidence,
                   "YES" if t.is_mobile else "NO"))
    conn.commit()
    conn.close()

def scan():
    """Auto-detects platform and scans."""
    load_whitelist() # Reload occasionally? Or just once. Done at top level for now.
    
    raw_targets = []
    lat, lon, speed = get_gps_location()
    
    # 1. Try Termux (Android)
    if shutil.which("termux-wifi-scaninfo"):
        try:
            out = subprocess.check_output("termux-wifi-scaninfo", shell=True, timeout=CONFIG.get("scan_timeout", 2)).decode()
            data = json.loads(out)
            for net in data:
                ssid = net.get("ssid", "")
                bssid = net.get("bssid", "")
                rssi = net.get("rssi", -100)
                freq_int = net.get("frequency_mhz", 0)
                
                if is_whitelisted(ssid, bssid): continue
                
                band = "2.4G"
                if freq_int > 5000: band = "5G"
                if freq_int > 6000: band = "6G"
                
                freq = f"{band}"
                
                t = Target(ssid, bssid, normalize_rssi(rssi), freq, "UNK", lat, lon)
                analyze_mobility(t, speed)
                raw_targets.append(t)
        except:
            pass

    # 2. Try nmcli (Linux)
    elif shutil.which("nmcli"):
        try:
            cmd = "nmcli -t -f SSID,BSSID,SIGNAL,FREQ,SECURITY device wifi list"
            out = subprocess.check_output(cmd, shell=True, timeout=CONFIG.get("scan_timeout", 2)).decode()
            for line in out.strip().split("\n"):
                parts = line.split(":")
                
                ssid = "UNKNOWN"
                bssid = "00:00:00:00:00:00"
                signal = 0
                freq = "2.4G"
                
                if len(parts) >= 3:
                    for part in parts:
                        if len(part) == 17 and part.count(":") == 5:
                            bssid = part
                            break
                    
                    ssid = parts[0].replace("\\", "")
                    
                    if is_whitelisted(ssid, bssid): continue

                    for part in parts:
                        if part.isdigit() and int(part) <= 100:
                            signal = int(part)
                            
                    if "MHz" in line or "5" in line:
                        freq = "UNK" 
                        if "5180" in line or "5200" in line or "5GHz" in line: freq = "5G"
                        else: freq = "2.4G"

                t = Target(ssid, bssid, signal, freq, "WPA", lat, lon)
                analyze_mobility(t, speed)
                raw_targets.append(t)
        except:
            pass

    # 3. Demo Mode (Fallback)
    if not raw_targets:
        for _ in range(5):
            ssid = f"DEMO_{random.randint(100,999)}"
            bssid = "00:00:00:00:00:00"
            if not is_whitelisted(ssid, bssid):
                t = Target(ssid, bssid, random.randint(20,90), "2.4", "WPA", lat, lon)
                analyze_mobility(t, speed)
                raw_targets.append(t)
    
    if raw_targets:
        log_threats(raw_targets)
        
    return raw_targets
