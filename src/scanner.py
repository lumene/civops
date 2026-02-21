import subprocess
import json
import random
import math
import shutil
import time
import csv
import os
from datetime import datetime
from .threats import classify_threat
from .config import CONFIG

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
        
        # Advanced Signal Math: Distance Estimation
        self.dist_m = calculate_distance(self.signal, self.freq)
        
        self.is_threat, self.threat_label, self.confidence = classify_threat(self.ssid, self.bssid)
        
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
    """Fetches GPS coordinates via termux-location (Android) or returns None."""
    if not CONFIG.get("gps_enabled", False):
        return None, None
    
    if shutil.which("termux-location"):
        try:
            out = subprocess.check_output("termux-location", shell=True, timeout=3).decode()
            data = json.loads(out)
            return data.get("latitude"), data.get("longitude")
        except:
            return None, None
    return None, None

def log_threats(targets):
    """Logs detected threats to CSV."""
    log_file = CONFIG.get("log_file", "logs/intercepts.csv")
    
    directory = os.path.dirname(log_file)
    if directory:
        os.makedirs(directory, exist_ok=True)
    
    file_exists = os.path.isfile(log_file)
    
    with open(log_file, "a", newline="") as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow(["Timestamp", "SSID", "BSSID", "Signal", "Freq", "Encryption", "Latitude", "Longitude", "Threat Label", "Confidence"])
            
        for t in targets:
            if t.is_threat:
                writer.writerow([
                    datetime.now().isoformat(),
                    t.ssid,
                    t.bssid,
                    t.signal,
                    t.freq,
                    t.encryption,
                    t.lat if t.lat else "",
                    t.lon if t.lon else "",
                    t.threat_label,
                    t.confidence
                ])

def scan():
    """Auto-detects platform and scans."""
    targets = []
    lat, lon = get_gps_location()
    
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
                
                band = "2.4G"
                if freq_int > 5000: band = "5G"
                if freq_int > 6000: band = "6G"
                
                freq = f"{band}"
                
                targets.append(Target(ssid, bssid, normalize_rssi(rssi), freq, "UNK", lat, lon))
            
            if targets:
                log_threats(targets)
            return targets
        except:
            pass

    # 2. Try nmcli (Linux)
    if shutil.which("nmcli"):
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
                    
                    for part in parts:
                        if part.isdigit() and int(part) <= 100:
                            signal = int(part)
                            
                    if "MHz" in line or "5" in line:
                        freq = "UNK" 
                        if "5180" in line or "5200" in line or "5GHz" in line: freq = "5G"
                        else: freq = "2.4G"

                targets.append(Target(ssid, bssid, signal, freq, "WPA", lat, lon))
            
            if targets:
                log_threats(targets)
            return targets
        except:
            pass

    # 3. Demo Mode (Fallback)
    if not targets:
        for _ in range(5):
            targets.append(Target(f"DEMO_{random.randint(100,999)}", "00:00:00:00:00:00", random.randint(20,90), "2.4", "WPA", lat, lon))
    
    return targets
