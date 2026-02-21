import subprocess
import json
import random
import math
import shutil
from .threats import classify_threat

class Target:
    def __init__(self, ssid, bssid, signal, freq, encryption):
        self.ssid = ssid or "HIDDEN"
        self.bssid = bssid
        self.signal = int(signal)
        self.freq = freq
        self.encryption = encryption
        
        self.is_threat, self.threat_label, self.confidence = classify_threat(self.ssid, self.bssid)
        
        # Visuals (Random start position)
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

def scan():
    """Auto-detects platform and scans."""
    targets = []
    
    # 1. Try Termux (Android)
    if shutil.which("termux-wifi-scaninfo"):
        try:
            # 'termux-wifi-scaninfo' reads from cache (Fast). 
            # 'termux-wifi-scan' triggers active scan (Slow, ~3-5s).
            # Strategy: Read cache instantly. 
            # Note: User should run 'termux-wifi-scan' via cron or background if they want updates, 
            # but 'scaninfo' is usually fresh enough if location is on.
            out = subprocess.check_output("termux-wifi-scaninfo", shell=True, timeout=2).decode()
            data = json.loads(out)
            for net in data:
                ssid = net.get("ssid", "")
                bssid = net.get("bssid", "")
                rssi = net.get("rssi", -100)
                freq_int = net.get("frequency_mhz", 0)
                
                # Determine Band (Physics)
                band = "2.4G"
                if freq_int > 5000: band = "5G"
                if freq_int > 6000: band = "6G"
                
                # Format Freq
                freq = f"{band}"
                
                targets.append(Target(ssid, bssid, normalize_rssi(rssi), freq, "UNK"))
            return targets
        except:
            pass

    # 2. Try nmcli (Linux)
    if shutil.which("nmcli"):
        try:
            # -f CHAN is approximate for freq, or usually FREQ is available
            cmd = "nmcli -t -f SSID,BSSID,SIGNAL,FREQ,SECURITY device wifi list"
            out = subprocess.check_output(cmd, shell=True, timeout=2).decode()
            for line in out.strip().split("\n"):
                parts = line.split(":")
                # nmcli escaping makes split(":") unsafe if SSID has colons.
                # Hardening parser:
                # Real nmcli output: "SSID:BSSID:SIGNAL:FREQ..."
                # If we assume BSSID is 6 hex pairs, we can find it via regex or fixed offset if simple.
                # For this demo, let's just grab the BSSID if it looks like a BSSID.
                
                ssid = "UNKNOWN"
                bssid = "00:00:00:00:00:00"
                signal = 0
                freq = "2.4G"
                
                # Simple heuristic parser
                if len(parts) >= 3:
                    # Last part is usually Security, 2nd last freq...
                    # Let's try to find the MAC address pattern
                    for part in parts:
                        if len(part) == 17 and part.count(":") == 5:
                            bssid = part
                            break
                    
                    ssid = parts[0].replace("\\", "") # Clean escapes
                    
                    # Signal is usually a raw number 0-100
                    for part in parts:
                        if part.isdigit() and int(part) <= 100:
                            signal = int(part)
                            
                    # Freq detection
                    if "MHz" in line or "5" in line: # Crude freq check
                        freq = "UNK" 
                        if "5180" in line or "5200" in line or "5GHz" in line: freq = "5G"
                        else: freq = "2.4G"

                targets.append(Target(ssid, bssid, signal, freq, "WPA"))
            return targets
        except:
            pass

    # 3. Demo Mode (Fallback)
    for _ in range(5):
        targets.append(Target(f"DEMO_{random.randint(100,999)}", "00:00:00:00:00:00", random.randint(20,90), "2.4", "WPA"))
    
    return targets
