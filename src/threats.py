# Threat Signatures and Classification Logic (Deep Research V2)

# --- SSID KEYWORDS (Heuristic) ---
# Expanded based on verified municipal/police network standards.
SUSPICIOUS_SSIDS = [
    # Standard Police/Gov
    "police", "sheriff", "patrol", "cop", "law", "enforcement",
    "mdc", "mdt", "mobile", "unit", "vehicle", "car", "squad",
    "publicsafety", "cityof", "county", "gov", "municipal",
    "emergency", "911", "dispatch", "command", "eoc",
    
    # Specific Hardware/Vendors
    "axon", "fleet", "bodycam", "taser", "evidence",
    "watchguard", "vigilant", "alpr", "lpr", "plate", "recognition",
    "cradlepoint", "ibr", "ibr600", "ibr900", "ibr1100", "ibr1700",
    "sierra", "airlink", "mp70", "gx450", "rv50", "mg90",
    "panasonic", "arbitrator", "toughbook",
    "kustom", "stalker", "radar", "lidar",
    "galls", "whelen", "soundoff", # Upfitters often leave test SSIDs
    
    # Surveillance / Stingray / Covert
    "stingray", "hailstorm", "drt", "imsi", "covert", "surveillance", "hidden",
    "fbi", "dea", "atf", "dhs", "taskforce", "icac",
    "covert", "kel", "kel-tech", "dropcam", "polecam"
]

# --- OUI PREFIXES (Hardware MAC Addresses) ---
# Deep dive into surveillance & industrial vendors.
# Format: "XX:XX:XX": ("Vendor Name", "Likely Device Type")
SUSPICIOUS_OUIS = {
    # --- BODY CAMS & IN-CAR VIDEO ---
    "00:25:DF": ("Axon (Taser)", "Bodycam/Fleet Hub"),
    "00:1C:12": ("Axon Enterprise", "Bodycam"),
    "34:1C:F0": ("WatchGuard Video", "In-Car Video System"),
    "00:1E:06": ("Wibrain", "Industrial Mobile PC"),
    "00:0C:29": ("VMware", "Mobile Server/MDC (Virtual Interface)"),
    "00:50:C2": ("TlON", "Surveillance System"),
    "00:0F:92": ("Vigilant Solutions", "ALPR Processor"),
    "00:11:8C": ("Genetec", "AutoVu ALPR"),
    
    # --- FLEET ROUTERS (High Confidence of Vehicle) ---
    "00:30:44": ("Cradlepoint", "Police Fleet Router (IBR/AER Series)"),
    "20:0C:C8": ("Cradlepoint", "Police Fleet Router"),
    "00:A0:F8": ("Sierra Wireless", "AirLink Gateway (MP70/MG90)"),
    "00:19:C8": ("Sierra Wireless", "AirLink Gateway"),
    "A8:4E:3F": ("Peplink", "Vehicle Router (MAX BR1/Transit)"),
    "00:1A:DD": ("Peplink", "Vehicle Router"),
    "00:0B:6B": ("Wintec", "Industrial Wireless"),
    
    # --- MUNICIPAL / SURVEILLANCE ---
    "00:19:34": ("Panasonic", "Arbitrator 360 / Toughbook"),
    "00:C0:CA": ("Panasonic", "Toughbook WLAN"),
    "00:04:F2": ("Polycom", "Wireless Headset (Dispatch)"),
    "00:10:E7": ("Breezecom", "Municipal Mesh Node"),
    "00:20:A6": ("Proxim", "Traffic/Surveillance Backhaul"),
    "00:08:02": ("Compaq", "Legacy MDC"),
    
    # --- DRONES / UAV (New V2) ---
    "60:60:1F": ("DJI", "Drone/UAV"),
    "34:D2:62": ("DJI", "Drone/UAV"),
    "90:03:B7": ("DJI", "Drone/UAV"),
    "00:26:7E": ("Parrot", "Drone/UAV"),
    "90:3A:E6": ("Autel", "Drone/UAV"),
}

def classify_threat(ssid, bssid):
    """
    Analyzes SSID and BSSID (MAC) to determine if a target is a potential threat.
    Returns: (is_threat: bool, label: str, confidence: str)
    """
    if not ssid and not bssid:
        return False, "", "NONE"

    confidence = "LOW"
    label = ""
    is_threat = False

    # 1. Analyze BSSID (MAC Address) - Strongest Signal (Hardware ID)
    if bssid:
        mac_clean = bssid.upper().replace("-", ":")
        for oui, (vendor, dev_type) in SUSPICIOUS_OUIS.items():
            if mac_clean.startswith(oui):
                return True, f"[{vendor}: {dev_type}]", "HIGH"

    # 2. Analyze SSID - Heuristic Signal
    if ssid:
        s_lower = ssid.lower()
        
        # High Confidence Keywords
        if "axon" in s_lower: return True, "[AXON BODYCAM]", "HIGH"
        if "watchguard" in s_lower: return True, "[WATCHGUARD]", "HIGH"
        if "lpr" in s_lower or "alpr" in s_lower: return True, "[ALPR SYSTEM]", "HIGH"
        
        # Hardware Pattern Matches (Cradlepoint Default: IBR1100-xxx)
        if "ibr" in s_lower and "-" in s_lower:
            return True, "[CRADLEPOINT]", "MED"
        if "airlink" in s_lower:
            return True, "[SIERRA WIRELESS]", "MED"
            
        # Keyword Fuzzy Match
        for kw in SUSPICIOUS_SSIDS:
            if kw in s_lower:
                return True, f"[{kw.upper()}]", "LOW"
    
    return False, "", "NONE"
