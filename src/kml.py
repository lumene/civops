import sqlite3
import os
from datetime import datetime
from .config import CONFIG

def export_kml(kml_path="logs/map.kml"):
    """
    Converts the intercepts SQLite DB to a Google Earth KML file.
    """
    db_path = CONFIG.get("log_file", "logs/civops.db").replace(".csv", ".db")
    
    if not os.path.exists(db_path):
        return False, "Database not found"

    kml_header = """<?xml version="1.0" encoding="UTF-8"?>
<kml xmlns="http://www.opengis.net/kml/2.2">
<Document>
    <name>CivOps Intercepts</name>
    <Style id="threat">
        <IconStyle>
            <color>ff0000ff</color>
            <scale>1.2</scale>
            <Icon>
                <href>http://maps.google.com/mapfiles/kml/shapes/caution.png</href>
            </Icon>
        </IconStyle>
    </Style>
    <Style id="mobile">
        <IconStyle>
            <color>ff00ffff</color>
            <scale>1.0</scale>
            <Icon>
                <href>http://maps.google.com/mapfiles/kml/shapes/motorcycling.png</href>
            </Icon>
        </IconStyle>
    </Style>
    <Style id="normal">
        <IconStyle>
            <color>ff00ff00</color>
            <scale>0.8</scale>
            <Icon>
                <href>http://maps.google.com/mapfiles/kml/shapes/placemark_circle.png</href>
            </Icon>
        </IconStyle>
    </Style>
"""
    kml_footer = """</Document>
</kml>
"""
    
    placemarks = ""
    
    try:
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        # id, timestamp, ssid, bssid, vendor, signal, freq, encryption, lat, lon, threat_label, confidence, is_mobile
        c.execute("SELECT timestamp, ssid, bssid, vendor, signal, freq, lat, lon, threat_label, is_mobile FROM intercepts WHERE lat IS NOT NULL AND lon IS NOT NULL")
        rows = c.fetchall()
        conn.close()
        
        for row in rows:
            ts, ssid, bssid, vendor, signal, freq, lat, lon, threat_label, is_mobile = row
            
            if not lat or not lon: continue
            
            style = "#normal"
            desc = f"SSID: {ssid}\nBSSID: {bssid}\nVendor: {vendor}\nSignal: {signal}%\nFreq: {freq}\nTime: {ts}"
            
            if threat_label and threat_label != "UNK":
                style = "#threat"
                desc = f"THREAT: {threat_label}\n{desc}"
            elif is_mobile == "YES":
                style = "#mobile"
                desc = f"MOBILE TARGET\n{desc}"
            
            placemarks += f"""
    <Placemark>
        <name>{ssid}</name>
        <description>{desc}</description>
        <styleUrl>{style}</styleUrl>
        <Point>
            <coordinates>{lon},{lat},0</coordinates>
        </Point>
    </Placemark>
"""
        
        with open(kml_path, 'w') as f:
            f.write(kml_header + placemarks + kml_footer)
            
        return True, f"Exported {len(rows)} points to {kml_path}"
        
    except Exception as e:
        return False, str(e)
