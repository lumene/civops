import csv
import os
from datetime import datetime

def export_kml(csv_path="logs/intercepts.csv", kml_path="logs/map.kml"):
    """
    Converts the intercepts CSV to a Google Earth KML file.
    """
    if not os.path.exists(csv_path):
        return False, "CSV not found"

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
        with open(csv_path, 'r') as f:
            reader = csv.reader(f)
            headers = next(reader, None) # Skip header
            
            for row in reader:
                if len(row) < 8: continue
                
                # CSV: Timestamp, SSID, BSSID, Signal, Freq, Encryption, Latitude, Longitude, Threat Label, Confidence
                ts, ssid, bssid, signal, freq, enc, lat, lon = row[0], row[1], row[2], row[3], row[4], row[5], row[6], row[7]
                threat_label = row[8] if len(row) > 8 else ""
                
                if not lat or not lon: continue
                
                style = "#normal"
                desc = f"SSID: {ssid}\nBSSID: {bssid}\nSignal: {signal}%\nFreq: {freq}\nTime: {ts}"
                
                if threat_label and threat_label != "UNK":
                    style = "#threat"
                    desc = f"THREAT: {threat_label}\n{desc}"
                
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
            
        return True, f"Exported {kml_path}"
        
    except Exception as e:
        return False, str(e)
