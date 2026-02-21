import curses
import time
import math
import threading
import argparse
import sys
import signal
from src.scanner import scan
from src.ui import draw
from src.config import CONFIG
from src.kml import export_kml

# Shared state for thread communication
targets = []
scanning_active = True
seek_history = []

def scan_loop():
    global targets, scanning_active
    interval = CONFIG.get("scan_interval", 2.0)
    
    while scanning_active:
        try:
            new_data = scan()
            if new_data:
                targets = new_data
            time.sleep(interval)
        except Exception as e:
            # In headless mode, we might want to log this error
            pass

def main(stdscr):
    global targets, scanning_active, seek_history
    
    curses.curs_set(0)
    curses.start_color()
    curses.use_default_colors()
    stdscr.nodelay(1)
    
    angle = 0.0
    seek_index = None # None = Radar Mode, Int = Index of target to seek
    
    # Start scanning thread
    scan_thread = threading.Thread(target=scan_loop, daemon=True)
    scan_thread.start()
    
    rotation_speed = CONFIG.get("ui_rotation_speed", 0.1)
    
    try:
        while True:
            try:
                c = stdscr.getch()
            except KeyboardInterrupt:
                break

            if c == ord('q'): break
            
            # K for KML Export
            if c == ord('k'):
                success, msg = export_kml()
                stdscr.attron(curses.A_REVERSE)
                stdscr.addstr(0, 0, f" KML: {msg} "[:40])
                stdscr.attroff(curses.A_REVERSE)
                stdscr.refresh()
                time.sleep(1.0)
            
            # S key toggles Seek Mode (Locks onto strongest threat or first item)
            if c == ord('s'):
                if seek_index is None:
                    # Find best target (Threat first, then strongest)
                    if targets:
                        seek_index = 0 
                        seek_history = [] # Reset history
                else:
                    seek_index = None # Back to Radar
            
            angle += rotation_speed
            if angle > 6.28: angle = 0
            
            # Pass copy of targets to avoid modification during draw if scan updates
            current_targets = list(targets)
            
            # Update history for the active target
            if seek_index is not None:
                # Replicate sort logic from UI to find the correct target
                sorted_targets = sorted(current_targets, key=lambda x: x.signal, reverse=True)
                if seek_index < len(sorted_targets):
                    t = sorted_targets[seek_index]
                    seek_history.append(t.signal)
                    if len(seek_history) > 60: seek_history.pop(0)
            
            draw(stdscr, current_targets, angle, seek_index, seek_history)
            time.sleep(0.05)
            
    finally:
        scanning_active = False
        scan_thread.join(timeout=1.0)

def headless_mode():
    global scanning_active
    print("Starting CivOps in HEADLESS MODE...")
    print("Press Ctrl+C to stop.")
    
    scan_thread = threading.Thread(target=scan_loop, daemon=True)
    scan_thread.start()
    
    try:
        while scanning_active:
            time.sleep(1)
            # Optional: Print status every few seconds
            if targets:
                threat_count = sum(1 for t in targets if t.is_threat)
                mobile_count = sum(1 for t in targets if t.is_mobile)
                print(f"\r[Status] Targets: {len(targets)} | Threats: {threat_count} | Mobile: {mobile_count}", end="")
    except KeyboardInterrupt:
        print("\nStopping...")
    finally:
        scanning_active = False
        scan_thread.join(timeout=2.0)
        print("Clean exit.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CivOps Wifi Scanner")
    parser.add_argument("--headless", action="store_true", help="Run without UI (logging only)")
    args = parser.parse_args()

    if args.headless:
        headless_mode()
    else:
        try:
            curses.wrapper(main)
        except KeyboardInterrupt:
            # Handle Ctrl+C during curses initialization/wrapper
            pass
