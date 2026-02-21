import curses
import time
import math
import threading
from src.scanner import scan
from src.ui import draw
from src.config import CONFIG

# Shared state for thread communication
targets = []
scanning_active = True

def scan_loop():
    global targets, scanning_active
    interval = CONFIG.get("scan_interval", 2.0)
    
    while scanning_active:
        new_data = scan()
        if new_data:
            targets = new_data
        time.sleep(interval)

def main(stdscr):
    global targets, scanning_active
    
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
            c = stdscr.getch()
            if c == ord('q'): break
            
            # S key toggles Seek Mode (Locks onto strongest threat or first item)
            if c == ord('s'):
                if seek_index is None:
                    # Find best target (Threat first, then strongest)
                    if targets:
                        seek_index = 0 
                else:
                    seek_index = None # Back to Radar
            
            angle += rotation_speed
            if angle > 6.28: angle = 0
            
            # Pass copy of targets to avoid modification during draw if scan updates
            current_targets = list(targets)
            draw(stdscr, current_targets, angle, seek_index)
            time.sleep(0.05)
            
    finally:
        scanning_active = False
        scan_thread.join(timeout=1.0)

if __name__ == "__main__":
    try:
        curses.wrapper(main)
    except KeyboardInterrupt:
        pass
