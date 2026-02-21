import curses
import time
import math
from src.scanner import scan
from src.ui import draw

def main(stdscr):
    curses.curs_set(0)
    curses.start_color()
    curses.use_default_colors()
    stdscr.nodelay(1)
    
    targets = []
    angle = 0.0
    last_scan = 0
    seek_index = None # None = Radar Mode, Int = Index of target to seek
    
    while True:
        c = stdscr.getch()
        if c == ord('q'): break
        
        # S key toggles Seek Mode (Locks onto strongest threat or first item)
        if c == ord('s'):
            if seek_index is None:
                # Find best target (Threat first, then strongest)
                # Sort logic mirrors UI: Strongest signal first
                # But we want to prefer threats if signal is decent
                if targets:
                    seek_index = 0 
            else:
                seek_index = None # Back to Radar
        
        # Scan Interval
        if time.time() - last_scan > 2.0:
            new_data = scan()
            if new_data: targets = new_data
            last_scan = time.time()
            
        angle += 0.1
        if angle > 6.28: angle = 0
        
        draw(stdscr, targets, angle, seek_index)
        time.sleep(0.05)

if __name__ == "__main__":
    try:
        curses.wrapper(main)
    except KeyboardInterrupt:
        pass
