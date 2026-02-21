import curses
import math
import time

def draw(stdscr, targets, radar_angle, selected_target_index=None, signal_history=None, car_mode=False):
    if signal_history is None: signal_history = []
    
    stdscr.clear()
    h, w = stdscr.getmaxyx()
    cy, cx = h // 2, w // 2
    max_radius = min(h, w) // 2 - 2

    curses.init_pair(1, curses.COLOR_CYAN, -1)
    curses.init_pair(2, curses.COLOR_GREEN, -1)
    curses.init_pair(3, curses.COLOR_RED, -1)
    curses.init_pair(4, curses.COLOR_YELLOW, -1)
    
    sorted_targets = sorted(targets, key=lambda x: x.signal, reverse=True)
    active_target = None
    if selected_target_index is not None and selected_target_index < len(sorted_targets):
        active_target = sorted_targets[selected_target_index]
    
    # --- MODE: CAR (HIGH CONTRAST) ---
    if car_mode:
        # Find the most dangerous target
        threats = [t for t in targets if t.is_threat]
        pacing = [t for t in targets if getattr(t, 'is_pacing', False)]
        
        primary_target = None
        status_color = curses.color_pair(2)
        status_text = "SECURE"
        
        if pacing:
            primary_target = pacing[0]
            status_color = curses.color_pair(4) | curses.A_BOLD | curses.A_BLINK
            status_text = "PACING DETECTED"
        elif threats:
            # Sort threats by signal
            threats.sort(key=lambda x: x.signal, reverse=True)
            primary_target = threats[0]
            status_color = curses.color_pair(3) | curses.A_BOLD
            status_text = "THREAT DETECTED"
        
        # Draw Big Status Bar
        stdscr.attron(status_color)
        stdscr.addstr(1, 2, status_text.center(w-4))
        stdscr.attroff(status_color)
        
        if primary_target:
            # Huge Signal Bar
            sig_str = f"{primary_target.signal}%"
            stdscr.addstr(4, 2, sig_str, curses.A_BOLD | curses.A_REVERSE)
            
            # Info
            stdscr.addstr(6, 2, f"SSID: {primary_target.ssid[:20]}")
            stdscr.addstr(7, 2, f"VEND: {primary_target.vendor[:20]}")
            stdscr.addstr(8, 2, f"TYPE: {primary_target.threat_label}")
            
            if getattr(primary_target, 'is_pacing', False):
                 stdscr.addstr(10, 2, "!!! VEHICLE FOLLOWING !!!", curses.color_pair(4) | curses.A_BOLD)
        else:
            stdscr.addstr(cy, cx-5, "SCANNING...", curses.A_DIM)
            
        stdscr.refresh()
        return

    # --- MODE: SEEKER ---
    if active_target:
        stdscr.attron(curses.color_pair(4) | curses.A_BOLD)
        stdscr.border()
        stdscr.addstr(0, 2, " SEEKER MODE // SIGNAL LOCK ", curses.A_REVERSE)
        
        stdscr.addstr(2, 4, f"TARGET: {active_target.ssid}")
        stdscr.addstr(3, 4, f"MAC:    {active_target.bssid}")
        stdscr.addstr(4, 4, f"BAND:   {active_target.freq}")
        stdscr.addstr(5, 4, f"TYPE:   {active_target.threat_label or 'UNKNOWN'}")
        
        # Visual Audio Bar (Geiger Style)
        # Represents "clicks" - density increases with signal
        # We'll use a random-looking pattern that regenerates based on signal intensity
        click_density = int(active_target.signal / 5) # 0-20
        clicks = ""
        import random
        for _ in range(40):
            if random.randint(0, 20) < click_density:
                clicks += "|"
            else:
                clicks += " "
        
        stdscr.addstr(7, 4, "AUDIO: [" + clicks + "]")

        # Main Signal Bar
        bar_width = w - 8
        fill = int((active_target.signal / 100.0) * bar_width)
        stdscr.addstr(8, 4, f"SIGNAL: {active_target.signal}%")
        stdscr.addstr(9, 4, "[" + "#" * fill + "-" * (bar_width - fill) + "]")
        
        # Tracked Target Persistent History
        # Simple ASCII sparkline
        hist_width = min(60, w - 20)
        recent = signal_history[-hist_width:]
        spark = ""
        for val in recent:
            if val < 25: spark += "_"
            elif val < 50: spark += "."
            elif val < 75: spark += "-"
            else: spark += "^"
        
        stdscr.addstr(10, 4, f"TRACK: {spark}")
        
        # Distance Math
        dist_m = getattr(active_target, 'dist_m', 0.0)
        dist_str = f"{dist_m}m" if dist_m > 0 else "CALCULATING..."
        stdscr.addstr(12, 4, f"EST. DISTANCE: {dist_str}", curses.A_BOLD)
        
        stdscr.addstr(h-2, 4, "[S] RETURN TO RADAR", curses.A_DIM)
        stdscr.refresh()
        return

    # --- MODE: RADAR ---
    
    stdscr.attron(curses.color_pair(1))
    stdscr.border()
    stdscr.addstr(0, 2, " S0PHIA CIVOPS // RECON V5 ", curses.A_BOLD)
    stdscr.addstr(h-1, 2, "[S] SEEK MODE  [K] EXPORT KML  [Q] QUIT", curses.A_BOLD)
    
    lx = int(cx + math.cos(radar_angle) * max_radius * 2)
    ly = int(cy + math.sin(radar_angle) * max_radius)
    for i in range(1, int(max_radius)):
        rx = int(cx + math.cos(radar_angle) * i * 2)
        ry = int(cy + math.sin(radar_angle) * i)
        if 0 < ry < h-1 and 0 < rx < w-1:
            stdscr.addch(ry, rx, '.', curses.color_pair(2))

    for t in targets:
        tx = int(cx + math.cos(t.angle) * t.dist * max_radius * 2)
        ty = int(cy + math.sin(t.angle) * t.dist * max_radius)
        
        if 0 < ty < h-1 and 0 < tx < w-1:
            color = curses.color_pair(2)
            char = 'O'
            if t.freq == "5G": char = '+' 
            
            if t.is_threat:
                color = curses.color_pair(3) | curses.A_BOLD
                if t.confidence == "HIGH": color = color | curses.A_BLINK
                char = '!'
            
            stdscr.addch(ty, tx, char, color)
            
            angle_diff = abs((radar_angle - t.angle + math.pi) % (2*math.pi) - math.pi)
            if angle_diff < 0.3:
                label = t.ssid[:10]
                if t.is_threat: label = f"{t.threat_label} {t.ssid}"
                stdscr.addstr(ty, tx+1, label, color)

    list_x = w - 35
    if list_x > cx + 15:
        stdscr.addstr(1, list_x, "/// LIVE FEED ///", curses.A_UNDERLINE)
        for i, t in enumerate(sorted_targets[:h-4]):
            color = curses.color_pair(2)
            prefix = "   "
            if t.is_threat:
                color = curses.color_pair(3) | curses.A_BOLD
                prefix = "!  "
            if selected_target_index == i:
                prefix = "-> "
                color = color | curses.A_REVERSE
            
            band_mk = "5G" if t.freq == "5G" else "2G"
            
            row_str = f"{prefix}[{band_mk}] {t.signal}% {t.ssid[:12]}"
            stdscr.addstr(2+i, list_x, row_str, color)

    stdscr.refresh()
