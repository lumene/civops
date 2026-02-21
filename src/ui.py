import curses
import math
import time

def draw(stdscr, targets, radar_angle, selected_target_index=None):
    stdscr.clear()
    h, w = stdscr.getmaxyx()
    cy, cx = h // 2, w // 2
    max_radius = min(h, w) // 2 - 2

    # Colors
    curses.init_pair(1, curses.COLOR_CYAN, -1)  # HUD
    curses.init_pair(2, curses.COLOR_GREEN, -1) # Radar
    curses.init_pair(3, curses.COLOR_RED, -1)   # Threat
    curses.init_pair(4, curses.COLOR_YELLOW, -1) # Seek Mode
    
    # Sort targets for selection logic (Strongest first usually best)
    sorted_targets = sorted(targets, key=lambda x: x.signal, reverse=True)
    active_target = None
    if selected_target_index is not None and selected_target_index < len(sorted_targets):
        active_target = sorted_targets[selected_target_index]

    # --- MODE: SEEKER (Geiger Counter) ---
    if active_target:
        stdscr.attron(curses.color_pair(4) | curses.A_BOLD)
        stdscr.border()
        stdscr.addstr(0, 2, " SEEKER MODE // SIGNAL LOCK ", curses.A_REVERSE)
        
        # Target Info
        stdscr.addstr(2, 4, f"TARGET: {active_target.ssid}")
        stdscr.addstr(3, 4, f"MAC:    {active_target.bssid}")
        stdscr.addstr(4, 4, f"BAND:   {active_target.freq}")
        stdscr.addstr(5, 4, f"TYPE:   {active_target.threat_label or 'UNKNOWN'}")
        
        # Giant Signal Bar
        bar_width = w - 8
        fill = int((active_target.signal / 100.0) * bar_width)
        stdscr.addstr(8, 4, f"SIGNAL: {active_target.signal}%")
        stdscr.addstr(9, 4, "[" + "#" * fill + "-" * (bar_width - fill) + "]")
        
        # Distance Hint (Physics)
        dist_hint = "FAR"
        if active_target.signal > 60: dist_hint = "NEAR"
        if active_target.signal > 80: dist_hint = "IMMEDIATE PROXIMITY"
        if active_target.freq == "5G" and active_target.signal > 60: dist_hint = "VERY CLOSE (5GHz)"
        
        stdscr.addstr(11, 4, f"PROXIMITY ESTIMATE: {dist_hint}", curses.A_BLINK if active_target.signal > 80 else 0)
        
        stdscr.addstr(h-2, 4, "[S] RETURN TO RADAR", curses.A_DIM)
        stdscr.refresh()
        return

    # --- MODE: RADAR ---
    
    # HUD
    stdscr.attron(curses.color_pair(1))
    stdscr.border()
    stdscr.addstr(0, 2, " S0PHIA CIVOPS // RECON V3 ", curses.A_BOLD)
    stdscr.addstr(h-1, 2, "[S] SEEK MODE  [Q] QUIT", curses.A_BOLD)
    
    # Sweep
    lx = int(cx + math.cos(radar_angle) * max_radius * 2)
    ly = int(cy + math.sin(radar_angle) * max_radius)
    for i in range(1, int(max_radius)):
        rx = int(cx + math.cos(radar_angle) * i * 2)
        ry = int(cy + math.sin(radar_angle) * i)
        if 0 < ry < h-1 and 0 < rx < w-1:
            stdscr.addch(ry, rx, '.', curses.color_pair(2))

    # Targets
    for t in targets:
        tx = int(cx + math.cos(t.angle) * t.dist * max_radius * 2)
        ty = int(cy + math.sin(t.angle) * t.dist * max_radius)
        
        if 0 < ty < h-1 and 0 < tx < w-1:
            color = curses.color_pair(2)
            char = 'O'
            if t.freq == "5G": char = '+' # 5GHz Symbol
            
            if t.is_threat:
                color = curses.color_pair(3) | curses.A_BOLD
                if t.confidence == "HIGH": color = color | curses.A_BLINK
                char = '!'
            
            # Draw
            stdscr.addch(ty, tx, char, color)
            
            # Label if swept
            angle_diff = abs((radar_angle - t.angle + math.pi) % (2*math.pi) - math.pi)
            if angle_diff < 0.3:
                label = t.ssid[:10]
                if t.is_threat: label = f"{t.threat_label} {t.ssid}"
                stdscr.addstr(ty, tx+1, label, color)

    # Sidebar Log
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
            
            # Band info in list
            band_mk = "5G" if t.freq == "5G" else "2G"
            
            row_str = f"{prefix}[{band_mk}] {t.signal}% {t.ssid[:12]}"
            stdscr.addstr(2+i, list_x, row_str, color)

    stdscr.refresh()
