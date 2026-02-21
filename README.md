# S0PHIA CIVOPS

A Termux-native reconnaissance radar for Android (and Linux).

## Installation

### Android (Termux)
1. Install Termux and Termux:API from F-Droid.
2. In Termux:
   ```bash
   pkg update
   pkg install python termux-api git
   git clone https://github.com/YOUR_USERNAME/civops.git
   cd civops
   python main.py
   ```
3. Grant "Location" permission to the Termux:API app in Android settings.

### Linux (Desktop)
1. Install requirements:
   ```bash
   sudo apt install network-manager python3
   ```
2. Run:
   ```bash
   sudo python3 main.py
   ```
   (Sudo needed for `nmcli` scanning in some distros).

## Features
- Real-time Wi-Fi radar HUD.
- Auto-detection of "Suspicious" SSIDs (Police, Bodycams, Surveillance).
- Offline-first.
