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
4. For audio alerts, ensure `termux-tts-speak` is working (may require TTS engine install).

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
- **V7 Automotive Edition**:
  - **High-Contrast Dashboard**: Run with `--car` for a driver-focused UI.
  - **Voice Alerts**: TTS announcements for critical threats.
  - **Pacing Detection**: Warns if a signal is persistently following you at speed.
  - **SQLite Logging**: High-performance database storage (`logs/civops.db`).
- Offline-first.

## Usage

```bash
# Standard Radar Mode
python main.py

# Car Mode (High Contrast + Big Text)
python main.py --car

# Headless (Logging only)
python main.py --headless
```
