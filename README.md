# ARY CAM HONEYPOT

### Advanced CCTV Honeypot for Ethical Security Research

**Made by Aryan Giri**

---

## 📌 Overview

ARY CAM HONEYPOT is a high-interaction fake CCTV system designed to capture attacker behavior, log malicious payloads, detect brute-forcing, mimic real IP cameras (ONVIF + RTSP-like streaming), and provide detailed forensic logs — while staying lightweight and fully local.

Created for ethical cybersecurity research, red teaming practice, and attacker behavior analysis.

---

## 🔥 Key Features

### 🎥 Fake CCTV Streaming

* Streams a looping `.mp4` video feed
* Supports custom camera feed selection
* Snapshot `.jpg` endpoint
* Real camera-like behaviour

### 📡 ONVIF Device Emulation

* `/onvif/device_service` returns real-looking XML
* Mimics a standard IP camera service
* Fool scanners & IoT exploit tools

### 🚨 Attack Detection

* Brute-force detection
* Rapid-scan detection
* Malicious payload signatures:

  * XSS
  * SQLi
  * LFI
  * RCE
  * Log4Shell
  * Webshell patterns

### 🔍 Full Request Capture

Every attack request is stored in `detailed_logs/` with:

* Headers
* Cookies
* GET/POST data
* Timestamp
* Method
* Endpoint

### 🌍 Offline GeoIP Lookup

* Uses `GeoLite2-City.mmdb`
* No external APIs
* Fully local attacker location enrichment

### 🗂 File-Based Logging System

* `logs.txt` → all visits
* `malicious.txt` → detected attacks
* `detailed_logs/` → per-request JSON logs

### 🖥 Admin Interface

* Hidden dashboard under a custom secret path
* View malicious logs
* Download detailed logs
* Stats + GeoIP + Top attackers

### ⚙️ Fully Configurable

At startup, the user can set:

* Admin username/password
* Random or custom dashboard path
* Port
* Banner text
* Whether to enable/disable RTSP endpoint
* Path to video feed `.mp4`
* Path to snapshot `.jpg`
* All with defaults when Enter is pressed

### 🖥 Works on Both Linux & Windows

* Auto-path handling
* Colorama ensures full color support everywhere

---

---

## 🚀 Installation

### 1️⃣ Install dependencies

```
pip install -r requirements.txt
```

### 2️⃣ Run the honeypot

```
python main.py
```

### 3️⃣ Configure live from terminal

* Enter credentials
* Choose port
* Choose feed file or accept default
* Enable or disable RTSP mode
* Auto-creates missing directories and files

---

## 🛡 Disclaimer

This honeypot is for **ethical research only**.
Do not expose it to networks without permission.
Unauthorized monitoring or trapping attackers is illegal in many regions — use responsibly.

---

## 🏆 Credits

**Developed by: Aryan Giri**
