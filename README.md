# Ethical Hacking Simulation: Student Data System

A comprehensive cyber-range simulation featuring a **Vulnerable Student Data App** (Victim), a **Security Operations Center** (SOC), and an **Attacker Console**. This project demonstrates real-world web attacks (SQLi, XSS, RCE) and their detection in a controlled environment.

## 🚀 Quick Start

1.  **Install Dependencies**:
    ```bash
    pip install flask requests
    ```

2.  **Run the Application**:
    ```bash
    python app.py
    ```

3.  **Access the Components**:
    *   **🏠 Landing Page**: [http://127.0.0.1:5000/](http://127.0.0.1:5000/)
    *   **🏫 Student Portal (Victim)**: [http://127.0.0.1:5000/portal/login](http://127.0.0.1:5000/portal/login)
    *   **🛡️ SOC Dashboard**: [http://127.0.0.1:5000/soc/](http://127.0.0.1:5000/soc/)
    *   **⚔️ Attacker Console**: [http://127.0.0.1:5000/attacker/](http://127.0.0.1:5000/attacker/)

---

## 🏗️ Architecture

The project is modularized into three core Flask Blueprints:

### 1. The Victim: Student Data App (`/portal`)
A fully functional "School Records System" backed by a **SQLite database** (`students.db`).
*   **Features**: Login, Student Search, Grade Dashboard.
*   **Vulnerabilities**:
    *   **SQL Injection (SQLi)**: The Login page (`/portal/login`) allows bypassing authentication using payloads like `' OR 1=1 --`.
    *   **Cross-Site Scripting (XSS)**: The Search page (`/portal/search`) reflects user input without sanitization.
    *   **Broken Authentication**: Weak internal logic.

### 2. The Defense: SOC Dashboard (`/soc`)
A real-time monitoring dashboard for the Security Team.
*   **IDS (Intrusion Detection System)**: Monitors all network traffic hitting the Student App.
*   **Signatures**: Detects SQLi, XSS, and RCE patterns in payloads.
*   **Anomaly Detection**: Flags DoS attacks (high request volume) and Brute Force attempts (repeated login failures).
*   **Alerts**: Displays interactive, dismissible alerts for active threats.

### 3. The Offense: Attacker Console (`/attacker`)
A remote control panel for launching attacks.
*   **Targeting**: Points to the IP of the Victim machine (default: `127.0.0.1`).
*   **Capabilities**:
    *   **Network Recon**: Scans ports and fingerprints services (e.g., User-Agent detection).
    *   **Brute Force**: Automated dictionary attacks against the Login Portal.
    *   **Exploits**: Auto-injects SQLi and XSS payloads into the vulnerable forms.

---

## 📂 Project Structure

```text
.
├── app.py                  # Main entry point & Middleware logging
├── database.py             # SQLite setup and mock data generation
├── utils.py                # shared logging and Threat Detection logic
├── routes/                 # Blueprints for each component
│   ├── victim.py           # Student Portal logic (Vulnerable)
│   ├── soc.py              # Dashboard logic
│   └── attacker.py         # Attack simulation logic
├── templates/              # HTML Frontend (Tailwind CSS)
│   ├── portal/             # Login.html, Search.html, Dashboard.html
│   ├── victim.html         # SOC Dashboard
│   └── attacker.html       # Attacker Console
└── notebooks/              # Logs and Data Analysis
    └── network_logs.csv    # Central log repository
```

## 🛠️ Requirements
*   Python 3.x
*   Flask
*   Requests
