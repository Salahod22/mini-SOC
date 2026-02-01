# Ethical Hacking Simulation

A comprehensive simulation environment featuring a **Flask Web Application** and analysis notebooks. This project demonstrates network attacks and defense analysis in a controlled, safe environment.

## 🚀 Quick Start (Web App)

The core of the project is the interactive Web Application.

1.  **Run the App**:
    ```bash
    python app.py
    ```
2.  **Access the Dashboard**:
    Open [http://127.0.0.1:5000/victim](http://127.0.0.1:5000/victim)
3.  **Access the Attacker Console**:
    Open [http://127.0.0.1:5000/attacker](http://127.0.0.1:5000/attacker)

---

## 🛡️ Features

### 1. Attacker Console (`/attacker`)
Simulate real-world attacks with a click of a button.
*   **DoS Flood**: customizable packet count (default: 50). Triggers "DoS Detected" alerts.
*   **Brute Force**: Simulates failed login attempts. Triggers "Brute Force Detected" alerts.
*   **SQL Injection (SQLi)**: Sends payloads like `' OR 1=1`.
*   **XSS**: Sends script injection payloads.
*   **Command Injection (RCE)**: Simulates unauthorized shell commands.

### 2. Victim Dashboard (SOC) (`/victim`)
A real-time Security Operations Center (SOC) dashboard.
*   **Live Traffic Log**: Auto-updating table of network requests.
*   **Interactive Alerts**: Red warning cards appear when threats are detected.
    *   **Persistent State**: Dismissed alerts stay dismissed unless a *new* attack occurs.
    *   **Smart IDs**: DoS alerts don't reappear when you launch SQLi, and vice versa.
*   **Threat Detection IDS**:
    *   **Signature Based**: Detects SQLi, XSS, and RCE patterns in logs.
    *   **Anomaly Based**: Detects DoS (volume) and Brute Force (failure count) anomalies.

### 3. Notebooks
For offline analysis and data science:
*   `notebooks/attacker_simulation.ipynb`: Scripted attacks without the Web UI.
*   `notebooks/victim_analysis.ipynb`: Data analysis and visualization of `network_logs.csv`.

---

## 📂 File Structure
*   `app.py`: The Flask backend and IDS logic.
*   `templates/`: HTML for the Attacker and Victim views (Tailwind CSS).
*   `notebooks/`: Jupyter notebooks and the `network_logs.csv` database.

## 📋 Requirements
*   Python 3.x
*   Flask (`pip install flask`)
*   Pandas (for notebooks)
