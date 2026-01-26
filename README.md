# Ethical Hacking Simulation Walkthrough

## Overview
We have created two Python notebooks and a **Flask Web Application** to simulate an ethical hacking scenario:
1. **Attacker Side**: [notebooks/attacker_simulation.ipynb](file:///c:/Users/John/Desktop/Mini%20project%20cybersec/notebooks/attacker_simulation.ipynb)
2. **Victim Side**: [notebooks/victim_analysis.ipynb](file:///c:/Users/John/Desktop/Mini%20project%20cybersec/notebooks/victim_analysis.ipynb)
3. **Web Interface**: [app.py](file:///c:/Users/John/Desktop/Mini%20project%20cybersec/app.py) (Flask)

## How to Run

### 1. Attacker Simulation
Open [attacker_simulation.ipynb](file:///c:/Users/John/Desktop/Mini%20project%20cybersec/attacker_simulation.ipynb) in your Jupyter environment (e.g., VS Code or Jupyter Lab).
Run all cells. This script will:
- Simulate a **Port Scan** on a dummy target.
- Simulate a **Brute Force** attack on SSH (Port 22).
- Simulate a **DoS Flood** on the Web Server (Port 80).
- **Log all actions** to [network_logs.csv](file:///c:/Users/John/Desktop/Mini%20project%20cybersec/network_logs.csv) in the same directory.

> [!NOTE]
> A sample [network_logs.csv](file:///c:/Users/John/Desktop/Mini%20project%20cybersec/network_logs.csv) has already been generated for you so you can test the victim analysis immediately.

### 2. Victim Analysis
Open [victim_analysis.ipynb](file:///c:/Users/John/Desktop/Mini%20project%20cybersec/victim_analysis.ipynb).
Run all cells. This notebook will:
- Load the [network_logs.csv](file:///c:/Users/John/Desktop/Mini%20project%20cybersec/network_logs.csv) file.
- Perform basic traffic analysis.
- **Detect Threats**:
    - Identify the **DoS attack** by counting request volume.
    - Identify the **Port Scan** by counting unique ports accessed.
    - Identify the **Brute Force** by counting failed login attempts.
- **Visualize** the attacks using charts.

## How to Run (Web Application)

### 1. Start the App
Open a terminal in the project root and run:
```bash
python app.py
```
> [!NOTE]
> You may need to install Flask first: `pip install flask`

### 2. Access the Interface
Open your browser and navigate to: `http://127.0.0.1:5000`

- **Attacker Console** (`/attacker`): Click buttons to launch simulations. You will see the logs updating in the backend.
- **Victim Dashboard** (`/victim`): Refresh the page to see the new logs and any detected alerts (e.g., "DoS Detected").

## Files
- [app.py](file:///c:/Users/John/Desktop/Mini%20project%20cybersec/app.py)
- [notebooks/attacker_simulation.ipynb](file:///c:/Users/John/Desktop/Mini%20project%20cybersec/notebooks/attacker_simulation.ipynb)
- [notebooks/victim_analysis.ipynb](file:///c:/Users/John/Desktop/Mini%20project%20cybersec/notebooks/victim_analysis.ipynb)
- [notebooks/network_logs.csv](file:///c:/Users/John/Desktop/Mini%20project%20cybersec/notebooks/network_logs.csv)
