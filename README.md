
# 🛡️ Linux Security Auditor (Group 4)

A streamlined security suite for Linux that combines a system configuration audit with a real-time intrusion detection monitor.

## 🚀 Quick Start

```bash
# 1. Compile the suite
gcc Part_1.c Main.c DetectionMonitor.c -o security_auditor

# 2. Run with root privileges
sudo ./security_auditor
```

---

## 🛠️ System Components

### 1. Security Audit (Part 1)
Evaluates the system's security posture by running six essential checks:

| Check | Command/Method | Risk Points |
| :--- | :--- | :--- |
| **SSH Config** | Detects if Root Login is enabled | +2 |
| **Open Ports** | Scans active listeners via `ss -tuln` | +2 |
| **Permissions** | Finds world-writable files (`-perm -0002`) | +2 |
| **Passwords** | Scans `/etc/shadow` for empty passwords | +3 |
| **SUID Files** | Identifies elevated execution files (`-perm -4000`) | +2 |
| **Firewall** | Verifies if `UFW` is active | +3 |

**Risk Levels:** 🟢 **0–4 (Low)** | 🟡 **5–9 (Medium)** | 🔴 **10+ (High)**

### 2. Intrusion Detection (Part 2)
A continuous background monitor that tracks:
* **Brute-Force Detection:** Monitors for repeated failed login attempts.
* **Unauthorized Access:** Flags suspicious `sudo` activity.
* **Incident Logging:** Records all alerts to `log.txt` for review.

---

## 🕹️ User Menu

Once launched, the program provides the following interactive options:

1.  **Run Audit:** Performs the 6-point scan, calculates the risk score, and provides fixes.
2.  **Start Monitor:** Activates the real-time log watcher (press `Ctrl+C` to stop).
3.  **Self-Test:** Automated verification that injects test events using `logger` and confirms detection.

---

## 🧪 Self-Test Workflow
The automated self-test (Option 3) validates the system by:
1.  Launching the **Detection Monitor** in the background.
2.  Injecting simulated attack signatures into the system logs via `logger`.
3.  Verifying the monitor correctly writes these events to `log.txt`.
4.  Cleaning up test processes and logs automatically.

---

## ⚙️ Implementation Standards
* **Lightweight:** Uses `system()` and `popen()` for efficient command execution.
* **Single File Logic:** Built to be easily readable without complex dependencies.
* **Actionable:** Every warning is paired with a specific fix in the final report.

-----------------------------------

A command-line C program that scans a Linux system for common security misconfigurations, evaluates risk, and generates a structured security report with actionable recommendations.

Simple Linux Security Audit Tool (Single File)
1. Goal

A single C program that:

Runs a few Linux commands
Prints results
Assigns a basic risk score
Shows quick recommendations
2. Program Flow (Very Simple)
Start
  ↓
Run checks (one by one)
  ↓
Add to risk score if issue found
  ↓
Print results
  ↓
Print final score + fixes
End
3. 🔍 Checks (Minimal Set)

Just include these 6 simple checks:

SSH config
Check if root login is enabled
Open ports
Run ss -tuln
World-writable files
find / -perm -0002
Empty passwords
Check /etc/shadow
SUID files
find / -perm -4000
Firewall
Check if UFW is active
4. Code Structure (All in One File)
main()
 ├── check_ssh()
 ├── check_ports()
 ├── check_world_writable()
 ├── check_passwords()
 ├── check_suid()
 ├── check_firewall()
 ├── print_score()
 └── print_recommendations()
5. ⚖️ Simple Risk Scoring

Keep it basic:

+2 → SSH issues
+2 → Open ports
+2 → World-writable files
+3 → Empty passwords
+2 → SUID files
+3 → No firewall
Risk Levels:
0–4 → Low
5–9 → Medium
10+ → High
6. 🖥️ Output Format (Simple)

Example:

==== Security Audit ====

[SSH]
WARNING: Root login enabled

[Ports]
(list of ports)

[Firewall]
WARNING: Not active

==== RESULT ====
Risk Score: 8 (MEDIUM)

==== FIXES ====
- Disable root SSH login
- Enable firewall
- Remove world-writable files
7. ⚙️ Implementation Rules (Keep It Simple)
Use:
system() → for quick checks
popen() → if you want output
Don’t over-parse output
Don’t store data in files (optional)
Just print everything
8.  Minimal Features Only

DO:

Print results
Increment score
Show fixes

DON’T:

Build modules
Use complex parsing
Add networking or APIs
Over-engineer
9. How to Run (current repo)

Compile:

```bash
gcc Part_1.c Main.c DetectionMonitor.c -o security_auditor
```

Run:

```bash
sudo ./security_auditor
```

Part 2 note:
- `Option 2` runs `./detection_monitor.sh` (keep that script in the same directory as `security_auditor`)

Menu options:
- 1: Run Part 1 audit
- 2: Run Part 2 intrusion detection monitor (continuous)
- 3: Run Part 2 self-test (starts monitor, injects test events with `logger`, checks `log.txt` + iptables, then stops monitor)
