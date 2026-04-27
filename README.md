
# 🛡️ Linux Security Auditor (Group 4)

A lightweight C-based security suite that combines a **System Audit** with a **Real-Time Intrusion Monitor**.

## 🚀 Quick Start
```bash
# 1. Compile
gcc Part_1.c Main.c DetectionMonitor.c -o security_auditor

# 2. Run
sudo ./security_auditor
```

---

## 🛠️ Main Features

### 1. Security Audit (Part 1)
Scans for common misconfigurations and provides a **Risk Score**:
* **SSH Check:** Verifies if root login is disabled.
* **Port Scan:** Lists all active listening ports.
* **Permission Audit:** Finds world-writable and SUID files.
* **Account Security:** Checks for empty passwords in `/etc/shadow`.
* **Firewall Status:** Confirms if `ufw` is active.

### 2. Intrusion Detection (Part 2)
A background monitor that watches system logs for:
* **Failed Logins:** Multiple unsuccessful password attempts.
* **Sudo Abuse:** Unauthorized attempts to use root privileges.
* **Auto-Logging:** Saves all suspicious events to `log.txt`.

---

## 🕹️ Menu Options
When you run the program, choose from the following:

| Option | Action | Description |
| :--- | :--- | :--- |
| **1** | **Run Audit** | Performs the 6-point scan and shows the risk level. |
| **2** | **Start Monitor** | Starts the live log watcher (press Ctrl+C to stop). |
| **3** | **Self-Test** | **Automated:** Injects test logs and verifies if the tool sees them. |

---

## 🧪 How the Self-Test Works
The self-test (Option 3) is designed to prove the tool works without needing a real hacker:
1.  **Starts** the monitor in the background.
2.  **Simulates** an attack using the `logger` command.
3.  **Verifies** that the attack was caught and written to `log.txt`.
4.  **Cleans up** all test data and processes.

---

## 📋 Requirements
* **OS:** Linux (Ubuntu/Debian preferred).
* **Compiler:** `gcc`.
* **Privileges:** Must run with `sudo` to access system security files

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

Menu options:
- 1: Run Part 1 audit
- 2: Run Part 2 intrusion detection monitor (continuous)
- 3: Run Part 2 self-test (starts monitor, injects test events with `logger`, checks `log.txt` + iptables, then stops monitor)
