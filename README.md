# 🛡️ Linux Security Auditor (Group 4)

A command-line C project that performs a Linux security audit (Part 1) and runs a lightweight intrusion detection monitor (Part 2), then reports risk and recommended fixes.

**Goal:** A single program that:
- Runs practical Linux security checks
- Prints clear findings
- Assigns a basic risk score
- Provides quick remediation guidance

## 🚀 Quick Start

```bash
# 1) Compile
gcc Part_1.c Main.c DetectionMonitor.c -o security_auditor

# 2) Run (sudo is recommended for full checks/monitoring)
sudo ./security_auditor
```

---

**Program Flow**

Start
  ↓
Choose mode from menu
  ↓
Run Part 1 audit OR Part 2 monitor/self-test
  ↓
Collect findings and risk signals
  ↓
Print report/log output

**End**

---

## 🛠️ System Components

### 1. Security Audit (Part 1)
`runPart1Audit()` executes these checks:

| Check | Command/Method | Risk Behavior |
| :--- | :--- | :--- |
| **SSH Config** | Greps `PermitRootLogin` / `PasswordAuthentication` in `/etc/ssh/sshd_config` | Adds **+2** for weak settings |
| **Open Ports** | Uses `ss -tuln` (fallback `netstat -tuln`) | Adds **+2** if many listening ports are found |
| **World-Writable Files** | `find / -xdev -type f -perm -0002` (bounded with `timeout`) | Adds **+2** when any are found |
| **Empty Passwords** | Scans `/etc/shadow` for blank password fields | Adds **+3** when any user is found |
| **SUID Files** | `find / -xdev -perm -4000` (bounded with `timeout`) | Adds **+1** only for unusually high count |
| **Firewall Status** | Checks `ufw` / `firewall-cmd` state | Adds **+3** if UFW is inactive |
| **File Integrity Snapshot** | `sha256sum` on key files (`/etc/passwd`, `/etc/shadow`, SSH config) | Informational output |

**Risk Levels (from current code):**
- `0`: SAFE
- `1-4`: LOW RISK
- `5-9`: MEDIUM RISK
- `10+`: HIGH RISK

### 2. Intrusion Detection (Part 2)
`runDetectionMonitor()` delegates to `detection_monitor.sh`, which:
- Monitors auth logs (`/var/log/auth.log` or `/var/log/secure`)
- Monitors system logs (`/var/log/syslog` or `/var/log/messages`) for `IPTABLES:` events
- Writes events to `log.txt`
- Tracks repeated events per IP and bans offenders with `iptables -I INPUT -s <ip> -j DROP`
- Uses threshold `THRESH=4` by default (configurable via env var)

---

## 🕹️ User Menu

When `security_auditor` starts, the menu is:

1. **Part 1** - Run the full security audit and print the report
2. **Part 2 Live Logs (1 minute)** - Start monitor, stream for 60 seconds, auto-stop
3. **Part 2 Self-Test (skip live logs)** - Start monitor, inject test events, verify results, stop monitor
0. **Exit**

> Part 2 options require root privileges to read logs and manage `iptables`.

---

## 🧪 Self-Test Workflow

Option 3 currently does the following:
1. Starts the detection monitor in a background process group.
2. Injects simulated auth + iptables-style events (4 rounds) for test IP `10.9.8.7` using `logger`.
3. Prints recent `log.txt` entries (`tail -n 25`).
4. Checks whether the test IP is banned in iptables (`BANNED` / `NOT BANNED`).
5. Stops the monitor and exits cleanly.

---

## ⚙️ Implementation Notes

- The project intentionally uses simple C patterns (`system()`, `popen()`) for readability.
- Long-running log monitoring logic is kept in `detection_monitor.sh`.
- Part 1 scan commands are bounded where needed (`timeout`) to reduce hangs.
- Output is report-first and terminal-friendly (no external services/APIs required).

## 📦 Current Repo Run Notes

- Keep `detection_monitor.sh` in the same directory as the compiled `security_auditor` binary.
