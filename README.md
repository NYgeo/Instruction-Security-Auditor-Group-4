# Linux Security Auditor & Intrusion Detection System
## Group-4 Cybersecurity Project

A comprehensive Linux security tool that performs system audits for misconfigurations and provides real-time intrusion detection monitoring.

## Project Structure

### Files
- `Main.c` - Main menu interface and program entry point
- `Part_1.c` - Security audit functions (misconfiguration scanning)
- `DetectionMonitor.c` - Intrusion detection monitor launcher
- `detection_monitor.sh` - Shell script implementing the monitoring daemon

### Components

## Part 1: Security Auditor

A C program that scans the Linux system for common security misconfigurations and generates a comprehensive security report.

### Features
- **SSH Configuration Check**: Detects weak SSH settings (root login, password authentication)
- **Open Ports Analysis**: Lists listening ports using `ss` or `netstat`
- **World-Writable Files**: Finds files with world-write permissions
- **Empty Password Users**: Identifies users with empty passwords in `/etc/shadow`
- **SUID Binaries Audit**: Lists setuid files (potential security risks)
- **Firewall Status**: Checks UFW/firewalld status
- **File Integrity**: Computes SHA256 hashes of critical system files
- **Risk Scoring**: Assigns risk scores and provides security recommendations

### Risk Scoring System
- SSH issues: +2 points
- Many open ports: +2 points
- World-writable files: +2 points
- Empty passwords: +3 points
- Excessive SUID files: +1 point
- Inactive firewall: +3 points

**Risk Levels:**
- 0-4: LOW RISK
- 5-9: MEDIUM RISK
- 10+: HIGH RISK

## Part 2: Intrusion Detection Monitor

A daemon/service that monitors system logs in real-time for suspicious activities and automatically responds to threats.

### Features
- **Real-time Log Monitoring**: Watches `/var/log/auth.log` and `/var/log/syslog`
- **Failed Login Detection**: Tracks failed SSH login attempts
- **Invalid User Alerts**: Monitors attempts with non-existent usernames
- **Sudo Usage Tracking**: Logs unusual sudo command usage
- **Privilege Escalation Detection**: Identifies su/sudo failure patterns
- **Port Scan Detection**: Uses iptables to log and detect SYN packet floods
- **Auto-Banning**: Automatically blocks repeat offenders via iptables rules
- **Structured Logging**: Records all events to `log.txt` with timestamps

### Auto-Banning Logic
- Tracks violations per IP address
- Bans IPs after reaching configurable threshold (default: 4 violations)
- Updates iptables firewall rules dynamically
- Logs all ban/unban actions

## Installation & Usage

### Prerequisites
- Linux system with standard tools (`ss`, `netstat`, `find`, `grep`, etc.)
- Root privileges for full functionality (log access, iptables)
- GCC compiler for building

### Building
```bash
gcc Main.c Part_1.c DetectionMonitor.c -o security_auditor
```

### Running
```bash
sudo ./security_auditor
```

### Menu Options
1. **Part 1 Audit**: Run the security misconfiguration scan
2. **Part 2 Live Monitor**: Start intrusion detection for 1 minute (demo)
3. **Part 2 Self-Test**: Run automated test with simulated attacks
0. **Exit**: Quit the program

## Part 2 Self-Test

The self-test feature:
- Starts the detection monitor in background
- Injects test events (failed logins, invalid users, port scans)
- Verifies that violations are logged and IPs are banned
- Checks iptables rules and log file
- Automatically stops the monitor

## Security Considerations

- **Run with sudo**: Required for accessing system logs and modifying iptables
- **Log File**: Events are logged to `log.txt` in current directory
- **Iptables Rules**: Bans are added to INPUT chain - review before production use
- **Resource Usage**: File scanning is limited to avoid system impact
- **Timeout Protection**: Long-running commands are timed out to prevent hangs

## Technical Implementation

### Architecture
- **C Frontend**: Menu interface and audit logic
- **Shell Backend**: Monitoring daemon using `tail -F` for log following
- **Process Management**: Proper cleanup and signal handling
- **Cross-Distribution**: Adapts to different log file locations (`auth.log` vs `secure`, `syslog` vs `messages`)

### Key Technologies
- System command execution via `popen()` and `system()`
- Real-time log monitoring with `tail -F`
- Firewall management with `iptables`
- Process groups for clean daemon shutdown
- Rate-limited iptables logging for port scan detection

## Future Enhancements

- File integrity baseline comparison (currently shows hashes only)
- Configurable risk scoring thresholds
- Email/SMS alerts for critical events
- Web-based dashboard
- Integration with SIEM systems
- Support for systemd/journald logging
