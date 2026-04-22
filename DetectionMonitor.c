#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

void runDetectionMonitor(void) {
    printf("Starting Detection Monitor...\n");
    printf("Logging alerts to: log.txt\n");
    printf("Note: run with sudo (needs /var/log + iptables).\n");

    // Bash-based monitor (C wrapper):
    // - tail -F auth.log + syslog
    // - detect: failed logins, invalid users, sudo usage, priv-esc hints, iptables logs
    // - track offenders by counting in log.txt
    // - ban at threshold=4 (and avoid duplicate bans)
    // - graceful shutdown: Ctrl+C stops tails cleanly
    system(
        "bash -lc '"
        "LOG=log.txt; THRESH=4; touch \"$LOG\"; "
        "ts(){ date \"+%Y-%m-%d %H:%M:%S\"; } "
        "log(){ echo \"[$(ts)] $1\" >> \"$LOG\"; } "
        "count(){ grep -c \"$1\" \"$LOG\" 2>/dev/null || echo 0; } "
        "already_banned(){ iptables -C INPUT -s \"$1\" -j DROP 2>/dev/null; } "
        "ban(){ IP=\"$1\"; REASON=\"$2\"; "
        "  if [ -n \"$IP\" ]; then "
        "    if already_banned \"$IP\"; then "
        "      log \"ALREADY_BANNED IP $IP\"; "
        "    else "
        "      iptables -I INPUT 1 -s \"$IP\" -j DROP 2>/dev/null && log \"BANNED IP $IP\" || log \"BAN_FAILED IP $IP\"; "
        "    fi; "
        "  fi; "
        "} "
        "log \"IDS START\"; "

        // Add a best-effort iptables LOG rule for SYN packets (rate limited)
        "iptables -C INPUT -p tcp --syn -m limit --limit 12/min --limit-burst 24 "
        "-j LOG --log-prefix \"IPTABLES: \" --log-level 4 2>/dev/null || "
        "iptables -I INPUT 1 -p tcp --syn -m limit --limit 12/min --limit-burst 24 "
        "-j LOG --log-prefix \"IPTABLES: \" --log-level 4 2>/dev/null; "

        // Graceful shutdown for background tails started below
        "cleanup(){ log \"IDS STOP\"; kill 0 2>/dev/null; exit 0; } "
        "trap cleanup INT TERM; "

        // AUTH LOG monitor
        "tail -F /var/log/auth.log | while read -r line; do "
        "  if echo \"$line\" | grep -q \"Failed password\"; then "
        "    IP=$(echo \"$line\" | awk \"{for(i=1;i<=NF;i++) if($i==\\\"from\\\") print $(i+1)}\"); "
        "    log \"FAILED_LOGIN from $IP\"; "
        "    C=$(count \"FAILED_LOGIN from $IP\"); "
        "    if [ -n \"$IP\" ] && [ \"$C\" -ge \"$THRESH\" ]; then ban \"$IP\" \"FAILED_LOGIN\"; fi; "
        "  fi; "

        "  if echo \"$line\" | grep -q \"Invalid user\"; then "
        "    IP=$(echo \"$line\" | awk \"{for(i=1;i<=NF;i++) if($i==\\\"from\\\") print $(i+1)}\"); "
        "    log \"INVALID_USER from $IP\"; "
        "    C=$(count \"INVALID_USER from $IP\"); "
        "    if [ -n \"$IP\" ] && [ \"$C\" -ge \"$THRESH\" ]; then ban \"$IP\" \"INVALID_USER\"; fi; "
        "  fi; "

        "  if echo \"$line\" | grep -q \"sudo\"; then "
        "    log \"SUDO_ATTEMPT from LOCAL\"; "
        "  fi; "

        "  if echo \"$line\" | grep -E -q \"su: .*FAILED|authentication failure\"; then "
        "    log \"PRIV_ESC_ATTEMPT from LOCAL\"; "
        "  fi; "
        "done & "

        // SYSLOG monitor (iptables log prefix)
        "tail -F /var/log/syslog | while read -r line; do "
        "  if echo \"$line\" | grep -q \"IPTABLES:\"; then "
        "    SRC=$(echo \"$line\" | sed -n \"s/.*SRC=\\([^ ]*\\).*/\\1/p\"); "
        "    log \"IPTABLES_EVENT from $SRC\"; "
        "    C=$(count \"IPTABLES_EVENT from $SRC\"); "
        "    if [ -n \"$SRC\" ] && [ \"$C\" -ge \"$THRESH\" ]; then ban \"$SRC\" \"IPTABLES_EVENT\"; fi; "
        "  fi; "
        "done & "

        // Keep bash script alive; C process also stays alive.
        "wait' "
    );

    while (1) sleep(10);
}