#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_BUFFER 256

int total_risk = 0;

// Run command and capture output
void run_and_print(const char *title, const char *cmd) {
    char buffer[MAX_BUFFER];
    FILE *fp;

    printf("\n=== %s ===\n", title);

    fp = popen(cmd, "r");
    if (fp == NULL) {
        perror("popen failed");
        return;
    }

    while (fgets(buffer, sizeof(buffer), fp)) {
        printf("%s", buffer);
    }

    pclose(fp);
}

// Run command and count lines (for scoring)
int count_results(const char *cmd) {
    char buffer[MAX_BUFFER];
    int count = 0;
    FILE *fp = popen(cmd, "r");

    if (!fp) return 0;

    while (fgets(buffer, sizeof(buffer), fp)) {
        count++;
    }

    pclose(fp);
    return count;
}

// ---------------- CHECKS ---------------- //

int check_ssh() {
    printf("\n[SSH Configuration Check]\n");

    run_and_print(
        "SSH Settings",
        "grep -Ei 'PermitRootLogin|PasswordAuthentication' /etc/ssh/sshd_config 2>/dev/null"
    );

    int risk = count_results(
        "grep -E 'PermitRootLogin yes|PasswordAuthentication yes' /etc/ssh/sshd_config 2>/dev/null"
    );

    if (risk > 0) {
        printf("⚠ Weak SSH settings detected\n");
        total_risk += 2;
    }

    return risk;
}

int check_ports() {
    printf("\n[Open Ports Check]\n");

    run_and_print("Listening Ports", "ss -tuln");

    int ports = count_results("ss -tuln | grep LISTEN");

    if (ports > 10) {  // arbitrary threshold
        printf("⚠ Many open ports\n");
        total_risk += 2;
    }

    return ports;
}

int check_world_writable() {
    printf("\n[World-Writable Files]\n");

    run_and_print(
        "Writable Files",
        "find / -type f -perm -0002 2>/dev/null | head -n 20"
    );

    int count = count_results("find / -type f -perm -0002 2>/dev/null");

    if (count > 0) {
        printf("⚠ World-writable files found: %d\n", count);
        total_risk += 2;
    }

    return count;
}

int check_empty_passwords() {
    printf("\n[Empty Password Users]\n");

    run_and_print(
        "Users",
        "awk -F: '($2 == \"\" ) { print $1 }' /etc/shadow 2>/dev/null"
    );

    int count = count_results(
        "awk -F: '($2 == \"\" ) { print $1 }' /etc/shadow 2>/dev/null"
    );

    if (count > 0) {
        printf("⚠ Users with empty passwords\n");
        total_risk += 3;
    }

    return count;
}

int check_suid() {
    printf("\n[SUID Binaries]\n");

    run_and_print(
        "SUID Files",
        "find / -perm -4000 2>/dev/null | head -n 20"
    );

    int count = count_results("find / -perm -4000 2>/dev/null");

    if (count > 50) {  // typical systems have some
        printf("⚠ Large number of SUID binaries\n");
        total_risk += 1;
    }

    return count;
}

int check_firewall() {
    printf("\n[Firewall Status]\n");

    run_and_print(
        "Firewall",
        "which ufw >/dev/null 2>&1 && ufw status || "
        "which firewall-cmd >/dev/null 2>&1 && firewall-cmd --state"
    );

    int inactive = count_results(
        "ufw status 2>/dev/null | grep inactive"
    );

    if (inactive > 0) {
        printf("⚠ Firewall inactive\n");
        total_risk += 3;
    }

    return inactive;
}

// ---------------- FILE INTEGRITY ---------------- //

void check_integrity() {
    printf("\n[File Integrity Check]\n");

    run_and_print(
        "Hashes",
        "sha256sum /etc/passwd /etc/shadow /etc/ssh/sshd_config 2>/dev/null"
    );

    printf("Compare manually with baseline file (future improvement).\n");
}

// ---------------- REPORT ---------------- //

void print_report() {
    printf("\n============================\n");
    printf(" SECURITY REPORT\n");
    printf("============================\n");

    printf("Total Risk Score: %d\n", total_risk);

    if (total_risk == 0)
        printf("Status: SAFE\n");
    else if (total_risk < 5)
        printf("Status: LOW RISK\n");
    else if (total_risk < 10)
        printf("Status: MEDIUM RISK\n");
    else
        printf("Status: HIGH RISK\n");

    printf("\nRecommendations:\n");
    printf("- Disable root SSH login\n");
    printf("- Enable firewall\n");
    printf("- Remove unnecessary SUID files\n");
    printf("- Fix file permissions\n");
    printf("- Audit open ports\n");
}

// ---------------- MAIN ---------------- //

int main() {
    printf("Starting Security Audit...\n");

    check_ssh();
    check_ports();
    check_world_writable();
    check_empty_passwords();
    check_suid();
    check_firewall();
    check_integrity();

    print_report();

    return 0;
}