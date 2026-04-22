#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

void runDetectionMonitor(void);
void runPart1Audit(void);

static void runPart2SelfTest(void) {
    if (geteuid() != 0) {
        printf("Part 2 self-test must be run with sudo.\n");
        return;
    }

    const char* test_ip = "10.9.8.7";

    printf("\n[Part 2 Self-Test]\n");
    printf("This will:\n");
    printf("- Start the detection monitor in the background\n");
    printf("- Inject test log events for IP %s (4 times)\n", test_ip);
    printf("- Verify log.txt and iptables ban\n");
    printf("- Stop the monitor\n\n");

    pid_t pid = fork();
    if (pid == 0) {
        runDetectionMonitor();
        _exit(0);
    }
    if (pid < 0) {
        perror("fork");
        return;
    }

    sleep(2); // give tails time to start

    // Inject 4x failed login + 4x iptables events via syslog.
    // Note: where these land depends on rsyslog/journald config.
    char cmd[2048];
    snprintf(
        cmd, sizeof(cmd),
        "bash -lc '"
        "for i in 1 2 3 4; do "
        "  logger -p authpriv.notice \"Failed password for invalid user testuser from %s port 2222 ssh2\"; "
        "  logger -p authpriv.notice \"Invalid user testuser from %s port 2222\"; "
        "  logger -p kern.warning \"IPTABLES: IN=eth0 SRC=%s DST=1.2.3.4 PROTO=TCP SPT=12345 DPT=22\"; "
        "  sleep 0.2; "
        "done'",
        test_ip, test_ip, test_ip
    );
    (void)system(cmd);

    sleep(2); // allow monitor to process

    printf("Recent log.txt entries:\n");
    (void)system("bash -lc 'tail -n 25 log.txt 2>/dev/null || echo \"log.txt not found\"'");

    printf("\nChecking iptables ban for %s:\n", test_ip);
    snprintf(cmd, sizeof(cmd), "bash -lc 'iptables -C INPUT -s %s -j DROP 2>/dev/null && echo \"BANNED\" || echo \"NOT BANNED\"'", test_ip);
    (void)system(cmd);

    // Stop monitor
    (void)kill(pid, SIGINT);
    (void)waitpid(pid, NULL, 0);
    printf("\nSelf-test complete.\n");
}

int main() {
    int choice;

    printf("1. Part 1\n");
    printf("2. Detection Monitor\n");
    printf("3. Part 2 Self-Test\n");
    printf("Enter choice: ");
    scanf("%d", &choice);

    if (choice == 1) {
        runPart1Audit();
    } else if (choice == 2) {
        runDetectionMonitor();
    } else if (choice == 3) {
        runPart2SelfTest();
    } else {
        printf("Invalid choice.\n");
    }

    return 0;
}