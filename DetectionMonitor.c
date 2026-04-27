#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

void runDetectionMonitor(void) {
    printf("Starting Detection Monitor...\n");
    printf("Logging alerts to: log.txt\n");
    printf("Note: run with sudo (needs /var/log + iptables).\n");

    // Delegate to a real script (much easier to read/maintain than a giant quoted one-liner).
    // The script prints clearly separated sections for each task.
    (void)system("bash ./detection_monitor.sh");
}