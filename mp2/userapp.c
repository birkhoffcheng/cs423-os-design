#include "userapp.h"

int main(int argc, char **argv) {
	if (argc < 3) {
		fprintf(stderr, "Usage: %s <period> <runtime>\n", argv[0]);
		return EXIT_FAILURE;
	}
	pid_t pid = getpid();
	int period = atoi(argv[1]);
	int runtime = atoi(argv[2]);
	if (period == 0 || runtime == 0) {
		fprintf(stderr, "Period and runtime must be integers\n");
		return EXIT_FAILURE;
	}
	FILE *fp = fopen("/proc/mp2/status", "w");
	if (!fp) {
		fprintf(stderr, "Status file opening failed\n");
		return EXIT_FAILURE;
	}
	fprintf(fp, "R, %d, %d, %d", pid, period, runtime);
	fclose(fp);
	char buf[BUFSIZ];
	sprintf(buf, "test $(grep %d /proc/mp2/status | wc -l) -gt 0", pid);
	if (system(buf) != 0) {
		fprintf(stderr, "Registration failed\n");
		return EXIT_FAILURE;
	}
	int i;
	unsigned long random, n;
	time_t wakeup_time, process_time;
	srand(time(NULL));
	fp = fopen("/proc/mp2/status", "w");
	for (i = rand() & 0xFF; i > 0; i--) {
		wakeup_time = time(NULL);
		n = 1;
		for (random = rand() % 64; random > 0; random--)
			n *= random;
		process_time = time(NULL) - wakeup_time;
		printf("wakeup: %ld, process: %ld\n", wakeup_time, process_time);
		fprintf(fp, "Y, %d", pid);
		fflush(fp);
	}
	fprintf(fp, "D, %d", pid);
	fclose(fp);
	return EXIT_SUCCESS;
}
