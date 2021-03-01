#include "userapp.h"

int main(int argc, char* argv[])
{
	pid_t pid = getpid();
	FILE *status_file = fopen("/proc/mp1/status", "w");
	if (status_file) {
		fprintf(status_file, "%d", pid);
		fclose(status_file);
	}
	uint64_t n, i, random;
	time_t start = time(NULL);
	while (time(NULL) - start < 10) {
		random = rand() % 64;
		n = 1;
		for (i = 1; i <= random; i++)
			n *= i;
		printf("%lu! = %lu\n", random, n);
	}
	int fd = open("/proc/mp1/status", O_RDONLY);
	if (fd >= 0) {
		char buffer[BUFSIZ];
		read(fd, buffer, BUFSIZ);
		puts(buffer);
		close(fd);
	}
	return 0;
}
