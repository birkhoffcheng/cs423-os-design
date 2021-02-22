#include "userapp.h"

int main(int argc, char* argv[])
{
	pid_t pid = getpid();
	FILE *status_file = fopen("/proc/mp1/status", "w");
	if (status_file) {
		fprintf(status_file, "%d", pid);
		fclose(status_file);
	}
	return 0;
}
