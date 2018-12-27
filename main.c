#include <stdio.h>
#include <stdbool.h>
#include <signal.h>
#include <string.h>

#include "uftpd.h"
#define UNUSED(x) (void)(x)

uftpd_handle handle;
void handle_sig(int sig) {
	UNUSED(sig);
	uftpd_stop(&handle);
}

int main() {
	// register signal handler for cleanup
	struct sigaction act;
	memset(&act, 0, sizeof(act));
	act.sa_handler = &handle_sig;
	sigaction(SIGTERM, &act, NULL);
	sigaction(SIGINT, &act, NULL);

	uftpd_init_localhost(&handle, "1033");
	uftpd_loop(&handle);

	return 0;
}

