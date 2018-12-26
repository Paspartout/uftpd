#include <stdio.h>

#include "uftpd.h"

int main() {
	// register signal handler for cleanup
	// struct sigaction act;
	// memset(&act, 0, sizeof(act));
	// act.sa_handler = &handle_sig;
	// sigaction(SIGTERM, &act, NULL);
	// sigaction(SIGINT, &act, NULL);

	uftpd_handle handle;
	uftpd_init_localhost(&handle, "1033");
	uftpd_loop(&handle);

	return 0;
}

