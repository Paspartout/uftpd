#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "uftpd.h"
#define UNUSED(x) (void)(x)

static uftpd_ctx ctx;

static void handle_sig(int sig) {
	UNUSED(sig);
	uftpd_stop(&ctx);
}

const char *event_names[] = {
    "ServerStarted", "ServerStopped", "ClientConnected", "ClientDisconnected", "Error",
};

static void callback(uftpd_event ev, const char *details) {
	printf("received event: %s\n", event_names[ev]);
	if (details != NULL) {
		printf("details: %s\n", details);
	}
}

int main() {
	// register signal handler for cleanup
	struct sigaction act;
	memset(&act, 0, sizeof(act));
	act.sa_handler = &handle_sig;
	sigaction(SIGTERM, &act, NULL);
	sigaction(SIGINT, &act, NULL);

	uftpd_init_localhost(&ctx, "1033");
	uftpd_set_ev_callback(&ctx, callback);
	uftpd_start(&ctx);

	return 0;
}
