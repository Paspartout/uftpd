#ifndef UFTPD_H

#include <sys/select.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdbool.h>

/// Handle for every server instance.
typedef struct uftpd_handle {
	int listen_socket;
	fd_set master;
	int fd_max;
	bool running;
} uftpd_handle;

// TODO: Implement callback based notification
typedef enum uftpd_event {
	ServerStarted,
	ServerStopped,
	ClientConnected,
	ClientDisconnected,
	Error,
} uftpd_event;

/// Intitialize the given handle by setting up a socket that listents to the given addr.
int uftpd_init(uftpd_handle* handle, struct addrinfo* addr);

/// Use getaddrinfo and use port to intialize the server/sockets.
int uftpd_init_localhost(uftpd_handle* handle, const char *port);

/// Start the event loop, this functions blocks forever.
int uftpd_loop(uftpd_handle* handle);

/// Stop the event loop.
void uftpd_stop(uftpd_handle* handle);

#define UFTPD_H
#endif

