#include <sys/socket.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <stdbool.h>
#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <dirent.h>

#include "cmds.h"

#define STRLEN(s) (sizeof(s)/sizeof(s[0]))
#define UNUSED(x) (void)(x)

enum ClientState {
	Disconnected = 0,
	Identifying, // Before submitting username
	Authenticating, // Before authenticated using username and password
	LoggedIn,
};

#define USERNAME_SIZE 32
#define MAX_PATHLEN 1024

// The data representation type used for data transfer and storage.
enum TranfserType {
	Ascii,
	Image,
};

typedef struct Client {
	enum ClientState state;
	int socket;
	int data_socket;

	// TODO: Add dtp sockets etc
	char username[USERNAME_SIZE];
	char cwd[MAX_PATHLEN];
	enum TranfserType type;

	// For linked list
	SLIST_ENTRY(Client) entries;
} Client;

// TODO: Consider implementing proper authentication or anonymous login
bool check_login(const char* username, const char* password) {
	printf("USER \"%s\" logged in with PASS \"%s\"\n", username, password);
	return true;
}

// Creates the list head struct
SLIST_HEAD(ClientList, Client) client_list = SLIST_HEAD_INITIALIZER(client_list);
static bool list_initialized = false;

// Retrieve client struct by its socket
Client* get_client(int socket) {
	Client* c;
	SLIST_FOREACH(c, &client_list, entries) {
		if (c->socket == socket || c->data_socket == socket) {
			return c;
		}
	}

	return NULL;
}

int close_all() {
	while (!SLIST_EMPTY(&client_list)) {
		Client *c = SLIST_FIRST(&client_list);
		SLIST_REMOVE_HEAD(&client_list, entries);
		if (close(c->socket) == -1) {
			perror("close");
		}
		free(c);
	}
	return 0;
}

int handle_connect(int listen_sock) {
	struct sockaddr_storage client_addr;
	socklen_t addrlen = sizeof(client_addr);
	int newfd = accept(listen_sock, (struct sockaddr*)&client_addr, &addrlen);
	if (newfd == -1) {
		perror("accept");
		return newfd;
	} 

	char client_ipstr[INET6_ADDRSTRLEN];
	printf("new connection from %s on socket %d\n",
			inet_ntop(client_addr.ss_family, 
				&((struct sockaddr_in*)&client_addr)->sin_addr,
				client_ipstr, sizeof(client_ipstr)),
				newfd);

	if (!list_initialized) {
		SLIST_INIT(&client_list);
		list_initialized = true;
	}

	Client *new_client = malloc(sizeof(Client));
	if (new_client == NULL) {
		fprintf(stderr, "error mallocing client!\n");
		close(newfd);
		return -1;
	}

	// Insert client into list of connected clients and start by asking for username and password
	new_client->socket = newfd;
	new_client->state = Identifying;
	new_client->data_socket = -1;
	new_client->type = Ascii;
	SLIST_INSERT_HEAD(&client_list, new_client, entries);
	
	// TODO: Add version to welcome msg?
	const char *welcome_msg = "220 ufpd server\r\n";
	if (send(newfd, welcome_msg, strlen(welcome_msg), 0) == -1) {
		perror("send");
		close(newfd);
	}
	
	// TODO: Notify user using control socket about a new connection?

	return newfd;
}


int handle_disconnect(int client_sock) {
	Client* client = get_client(client_sock);
	assert(client != NULL);
	printf("user disconnected\n");
	SLIST_REMOVE(&client_list, client, Client, entries);
	free(client);
	return 0;
}

// Process data from data connection
int handle_data(char* buf, Client *client) {
	UNUSED(buf); UNUSED(client);
	// TODO: Implement
	return 0;
}

// Makro for less typing
#define reply(s) if (send(client_sock, s, STRLEN(s), 0) == -1) \
					return -1; \

// Makro for less typing
static int replyf(int sock, const char *format, ...) {
	#define REPLYBUFLEN 255
	static char reply_buf[REPLYBUFLEN];

	va_list args;
	va_start(args, format);
	int len = vsnprintf(reply_buf, REPLYBUFLEN, format, args);
	va_end(args);
	// TODO: len handling?

	// TODO: send hanlde large packets
	if (send(sock, reply_buf, len, 0) == -1)
		return -1;

	return 0;

}

// Handle commands from user once logged in
int handle_ftpcmd(const FtpCmd *cmd, Client *client) {
	const int client_sock = client->socket;
	const char* path = NULL;
	char type;
	DIR *dir = NULL;
	switch (cmd->keyword) {
		case PWD: // Print working directory
			replyf(client_sock, "257 \"%s\"\n", client->cwd);
			break;
		case CWD: // Change working directory
			path = cmd->parameter.string;
			dir = opendir(path);
			if (dir == NULL) {
				replyf(client_sock, "431 Error changing directory: %s\n", strerror(errno));
				return -1;
			}
			strncpy(client->cwd, path, MAX_PATHLEN);
			reply("200 Working directory changed.\n");
			closedir(dir);
			break;
		case TYPE: // Set the data representation type
			type = cmd->parameter.code;
			if (type == 'I') {
				client->type = Image;
				replyf(client_sock, "200 Type set to %c.\n", type);
			} else if (type == 'A') {
				client->type = Ascii;
				replyf(client_sock, "200 Type set to %c.\n", type);
			} else {
				replyf(client_sock, "500 Type %c not supported.\n", type);
			}
			break;
		case INVALID:
			reply("500 Invalid command.\n");
			break;
		default:
			reply("500 Internal error. Command parsed but not implemented yet.\n");
			return -1;
			break;
	}
	return 0;
}

// Handle authentication and socket re
int handle_recv(int client_sock, char* buf) {
	// Retreive user socket
	Client* client = get_client(client_sock);
	assert(client != NULL);
	const bool is_data_socket = client_sock == client->data_socket ? true : false;

	if (is_data_socket) {
		if (handle_data(buf, client) != 0) {
			fprintf(stderr, "error handling ftp data socket");
			return -1;
		}
		return 0;
	}

	// TODO: Handle DTP socket?
	FtpCmd cmd = parse_ftpcmd(buf);
	printf("command \"%s\"\n", buf);
	printf("parsed %s\n", keyword_names[cmd.keyword]);

	switch(client->state) {
		case Identifying:
			// Only allow USER command for identification
			if (cmd.keyword == USER) {
				reply("331 Please authenticate using PASS.\n");
				client->state = Authenticating;
				strncpy(client->username, cmd.parameter.string, USERNAME_SIZE);
			} else {
				reply("530 Please login using USER and PASS command.\n");
			}
			break;
		case Authenticating:
			// Only allow PASS command for authentification
			if (cmd.keyword == PASS) {
				// check username and password
				const char* password = cmd.parameter.string;
				bool logged_in = check_login(client->username, password);
				if (logged_in) {
					reply("230 Login successful.\n");
					client->state = LoggedIn;
					strncpy(client->cwd, "/", STRLEN("/")); // TODO: Make starting cwd configurable?
				} else {
					reply("530 Wrong password.\n");
					client->state = Identifying;
				}
			} else {
				reply("530 Please use PASS to authenticate.\n");
			}
			break;
		case LoggedIn:
			// Allow every command
			if (handle_ftpcmd(&cmd, client) != 0) {
				return -1;
			}
			break;
		default:
			fprintf(stderr, "invalid client state: %d\n", client->state);
			break;
	}

	return 0;
}

#undef reply

bool running = true;

void handle_sig(int sig) {
	printf("Handling signal %d\n", sig);
	running = false;
}

int main() {
	struct addrinfo hints, *res;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	// register signal handler for cleanup
	struct sigaction act;
	memset(&act, 0, sizeof(act));
	act.sa_handler = &handle_sig;
	sigaction(SIGTERM, &act, NULL);
	sigaction(SIGINT, &act, NULL);

	// only on local system not esp:
	if (getaddrinfo(NULL, "1034", &hints, &res) == -1) {
		perror("getaddrinfo");
		return -1;
	}

	int listen_sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if (listen_sock == -1) {
		perror("socket");
		return -1;
	}

	if (bind(listen_sock, res->ai_addr, sizeof(struct sockaddr)) == -1) {
		perror("bind");
		return -1;
	}

	if (listen(listen_sock, 10) == -1) {
		perror("listen");
		return -1;
	}

	fd_set master, ready;
	FD_ZERO(&master);
	FD_ZERO(&ready);
	FD_SET(listen_sock, &master);

	int fdmax = listen_sock;
	int nbytes;

	while(running) {
		ready = master;
		if (select(fdmax+1, &ready, NULL, NULL, NULL) == -1) {
			perror("select");
			break;
		}
		// One got ready
		char buf[128];
		for (int i = 0; i <= fdmax; i++) {
			if (!FD_ISSET(i, &ready)) {
				continue;
			}

			if (i == listen_sock) {
				int csock;
				if ((csock = handle_connect(listen_sock)) == -1) {
					fprintf(stderr, "error handling incomming connection");
					running = false;
				}

				// Add new socket to master list
				FD_SET(csock, &master); 
				if (csock > fdmax) {
					fdmax = csock;
				}
			} else { // data socket
				if ((nbytes = recv(i, buf, sizeof(buf), 0)) <= 0) {
					// Handle error or disconnect
					if (nbytes == 0) {
						handle_disconnect(i);
					} else {
						perror("recv");
					}
					close(i);
					FD_CLR(i, &master);
					continue; // skip to next socket
				}

				// nbytes > 0
				assert(nbytes > 0);
				buf[nbytes] = '\0';
				handle_recv(i, buf);
			} // i == listen_sock
		}
	}

	// close remaining connections
	close_all();
	close(listen_sock);

	return 0;
}


