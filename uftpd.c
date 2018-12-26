#include <sys/socket.h>
#include <sys/types.h>
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
#include <sys/stat.h>
#include <time.h>
#include <limits.h>

#include "queue.h"
#include "cmds.h"

// Set PATH_MAX to 4096 for now
// Actually paths can be much longer but I don't care about that use case for now.
// (Who uses paths longer than 4096 characters anyway?)
// 
// See https://eklitzke.org/path-max-is-tricky and 
// https://insanecoding.blogspot.com/2007/11/pathmax-simply-isnt.html
#ifndef PATH_MAX
#define PATH_MAX 4096
#endif
#define USERNAME_SIZE 32
#define DATABUF_SIZE 16384

#define STRLEN(s) (sizeof(s)/sizeof(s[0]))
#define UNUSED(x) (void)(x)

#ifndef DEBUG
#define DEBUG 0
#endif
#define dprintf(fmt, ...) \
	            do { if (DEBUG) fprintf(stderr, fmt, __VA_ARGS__); } while (0)

// Macros for less typing
#define rreply(sock, s) if (send(sock, s, STRLEN(s), 0) == -1) \
					return -1; \

#define rreply_client(s) if (send(client->socket, s, STRLEN(s), 0) == -1) \
					return -1; \

static int replyf(int sock, const char *format, ...) {
	#define REPLYBUFLEN 255
	static char reply_buf[REPLYBUFLEN];

	va_list args;
	va_start(args, format);
	int len = vsnprintf(reply_buf, REPLYBUFLEN, format, args);
	va_end(args);

	if (send(sock, reply_buf, len, 0) == -1)
		return -1;

	return 0;
}

// TODO: Consider implementing proper authentication or anonymous login
bool check_login(const char* username, const char* password) {
	printf("USER \"%s\" logged in with PASS \"%s\"\n", username, password);
	return true;
}

enum ClientState {
	Disconnected = 0,
	Identifying, // Before submitting username
	Authenticating, // Before authenticated using username and password
	LoggedIn,
};


// The data representation type used for data transfer and storage.
enum TranfserType {
	Ascii,
	Image,
};

typedef struct Client {
	enum ClientState state;
	int socket;
	int data_socket;

	char username[USERNAME_SIZE];
	char cwd[PATH_MAX];
	enum TranfserType type;

	// Adress and port used for active or passive ftp?
	bool passive_mode;
	struct sockaddr_in addr;

	// Used for moving/renaming files
	char from_path[PATH_MAX];

	// For linked list
	SLIST_ENTRY(Client) entries;
} Client;


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

// Create a new client and initalize it
Client *client_new(int socket, struct sockaddr_storage *client_addr) {
	Client *new_client = malloc(sizeof(Client));
	if (new_client == NULL) {
		fprintf(stderr, "error mallocing client!\n");
		return NULL;
	}

	new_client->socket = socket;
	new_client->state = Identifying;
	new_client->data_socket = -1;
	new_client->type = Ascii;
	new_client->passive_mode = false;
	new_client->from_path[0] = 0;

	// Use client address and default port 20 for active mode
	new_client->addr.sin_port = htons(20);
	memcpy(&(new_client->addr), client_addr, sizeof(new_client->addr));

	return new_client;
}

int handle_connect(int listen_sock) {
	struct sockaddr_storage client_addr;
	socklen_t addrlen = sizeof(client_addr);

	int newfd = accept(listen_sock, (struct sockaddr*)&client_addr, &addrlen);
	if (newfd == -1) {
		perror("accept");
		return newfd;
	} 


	if (!list_initialized) {
		SLIST_INIT(&client_list);
		list_initialized = true;
	}

	// Insert client into list of connected clients
	Client *client = client_new(newfd, &client_addr);
	if (client == NULL) {
		return -1;
	}
	SLIST_INSERT_HEAD(&client_list, client, entries);
	
	rreply_client("220 uftpd server\r\n");

	// TODO: Notify user using control socket about a new connection?
	char client_ipstr[INET6_ADDRSTRLEN];
	printf("new connection from %s:%d on socket %d\n",
			inet_ntop(client_addr.ss_family, 
				&((struct sockaddr_in*)&client_addr)->sin_addr,
				client_ipstr, sizeof(client_ipstr)),
				((struct sockaddr_in*)&client_addr)->sin_port,
				newfd);


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
	// TODO: PASSV: Implement
	return 0;
}

int cwd(Client *client, const char *path) {
	static char pathbuf[8192];
	const char* newpath;
	const char* pwd = client->cwd;
	DIR* dir = NULL;

	// Handle .. and .
	if (path[0] == '.' && path[1] == '.') {
		// Go up
		if(strlen(pwd) <= 1 && pwd[0] == '/') {
			// Cant go up anymore
			rreply_client("431 Error changing directory: Already at topmost directory\n");
			return -1;
		}

		// Remove upmost directory
		bool copy = false;
		int len = 0;
		for(ssize_t i = strlen(pwd); i >= 0; i--) {
			if (pwd[i] == '/') copy = true;
			if (copy) {
				pathbuf[i] = pwd[i];
				len++;
			}
		}
		assert(copy);
		// remove trailing slash
		if (len > 1 && pathbuf[len-1] == '/')
			len--;
		pathbuf[len] = '\0';
		newpath = pathbuf;
	} else if (path[0] == '/') {
		// Go to specified absoule path
		newpath = path;
	} else {
		// Go to specified relative path
		int len = snprintf(pathbuf, sizeof(pathbuf), "%s/%s", client->cwd, path);
		if (len > PATH_MAX) {
			replyf(client->socket, "500 Internal error: Path is too long!");
			return -1;
		}
		newpath = pathbuf;
	}

	dir = opendir(newpath);
	if (dir == NULL) {
		replyf(client->socket, "431 Error changing directory: %s\n", strerror(errno));
		return -1;
	}
	strncpy(client->cwd, newpath, PATH_MAX);
	rreply_client("200 Working directory changed.\n");
	closedir(dir);
	return 0;
}

// Open a active ftp connection by connecting to the clients address
int open_active(Client *client) {
	int data_socket = socket(AF_INET, SOCK_STREAM, 0);
	// TODO: Consider using getaddrinfo
	if (data_socket == -1) {
		replyf(client->socket, "500 Connection error: %s\n", strerror(errno));
		perror("socket");
		return -1;
	}

	rreply_client("150 File status okay; about to open data connection.\n");
	int res = connect(data_socket, (struct sockaddr*)&(client->addr), sizeof(client->addr));
	if (res == -1) {
		replyf(client->socket, "500 Connection error: %s\n", strerror(errno));
		perror("connect");
		close(data_socket);
		return -1;
	}

	return data_socket;
}

// Open active or passive connection depending on setting
int open_data(Client *client) {
	int data_socket;
	if (client->passive_mode) {
		// TODO: PASSV: Use listen socket? Enque listen command?
	} else {
		if ((data_socket = open_active(client)) == -1) {
			return -1;
		}
		return data_socket;
	}
	return -1;
}

// Appends the path child to base and writes the result to dest.
int path_extend(char* dest, size_t n, const char *base, const char* child) {
	int len = snprintf(dest, n, "%s/%s", base, child);
	if (len > (int)n) {
		fprintf(stderr, "the new path is too long!\n");
		return -1;
	} else if (len < 0) {
		perror("snprintf");
		return -2;
	}
	return 0;
}

#define rpath_extend(dest, n, base, child) if (path_extend(dest, n, base, child) < 0) { \
	replyf(client->socket, "500 Internal error: Path is too long!"); \
	return -1; \
}

// Handle commands from user once logged in
int handle_ftpcmd(const FtpCmd *cmd, Client *client) {
	static char fullpath[PATH_MAX];
	const int client_sock = client->socket;
	int data_socket;
	char type;
	switch (cmd->keyword) {
		case PWD: // Print working directory
			replyf(client_sock, "257 \"%s\"\n", client->cwd);
			break;
		case CWD: // Change working directory
			if (cwd(client, cmd->parameter.string) == -1) {
				return -1;
			}
			break;
		case CDUP:
			if (cwd(client, "..") == -1) {
				return -1;
			}
			break;
		case PORT: {
			const uint8_t ip0 = cmd->parameter.numbers[0];
			const uint8_t ip1 = cmd->parameter.numbers[1];
			const uint8_t ip2 = cmd->parameter.numbers[2];
			const uint8_t ip3 = cmd->parameter.numbers[3];

			const uint8_t port0 = cmd->parameter.numbers[4]; // high byte
			const uint8_t port1 = cmd->parameter.numbers[5]; // low byte
			client->addr.sin_family = AF_INET;
			// TODO: Probably don't do this and use inet_pton
			client->addr.sin_addr.s_addr = ip3 << 24 | ip2 << 16 | ip1 << 8 | ip0;
			client->addr.sin_port = port1 << 8 | port0;
			rreply_client("200 PORT was set.\n");
			} break;
		//case PASV:
			// TODO: PASSV: Listen on new dataport and print addr of it
			//break;
		case RETR: {
			// Do it
			rpath_extend(fullpath, PATH_MAX, client->cwd, cmd->parameter.string);
			printf("opening file %s\n", fullpath);

			FILE *f = fopen(fullpath, "r");
			if (f == NULL) {
				replyf(client->socket, "550 Filesystem error: %s\n", strerror(errno));
				perror("fopen");
				return -1;
			}
			
			if ((data_socket = open_data(client)) == -1) {
				return -1;
			}

			char data_buf[DATABUF_SIZE];
			size_t read_bytes = 0;
			ssize_t sent_bytes = 0;
			size_t reamining_bytes = 0;
			do {
				read_bytes = fread(data_buf, 1, 2048, f);
				dprintf("read %ld bytes\n", read_bytes);
				if (ferror(f)) {
					perror("fread");
				}
				reamining_bytes = read_bytes;
				dprintf("remaining %ld bytes\n", reamining_bytes);
				while(reamining_bytes > 0) {
					sent_bytes = send(data_socket, data_buf, read_bytes, 0);
					dprintf("sent %ld bytes\n", sent_bytes);
					if (sent_bytes == -1) {
						perror("send");
						close(data_socket);
						return -1;
					}
					reamining_bytes -= sent_bytes;
					dprintf("remaining %ld bytes\n", reamining_bytes);
				}
			} while(read_bytes > 0);

			fclose(f);

			rreply_client("226 Closing data connection.\n");
			close(data_socket);
			rreply_client("250 Requested file action okay, completed.\n");
			} break;
		case STOR: {
			rpath_extend(fullpath, PATH_MAX, client->cwd, cmd->parameter.string);

			// Try to create file by opening it for writing
			FILE *f = fopen(fullpath, "w");
			if (f == NULL) {
				replyf(client->socket, "550 Filesystem error: %s\n", strerror(errno));
				perror("fopen");
				return -1;
			}

			if ((data_socket = open_data(client)) == -1) {
				return -1;
			}

			// Read data from data_socket and write it to created file
			char data_buf[DATABUF_SIZE];
			size_t written_bytes = 0;
			ssize_t received_bytes = 0;
			ssize_t reamining_bytes = 0;
			do {
				received_bytes = recv(data_socket, data_buf, sizeof(data_buf), 0);
				if (received_bytes == -1) {
					perror("recv");
				}
				dprintf("received %ld bytes\n", received_bytes);
				reamining_bytes = received_bytes;
				dprintf("remaining %ld bytes\n", reamining_bytes);
				// Write the received bytes down
				while(reamining_bytes > 0) {
					written_bytes = fwrite(data_buf, 1, received_bytes, f);
					dprintf("written %ld bytes\n", written_bytes);
					if (ferror(f)) {
						replyf(client->socket, "550 Filesystem error: %s\n", strerror(errno));
						perror("fwrite");
						fclose(f);
						return -1;
					}
					reamining_bytes -= written_bytes;
					dprintf("remainingloop %ld bytes\n", reamining_bytes);
				}
			} while(received_bytes > 0);

			rreply_client("226 Closing data connection.\n");
			close(data_socket);
			rreply_client("250 Requested file action okay, completed.\n");

			fclose(f);
			} break;
		case DELE: {
			rpath_extend(fullpath, PATH_MAX, client->cwd, cmd->parameter.string);
			if (unlink(fullpath) == -1) {
				perror("unlink");
				replyf(client->socket, "550 Filesystem error: %s\n", strerror(errno));
				return -1;
			}
			rreply_client("250 Requested file action okay, completed.\n");
			} break;
		case RMD: {
			rpath_extend(fullpath, PATH_MAX, client->cwd, cmd->parameter.string);
			if (rmdir(fullpath) == -1) {
				perror("rmdir");
				replyf(client->socket, "550 Filesystem error: %s\n", strerror(errno));
				return -1;
			}
			rreply_client("250 Requested file action okay, completed.\n");
			} break;
		case MKD: {
			rpath_extend(fullpath, PATH_MAX, client->cwd, cmd->parameter.string);
			if (mkdir(fullpath, 0755) == -1) {
				perror("mkdir");
				replyf(client->socket, "550 Filesystem error: %s\n", strerror(errno));
				return -1;
			}
			rreply_client("250 Requested file action okay, completed.\n");
			} break;
		case RNFR: {
			rpath_extend(client->from_path, PATH_MAX, client->cwd, cmd->parameter.string);
			rreply_client("350 Please specify destination using RNTO now.\n");
			} break;
		case RNTO: {
			if (client->from_path[0] == 0) {
				replyf(client->socket, "503 Bad sequence of commands. Use RNFR first.\n");
				return -1;
			}
			if (rename(client->from_path, cmd->parameter.string) == -1) {
				perror("rename");
				replyf(client->socket, "550 Filesystem error: %s\n", strerror(errno));
				client->from_path[0] = 0;
				return -1;
			}
			client->from_path[0] = 0;
			rreply_client("250 Requested file action okay, completed.\n");
			} break;
		case LIST: {
			const char *pathname = client->cwd;
			if (cmd->parameter.string[0] != 0) {
				pathname = cmd->parameter.string;
			}
			
			// List files
			// TODO: Buffer first and the send once we know we got no error
			DIR *dir = opendir(pathname);
			if (dir == NULL) {
				replyf(client->socket, "450 Filesystem error: %s\n", strerror(errno));
				perror("opendir");
				return -1;
			}

			if ((data_socket = open_data(client)) == -1) {
				return -1;
			}

			struct dirent* entry;
			while((entry = readdir(dir)) != NULL) {
				if (entry->d_name[0] == '.') { // skip . file for now
					continue;
				}
				struct stat entry_stat;
				rpath_extend(fullpath, sizeof(fullpath), client->cwd, entry->d_name);
				if (stat(fullpath, &entry_stat) == -1) {
					perror("stat");
					continue;
				}

				// filetype: no link support(yet?)
				char filetype;
				if (entry->d_type ==DT_DIR)
					filetype = 'd';
				else
					filetype = '-';

				// Date format conforming to POSIX ls:
				// https://pubs.opengroup.org/onlinepubs/9699919799/utilities/ls.html
				char date_str[24];
				const char *date_fmt = "%b %d %H:%M";
				time_t mtime = entry_stat.st_mtim.tv_sec;
				// Display year if file is older than 6 months
				if (time(NULL) > entry_stat.st_mtim.tv_sec + 6*30*24*60*60)
					date_fmt = "%b %d  %Y";
				strftime(date_str, 24, date_fmt, localtime(&mtime));

				const char *fmtstring = "%crw-rw-rw- 1 user group %lu %s %s\r\n";
				dprintf(fmtstring, filetype, entry_stat.st_size, date_str, entry->d_name);
				replyf(data_socket, fmtstring, filetype, entry_stat.st_size, date_str, entry->d_name);
			}
			closedir(dir);
			
			rreply_client("226 Closing data connection.\n");
			close(data_socket);
			rreply_client("250 Requested file action okay, completed.\n");
			} break;
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
			rreply(client_sock, "500 Invalid command.\n");
			break;
		default:
			rreply(client_sock, "502 Command parsed but not implemented yet.\n");
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

	// TODO: PASSV: Handle DTP socket?
	if (is_data_socket) {
		if (handle_data(buf, client) != 0) {
			fprintf(stderr, "error handling ftp data socket");
			return -1;
		}
		return 0;
	}

	FtpCmd cmd = parse_ftpcmd(buf);
	dprintf("command buffer: \"%s\"", buf);
	dprintf("parsed command: %s\n", keyword_names[cmd.keyword]);

	switch(client->state) {
		case Identifying:
			// Only allow USER command for identification
			if (cmd.keyword == USER) {
				rreply_client("331 Please authenticate using PASS.\n");
				client->state = Authenticating;
				strncpy(client->username, cmd.parameter.string, USERNAME_SIZE);
			} else {
				rreply_client("530 Please login using USER and PASS command.\n");
			}
			break;
		case Authenticating:
			// Only allow PASS command for authentification
			if (cmd.keyword == PASS) {
				// check username and password
				const char* password = cmd.parameter.string;
				bool logged_in = check_login(client->username, password);
				if (logged_in) {
					rreply_client("230 Login successful.\n");
					client->state = LoggedIn;
					strncpy(client->cwd, "/", STRLEN("/")); // TODO: Make starting cwd configurable?
				} else {
					rreply_client("530 Wrong password.\n");
					client->state = Identifying;
				}
			} else {
				rreply_client("530 Please use PASS to authenticate.\n");
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

	// only on local system not esp:sd
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


