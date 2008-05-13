#ifndef CONNECTION_H
#define CONNECTION_H

struct connection {
	int sd;
	struct sockaddr_un sa;
};

void *connection_thread(void *conn);

#endif /* CONNECTION_H */
