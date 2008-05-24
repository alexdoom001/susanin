#ifndef CHANNEL_H
#define CHANNEL_H

#define SCVP_MSG_BLOCK_SIZE 4096

int send_data(int sd, const unsigned char *data, int len)
	__attribute__((nonnull));
int recv_data(int sd, unsigned char **data, int *len)
	__attribute__((nonnull));

#endif /* CHANNEL_H */
