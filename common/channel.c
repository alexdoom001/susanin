#include <stdlib.h>
#include <sys/socket.h>
#include <sys/poll.h>
#include <unistd.h>

#include "channel.h"

int send_data(int sd, unsigned char *data, int len)
{
	int data_left, data_len, ret;

	data_left = len;
	while (1) {
		data_len = (data_left < SCVP_MSG_BLOCK_SIZE) ? data_left : SCVP_MSG_BLOCK_SIZE;
		ret = send(sd, data + (len - data_left), data_len, 0);
		if (ret != data_len)
			return 1;
		if (data_left < SCVP_MSG_BLOCK_SIZE)
			break;
		data_left -= SCVP_MSG_BLOCK_SIZE;
	}
	return 0;
}

int recv_data(int sd, unsigned char **data, int *len)
{
	int data_len, ret;
	struct pollfd poll_fd;

	poll_fd.fd = sd;
	poll_fd.events = POLLIN;

	*len = 0;
	while (1) {
		ret = poll(&poll_fd, 1, (100 * 1000));
		if (ret == -1 || ret == 0)
			goto end;
		*data = realloc(*data, *len + SCVP_MSG_BLOCK_SIZE);
		data_len = read(sd, *data + *len, SCVP_MSG_BLOCK_SIZE);
		*len += data_len;
		if (data_len < SCVP_MSG_BLOCK_SIZE)
			break;
	}
	return 0;

end:
	free(*data);
	return 1;
}
