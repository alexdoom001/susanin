#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <glib.h>

#include "connection.h"
#include "channel.h"
#include "scvp_proto.h"
#include "path_checker.h"
#include "logger.h"

void *connection_thread(void *conn)
{
	int sd, rqst_len = 0, resp_len;
	unsigned char *rqst_data = NULL, *resp_data = NULL;
	pthread_t thr_id;

	sd = ((struct connection*)conn)->sd;

	thr_id = pthread_self();
	pthread_detach(thr_id);
	free(conn);

	log_msg(LOG_DEBUG, "New connection established (thread %lu)", thr_id);

	while(1) {
		if (recv_data(sd, &rqst_data, &rqst_len)) {
			log_msg(LOG_DEBUG, "Failed receive SCVP request (thread %lu)", thr_id);
			goto end;
		}
		if (!(resp_data = process_scvp_request(rqst_data, rqst_len, &resp_len))) {
			log_msg(LOG_DEBUG, "Failed to process SCVP request (thread %lu)", thr_id);
			goto end;
		}
		if (send_data(sd, resp_data, resp_len)) {
			log_msg(LOG_DEBUG, "send() failed to send SCVP response (thread %lu)\n", thr_id);
			goto end;
		}
		free(resp_data);
		resp_data = NULL;
	}

end:
	free(rqst_data);
	free(resp_data);
	close(sd);
	log_msg(LOG_DEBUG, "Finishing thread %lu", thr_id);
	return NULL;
}
