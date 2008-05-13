#include <errno.h>
#include <syslog.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <glib.h>

#include "connection.h"
#include "scvp_proto.h"
#include "crypto_openssl.h"
#include "config.h"
#include "logger.h"

void *asn1_definitions;

char *parse_command_line(int argc, char *argv[])
{
	char *conf_file = NULL;
	GOptionContext *opt_ctx;
	GOptionEntry entries[] = {
		{ "config", 'c', 0, G_OPTION_ARG_STRING, &conf_file, "configuration file", NULL},
		{ "daemonize", 'd', 0, G_OPTION_ARG_NONE, &cfg.daemon, "run as daemon", NULL},
		{ NULL }
	};

	if (!(opt_ctx = g_option_context_new("- PKI path validation daemon")))
		return NULL;
	g_option_context_add_main_entries(opt_ctx, entries, NULL);
	if (!g_option_context_parse (opt_ctx, &argc, &argv, NULL)) {
		g_option_context_free(opt_ctx);
		fprintf(stderr, "Failed to parse command line\n");
		return NULL;
	}
	g_option_context_free(opt_ctx);
	return conf_file;
}

int main(int argc, char **argv) {
	int err, listen_sd;
	unsigned int client_len;
	struct sockaddr_un sa_serv;
	char *conf_file;
	pid_t pid, sid;
	FILE *pidf;
	pthread_attr_t pth_attr;
	pthread_t thread;
	struct connection *con;

	if (!(conf_file = parse_command_line(argc, argv))) {
		fprintf(stderr,"Failed to retrieve configuration file name\n");
		return 1;
	}

	logger_init();

	if (load_config(conf_file) != 0) {
		log_msg(LOG_DEBUG, "Failed to read configuration file '%s'", conf_file);
		return 1;
	}

	if (!(asn1_definitions = scvp_initialize("scvp.asn"))) {
		log_msg(LOG_DEBUG, "Failed to initialize ASN.1 library\n");
		return 1;
	}

	openssl_init();

	/* Daemonize */
	if (cfg.daemon) {
		pid = fork();
		if (pid < 0) {
			log_msg(LOG_DEBUG, "Failed to fork()");
			return 1;
		}

		/* Parent */
		if (pid > 0) {
			return 0;
		}
		sid = setsid();
		if (sid < 0) {
			log_msg(LOG_DEBUG, "Failed to setsid()");
			return 1;
		}
	}

	if ((pthread_attr_init(&pth_attr) != 0) || pthread_attr_setdetachstate(&pth_attr, PTHREAD_CREATE_DETACHED) != 0) {
		log_msg(LOG_DEBUG, "Failed to init pthread attributes");
		return 1;
	}

	listen_sd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
	if (listen_sd == -1) {
		log_msg(LOG_DEBUG, "socket(): %s", strerror(errno));
		return 1;
	}

	memset(&sa_serv, 0, sizeof(sa_serv));
	sa_serv.sun_family = AF_UNIX;
	strcpy(sa_serv.sun_path, cfg.socket_path);
	unlink(cfg.socket_path);

	err = bind(listen_sd, (struct sockaddr *) & sa_serv, sizeof (sa_serv));
	if (err == -1) {
		log_msg(LOG_DEBUG, "bind(): %s", strerror(errno));
		return 1;
	}

	err = listen(listen_sd, 1024);
	if (err == -1) {
		log_msg(LOG_DEBUG, "listen(): %s", strerror(errno));
		return 1;
	}

	pidf = fopen(cfg.pid_path, "w");
	if (pidf == NULL) {
		log_msg(LOG_DEBUG, "Can't open pid file");
	} else {
		pid = getpid();
		if (fprintf(pidf, "%llu\n", (unsigned long long int) pid) < 0)
			log_msg(LOG_DEBUG, "Can't write to pid file");
		if (fclose(pidf) != 0)
			log_msg(LOG_DEBUG, "Can't close pid file");
	}
	for (;;) {
		if (!(con = malloc(sizeof(struct connection)))) {
			log_msg(LOG_DEBUG, "malloc() error");
			break;
		}
		client_len = sizeof(con->sa);
		con->sd = accept(listen_sd, (struct sockaddr *) &con->sa, &client_len);
		if (con->sd == -1) {
			log_msg(LOG_DEBUG, "accept() failed: %s", strerror(errno));
			close(con->sd);
			free(con);
			continue;
		}
		err = pthread_create(&thread, &pth_attr, connection_thread, (void *) con);
		if (err != 0) {
			log_msg(LOG_DEBUG, "Can't create thread to serve client");
			close(con->sd);
			free(con);
		}
	}
	close (listen_sd);
	return 0;
}
