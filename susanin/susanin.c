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
#include <openssl/ssl.h>
#include <locale.h>

#include "connection.h"
#include "scvp_defs.h"
#include "scvp_proto.h"
#include "crypto_openssl.h"
#include "config.h"
#include "logger.h"
#include "update_chain.h"

struct command_line_values {
	char *conf_file;
	int daemon;
	int update_crl;
	char *ca_name;
	char *ca_path;
	char *crl_path;
	char *tmp_path;
};

extern struct config cfg;

struct scvp_proto_ctx *scvp_ctx;

static int parse_command_line(int argc, char *argv[], struct command_line_values *cmd_vals)
{
	GOptionContext *opt_ctx;
	GOptionEntry entries[] = {
		{ "config", 'c', 0, G_OPTION_ARG_STRING, &cmd_vals->conf_file, "configuration file", NULL},
		{ "daemonize", 'd', 0, G_OPTION_ARG_NONE, &cmd_vals->daemon, "run as daemon", NULL},
		{ "update-all-crl", 0, 0, G_OPTION_ARG_NONE, &cmd_vals->update_crl, "update all CA certificates CRL", NULL},
		{ "update-cert-crl", 0, 0, G_OPTION_ARG_STRING, &cmd_vals->ca_name, "update CA certificate CRL", NULL},
		{ "ca-cache-path", 0, 0, G_OPTION_ARG_STRING, &cmd_vals->ca_path, "CA certificates cache path", NULL},
		{ "crl-cache-path", 0, 0, G_OPTION_ARG_STRING, &cmd_vals->crl_path, "CRL cache path", NULL},
		{ "tmp-path", 0, 0, G_OPTION_ARG_STRING, &cmd_vals->tmp_path, "temporary files path", NULL},
		{ NULL }
	};

	memset(cmd_vals, 0, sizeof(*cmd_vals));
	if (!(opt_ctx = g_option_context_new("- PKI path validation daemon")))
		return 1;
	g_option_context_add_main_entries(opt_ctx, entries, NULL);
	if (!g_option_context_parse(opt_ctx, &argc, &argv, NULL)) {
		g_option_context_free(opt_ctx);
		fprintf(stderr, "Failed to parse command line\n");
		return 1;
	}
	if (cmd_vals->ca_name)
		cmd_vals->update_crl = 1;
	g_option_context_free(opt_ctx);
	return 0;
}

static void cmd_vals_free(struct command_line_values *cmd_vals)
{
	free(cmd_vals->conf_file);
	free(cmd_vals->ca_name);
	free(cmd_vals->ca_path);
	free(cmd_vals->crl_path);
	free(cmd_vals->tmp_path);
}

int main(int argc, char **argv) {
	int err = 1, listen_sd;
	unsigned int client_len;
	struct sockaddr_un sa_serv;
	pid_t pid, sid;
	FILE *pidf;
	pthread_attr_t pth_attr;
	pthread_t thread;
	struct connection *con;
	struct command_line_values cmd_vals;

	setlocale(LC_ALL,"");

	if (parse_command_line(argc, argv, &cmd_vals))
		return 1;

	if (cmd_vals.update_crl) {
		if (!cmd_vals.ca_path) {
			fprintf(stderr,"Failed to retrieve certificate cache path\n");
			goto end;
		}
		if (!cmd_vals.crl_path) {
			fprintf(stderr,"Failed to retrieve CRL cache path\n");
			goto end;
		}
		if (!cmd_vals.tmp_path) {
			fprintf(stderr,"Failed to retrieve temp files path\n");
			goto end;
		}
		if (cmd_vals.ca_name) {
			if (update_ca_cert_crl(cmd_vals.ca_name, cmd_vals.ca_path, cmd_vals.crl_path, cmd_vals.tmp_path))
				goto end;
		}
		else {
			if (update_all_ca_certs_crl(cmd_vals.ca_path, cmd_vals.crl_path, cmd_vals.tmp_path))
				goto end;
		}
		err = 0;
		goto end;
	}

	if (!cmd_vals.conf_file) {
		fprintf(stderr,"Failed to retrieve configuration file name\n");
		return 1;
	}
	cfg.daemon = cmd_vals.daemon;

	logger_init();

	if (!(scvp_ctx = scvp_init())) {
		log_msg(LOG_DEBUG, "Failed init SCVP protocol");
		return 1;
	}

	if (load_config(cmd_vals.conf_file) != 0)
		return 1;

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
	err = 0;

end:
	cmd_vals_free(&cmd_vals);
	openssl_deinit();
	return err;
}
