#ifndef CONFIG_H
#define CONFIG_H

#include <glib.h>

struct validation_values {
	char *value;
	unsigned int flag;
};

struct config {
	int daemon;
	char *socket_path;
	char *pid_path;
	char *ca_path;
	char *crl_path;
	char *tmp_path;
	char *untrusted_path;
	unsigned int crl_values;
	unsigned int ocsp_values;
	GSList *cert_ocsp_list;
};

struct config cfg;

int load_config(const char *conf_file);

#endif /* CONFIG_H */
