#include <string.h>
#include <syslog.h>
#include <glib.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>

#include "path_checker.h"
#include "ocsp_verify.h"
#include "config.h"
#include "logger.h"

struct validation_values val_values[] = {
	{"available",     CHECK_AVAILABLE},
	{"accurate",      CHECK_ACCURATE},
	{"peer",          CHECK_PEER},
	{"all",           CHECK_ALL},
	{"disable_nonce", DISABLE_NONCE}
};

static int file_get_string(GKeyFile *key_file, const gchar *group_name, const gchar *key, char **config_val)
{
	GError *gerr = NULL;
	gchar *str_value = NULL;

	str_value = g_key_file_get_string(key_file, group_name, key, NULL);
	if (gerr)
		if (gerr->code != G_KEY_FILE_ERROR_KEY_NOT_FOUND) {
			log_msg(LOG_DEBUG, "Failed to get %s %s", group_name, key);
			g_error_free(gerr);
			return 1;
		}
	if (str_value) {
		*config_val = g_strchomp(str_value);
		log_msg(LOG_DEBUG, "%s %s is set to %s", group_name, key, *config_val);
		return 0;
	}
	log_msg(LOG_DEBUG, "Failed to get %s %s", group_name, key);
	return 1;
}

static int file_get_integer(GKeyFile *key_file, const gchar *group_name, const gchar *key, unsigned int *config_val)
{
	GError *gerr = NULL;
	gint int_value = -1;

	int_value = g_key_file_get_integer(key_file, group_name, key, NULL);
	if (gerr)
		if (gerr->code != G_KEY_FILE_ERROR_KEY_NOT_FOUND) {
			log_msg(LOG_DEBUG, "Failed to get %s %s", group_name, key);
			g_error_free(gerr);
			return 1;
		}
	*config_val = int_value;
	log_msg(LOG_DEBUG, "%s %s is set to %d", group_name, key, *config_val);
	return 0;
}

static int get_cert_values(const char *cret_path, struct cert_ocsp_ref *cert_ocsp)
{
	int err = 1;
	BIO *bio;
	X509 *cert = NULL;

	if (!(bio = BIO_new(BIO_s_file()))) {
		log_msg(LOG_DEBUG, "OpenSSL BIO_new() failed");
		return 1;
	}
	if (!BIO_read_filename(bio, cret_path)) {
		log_msg(LOG_DEBUG, "Certificate file %s read failed", cret_path);
		goto end;
	}
	if (!(cert = PEM_read_bio_X509_AUX(bio, NULL, NULL, NULL))) {
		log_msg(LOG_DEBUG, "Certificate file %s parse failed", cret_path);
		goto end;
	}
	if (!(cert_ocsp->serial = ASN1_INTEGER_dup(X509_get_serialNumber(cert)))) {
		log_msg(LOG_DEBUG, "OpenSSL ASN1_INTEGER_dup() failed");
		goto end;
	}
	X509_digest(cert, EVP_sha1(), cert_ocsp->hash, &cert_ocsp->hash_len);
	err = 0;

end:
	X509_free(cert);
	BIO_free(bio);
	return err;
}

static int get_validation_values(GKeyFile *key_file)
{
	int i, j;
	gchar **str_vals;
	gsize len;

	str_vals = g_key_file_get_string_list(key_file, "validation_values", "crl", &len, NULL);
	if (!str_vals) {
		log_msg(LOG_DEBUG, "Failed to get CRL validation values");
		return 1;
	}

	cfg.crl_values = 0;
	for (i = 0; i < len; i++)
		for (j = 0; j < sizeof(val_values)/sizeof(val_values[0]); j++)
			if (!strcmp(str_vals[i], val_values[j].value) && (val_values[j].flag != DISABLE_NONCE)) {
				cfg.crl_values |= val_values[j].flag;
				break;
			}
	g_strfreev(str_vals);

	if ((cfg.crl_values & CHECK_AVAILABLE) && (cfg.crl_values & CHECK_ACCURATE)) {
		log_msg(LOG_DEBUG, "CRL validation values error: both available and accurate defined");
		return 1;
	}
	if ((cfg.crl_values & CHECK_PEER) && (cfg.crl_values & CHECK_ALL)) {
		log_msg(LOG_DEBUG, "CRL validation values error: both peer and all defined");
		return 1;
	}
	if (!((cfg.crl_values & CHECK_AVAILABLE) || (cfg.crl_values & CHECK_ACCURATE)))
		cfg.crl_values = 0;
	else if (!((cfg.crl_values & CHECK_PEER) || (cfg.crl_values & CHECK_ALL))) {
		log_msg(LOG_DEBUG, "CRL validation values error: peer or all should be defined");
		return 1;
	}

	str_vals = g_key_file_get_string_list(key_file, "validation_values", "ocsp", &len, NULL);
	if (!str_vals) {
		log_msg(LOG_DEBUG, "Failed to get OCSP validation values");
		return 1;
	}

	cfg.ocsp_values = 0;
	for (i = 0; i < len; i++)
		for (j = 0; j < sizeof(val_values)/sizeof(val_values[0]); j++)
			if (!strcmp(str_vals[i], val_values[j].value)) {
				cfg.ocsp_values |= val_values[j].flag;
				break;
			}
	g_strfreev(str_vals);

	if ((cfg.ocsp_values & CHECK_AVAILABLE) && (cfg.ocsp_values & CHECK_ACCURATE)) {
		log_msg(LOG_DEBUG, "OCSP validation values error: both available and accurate defined");
		return 1;
	}
	if ((cfg.ocsp_values & CHECK_PEER) && (cfg.ocsp_values & CHECK_ALL)) {
		log_msg(LOG_DEBUG, "OCSP validation values error: both peer and all defined");
		return 1;
	}
	if (!((cfg.ocsp_values & CHECK_AVAILABLE) || (cfg.ocsp_values & CHECK_ACCURATE)))
		cfg.ocsp_values = 0;
	else if (!((cfg.ocsp_values & CHECK_PEER) || (cfg.ocsp_values & CHECK_ALL))) {
		log_msg(LOG_DEBUG, "OCSP validation values error: peer or all should be defined");
		return 1;
	}

	return 0;
}

static int get_ocsp_url_values(GKeyFile *key_file)
{
	int err = 1, i;
	gchar **groups;
	gsize len;
	struct cert_ocsp_ref *cert_ocsp;
	char *ca_path;

	if (!(groups = g_key_file_get_groups(key_file, &len))) {
		log_msg(LOG_DEBUG, "Failed to parse configuration file");
		return 1;
	}

	cfg.cert_ocsp_list = NULL;
	for (i = 0; i < len; i++)
		if (!strncmp(groups[i], "ca_", 3)) {
			if (!(cert_ocsp = cert_ocsp_alloc()))
				goto end;
			if (file_get_string(key_file, groups[i], "url", &cert_ocsp->url)) {
				cert_ocsp_free(cert_ocsp);
				goto end;
			}
			if (file_get_string(key_file, groups[i], "ca_path", &ca_path)) {
				cert_ocsp_free(cert_ocsp);
				goto end;
			}
			if (file_get_integer(key_file, groups[i], "validate", &cert_ocsp->validate)) {
				cert_ocsp_free(cert_ocsp);
				goto end;
			}
			if (get_cert_values(ca_path, cert_ocsp)) {
				cert_ocsp_free(cert_ocsp);
				goto end;
			}
			cfg.cert_ocsp_list = g_slist_append(cfg.cert_ocsp_list, cert_ocsp);
		}
	err = 0;

end:
	g_strfreev(groups);
	return err;
}

int get_path_values(GKeyFile *key_file)
{
	cfg.socket_path = cfg.pid_path = cfg.ca_path = cfg.crl_path = cfg.tmp_path = NULL;
	if (file_get_string(key_file, "path_values", "socket_file", &cfg.socket_path))
		return 1;
	if (file_get_string(key_file, "path_values", "pid_file", &cfg.pid_path))
		goto end;
	if (file_get_string(key_file, "path_values", "ca_path", &cfg.ca_path))
		goto end;
	if (file_get_string(key_file, "path_values", "crl_path", &cfg.crl_path))
		goto end;
	if (file_get_string(key_file, "path_values", "tmp_path", &cfg.tmp_path))
		goto end;
	if (file_get_string(key_file, "path_values", "untrusted_path", &cfg.untrusted_path))
		goto end;
	return 0;

end:
	free(cfg.socket_path);
	free(cfg.pid_path);
	free(cfg.ca_path);
	free(cfg.crl_path);
	free(cfg.tmp_path);
	free(cfg.untrusted_path);
	return 1;
}

int load_config(const char *conf_file)
{
	int err = 1;
	GKeyFile *key_file;

	if (!(key_file = g_key_file_new())) {
		log_msg(LOG_DEBUG, "g_key_file_new() failed");
		return 1;
	}
	if (!g_key_file_load_from_file(key_file, conf_file, G_KEY_FILE_NONE, NULL)) {
		log_msg(LOG_DEBUG, "Failed to load configuration file %s", conf_file);
		goto end;
	}
	if (get_validation_values(key_file))
		goto end;
	if (get_ocsp_url_values(key_file))
		goto end;
	if (get_path_values(key_file))
		goto end;
	err = 0;

end:
	g_key_file_free(key_file);
	return err;
}
