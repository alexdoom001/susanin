#include <string.h>
#include <syslog.h>
#include <glib.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>

#include "path_checker.h"
#include "ocsp_verify.h"
#include "config.h"
#include "logger.h"

static const struct validation_values val_values[] = {
	{"available",     CHECK_AVAILABLE},
	{"accurate",      CHECK_ACCURATE},
	{"peer",          CHECK_PEER},
	{"all",           CHECK_ALL},
	{"disable_nonce", DISABLE_NONCE}
};

struct config cfg;

struct config_cert_ref *config_cert_ref_alloc(void)
{
	struct config_cert_ref *cert_ref;

	if (!(cert_ref = malloc(sizeof(*cert_ref)))) {
		log_msg(LOG_ERR, "malloc() failed");
		return NULL;
	}
	memset(cert_ref, 0, sizeof(*cert_ref));
	return cert_ref;
}

void config_cert_ref_free(struct config_cert_ref *cert_ref)
{
	if (!cert_ref)
		return;
	ASN1_INTEGER_free(cert_ref->serial);
	free(cert_ref);
}

static int get_config_cert_ref_values(const char *cert_path, struct config_cert_ref *cert_ref)
{
	int err = 1;
	BIO *bio;
	X509 *cert = NULL;

	if (!(bio = BIO_new(BIO_s_file())))
		return 1;
	if (!BIO_read_filename(bio, cert_path))
		goto end;
	if (!(cert = PEM_read_bio_X509_AUX(bio, NULL, NULL, NULL)))
		goto end;
	if (!(cert_ref->serial = ASN1_INTEGER_dup(X509_get_serialNumber(cert))))
		goto end;
	X509_digest(cert, EVP_sha1(), cert_ref->hash, &cert_ref->hash_len);
	err = 0;

end:
	X509_free(cert);
	BIO_free(bio);
	return err;
}

static struct config_cert_ref *find_config_cert_ref(X509 *cert)
{
	struct config_cert_ref *cert_ref = NULL;
	ASN1_INTEGER *serial;
	unsigned char hash[EVP_MAX_MD_SIZE];
	unsigned int hash_len;
	GSList *iterator;

	X509_digest(cert, EVP_sha1(), hash, &hash_len);
	serial = X509_get_serialNumber(cert);
	for (iterator = cfg.config_cert_list; iterator; iterator = g_slist_next(iterator)) {
		struct config_cert_ref *tmp_ref;

		tmp_ref = (struct config_cert_ref*)iterator->data;
		if (!M_ASN1_INTEGER_cmp(serial, tmp_ref->serial))
			if (!memcmp(hash, tmp_ref->hash, hash_len)) {
				cert_ref = tmp_ref;
				break;
			}
	}
	return cert_ref;
}

int get_cert_values(X509 *cert, int type)
{
	int values;
	struct config_cert_ref *cert_ref;

	cert_ref = find_config_cert_ref(cert);
	if (cert_ref != NULL) {
		if (type == CRL_VALUES) {
			if (cert_ref->crl_values & UNDEFINED_VALUE)
				values = cfg.crl_values;
			else
				values = cert_ref->crl_values;
		} else {
			if (cert_ref->ocsp_values & UNDEFINED_VALUE)
				values = cfg.ocsp_values;
			else
				values = cert_ref->ocsp_values;
		}
	} else {
		if (type == CRL_VALUES)
			values = cfg.crl_values;
		else
			values = cfg.ocsp_values;
	}
	return values;
}

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

#if 0
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
#endif

static int chech_crl_validation_values(gchar **str_vals, gsize str_num, unsigned int *crl_vals)
{
	int i, j, values;

	for (i = 0, values = 0; i < str_num; i++)
		for (j = 0; j < sizeof(val_values)/sizeof(val_values[0]); j++)
			if ((strcmp(str_vals[i], val_values[j].value) == 0) &&
					(val_values[j].flag != DISABLE_NONCE)) {
				values |= val_values[j].flag;
				break;
			}
	if ((values & CHECK_AVAILABLE) && (values & CHECK_ACCURATE)) {
		log_msg(LOG_DEBUG, "CRL validation values error: both available and accurate defined");
		return 1;
	}
	if ((values & CHECK_PEER) && (values & CHECK_ALL)) {
		log_msg(LOG_DEBUG, "CRL validation values error: both peer and all defined");
		return 1;
	}
	if (!((values & CHECK_AVAILABLE) || (values & CHECK_ACCURATE)))
		values = 0;
	else if (!((values & CHECK_PEER) || (values & CHECK_ALL))) {
		log_msg(LOG_DEBUG, "CRL validation values error: peer or all should be defined");
		return 1;
	}

	*crl_vals = values;
	return 0;
}

static int chech_ocsp_validation_values(gchar **str_vals, gsize str_num, unsigned int *ocsp_vals)
{
	int i, j, values;

	for (i = 0, values = 0; i < str_num; i++)
		for (j = 0; j < sizeof(val_values)/sizeof(val_values[0]); j++)
			if (strcmp(str_vals[i], val_values[j].value) == 0) {
				values |= val_values[j].flag;
				break;
			}

	if ((values & CHECK_AVAILABLE) && (values & CHECK_ACCURATE)) {
		log_msg(LOG_DEBUG, "OCSP validation values error: both available and accurate defined");
		return 1;
	}
	if ((values & CHECK_PEER) && (values & CHECK_ALL)) {
		log_msg(LOG_DEBUG, "OCSP validation values error: both peer and all defined");
		return 1;
	}
	if (!((values & CHECK_AVAILABLE) || (values & CHECK_ACCURATE)))
		values = 0;
	else if (!((values & CHECK_PEER) || (values & CHECK_ALL))) {
		log_msg(LOG_DEBUG, "OCSP validation values error: peer or all should be defined");
		return 1;
	}

	*ocsp_vals = values;
	return 0;
}

static int get_global_validation_values(GKeyFile *key_file)
{
	gchar **str_vals;
	gsize str_num;

	str_vals = g_key_file_get_string_list(key_file, "validation_values", "crl", &str_num, NULL);
	if (!str_vals) {
		log_msg(LOG_DEBUG, "Failed to get global CRL validation values");
		return 1;
	}
	if (chech_crl_validation_values(str_vals, str_num, &cfg.crl_values)) {
		g_strfreev(str_vals);
		return 1;
	}
	g_strfreev(str_vals);

	str_vals = g_key_file_get_string_list(key_file, "validation_values", "ocsp", &str_num, NULL);
	if (!str_vals) {
		log_msg(LOG_DEBUG, "Failed to get global OCSP validation values");
		return 1;
	}
	if (chech_ocsp_validation_values(str_vals, str_num, &cfg.ocsp_values)) {
		g_strfreev(str_vals);
		return 1;
	}
	g_strfreev(str_vals);

	return 0;
}

static int get_cert_validation_values(GKeyFile *key_file)
{
	int err = 1, i;
	gchar **groups;
	gsize len;

	if (!(groups = g_key_file_get_groups(key_file, &len))) {
		log_msg(LOG_DEBUG, "Failed to parse configuration file");
		return 1;
	}

	for (i = 0, cfg.config_cert_list = NULL; i < len; i++) {
		struct config_cert_ref *cert_ref;
		gchar **str_vals;
		gsize str_num;
		char *ca_path;

		if (!strncmp(groups[i], "ca_", 3)) {
			if (!(cert_ref = config_cert_ref_alloc()))
				goto end;
			if (file_get_string(key_file, groups[i], "ca_path", &ca_path)) {
				config_cert_ref_free(cert_ref);
				goto end;
			}
			if (get_config_cert_ref_values(ca_path, cert_ref)) {
				log_msg(LOG_DEBUG, "Certificate file %s read failed", ca_path);
				config_cert_ref_free(cert_ref);
				free(ca_path);
				goto end;
			}
			free(ca_path);

			str_vals = g_key_file_get_string_list(key_file, groups[i], "crl", &str_num, NULL);
			if (str_vals) {
				if (chech_crl_validation_values(str_vals, str_num, &cert_ref->crl_values)) {
					config_cert_ref_free(cert_ref);
					g_strfreev(str_vals);
					goto end;
				}
				g_strfreev(str_vals);
			} else
				cert_ref->crl_values = UNDEFINED_VALUE;

			str_vals = g_key_file_get_string_list(key_file, groups[i], "ocsp", &str_num, NULL);
			if (str_vals) {
				if (chech_crl_validation_values(str_vals, str_num, &cert_ref->ocsp_values)) {
					config_cert_ref_free(cert_ref);
					g_strfreev(str_vals);
					goto end;
				}
				g_strfreev(str_vals);
			} else
				cert_ref->ocsp_values = UNDEFINED_VALUE;

			cfg.config_cert_list = g_slist_append(cfg.config_cert_list, cert_ref);
		}
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
	if (get_global_validation_values(key_file))
		goto end;
	if (get_cert_validation_values(key_file))
		goto end;
	if (get_path_values(key_file))
		goto end;
	err = 0;

end:
	g_key_file_free(key_file);
	return err;
}
