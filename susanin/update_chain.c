#include <syslog.h>
#include <openssl/x509v3.h>
#include <openssl/ssl.h>
#include <glib.h>
#include <curl/curl.h>
#include <ctype.h>
#include <string.h>

#include "cache.h"
#include "logger.h"
#include "cache.h"
#include "config.h"
#include "update_chain.h"

extern struct config cfg;

enum LDIF2PEM_state{
	STATE_START = 0,
	STATE_ATTR,
	STATE_DATA,
	STATE_DATA_LINE_END,
	STATE_DATA_END,
	STATE_DONE
};

struct LDIF2PEM_data {
	FILE* file;
	size_t file_data_size;
	enum LDIF2PEM_state state;
	const char *attr_name;
	char *attr_cmp;
	const char *pem_str;
	int err;
};

size_t LDIF2PEM(char *ptr, size_t membsize, size_t nmemb, void *userdata)
{
	struct LDIF2PEM_data *arg = (struct LDIF2PEM_data *)userdata;
	const char *header = "-----BEGIN %s-----\n";
	const char *footer = "-----END %s-----\n";
	size_t size = membsize*nmemb, i, l;
	if (arg == NULL
			|| arg->file == NULL
			|| arg->attr_name == NULL
			|| arg->pem_str == NULL) {
		log_msg(LOG_DEBUG, "%s bad argument", __FUNCTION__);
		return 0;
	}
	if (ptr == NULL
			|| size == 0) {
		log_msg(LOG_DEBUG, "%s bad ptr", __FUNCTION__);
		return 0;
	}

parse:
	if (size == 0)
		return membsize*nmemb;

	switch (arg->state) {
		case STATE_START:
			arg->attr_cmp = arg->attr_name;
			arg->state = STATE_ATTR;
			arg->err = 1;
		case STATE_ATTR:
			while (*arg->attr_cmp != '\0' && size > 0) {
				if (toupper(*ptr) == toupper(*arg->attr_cmp)) {
					arg->attr_cmp++;
				}
				else {
					arg->attr_cmp = arg->attr_name;
				}
				ptr++;
				size--;
			}

			if (*arg->attr_cmp == '\0') {
				arg->state = STATE_DATA;
				i = strlen(header) - 2 /*%s*/ + strlen(arg->pem_str);
				if (fprintf(arg->file, header, arg->pem_str) != i)
					arg->err = 1;
			}

			goto parse;
		case STATE_DATA:
			for (i = 0; i < size && *(ptr + i) != '\n'; i++);

			while (i != 0) {
				l = i > 64 ? 64 : i;
				if (l + (arg->file_data_size % 64) > 64)
					l = 64 - (arg->file_data_size % 64);

				if (fwrite(ptr, l, 1, arg->file) != 1)
					arg->err = 1;
				arg->file_data_size += l;
				if (arg->file_data_size % 64 == 0
						&& (fprintf(arg->file, "\n") != 1))
					arg->err = 1;

				i -= l;
				ptr += l;
				size -= l;
			}

			if (size > 0 && *ptr == '\n') {
				arg->state = STATE_DATA_LINE_END;
			}
			goto parse;

		case STATE_DATA_LINE_END:
			switch (*ptr) {
				case ' ':
					arg->state = STATE_DATA;
					break;
				case '\n':
					arg->state = STATE_DATA_END;
					break;
				default: arg->err = 1;
			}
			ptr++;
			size--;
			goto parse;

		case STATE_DATA_END:
			if (arg->file_data_size % 64 != 0
					&& (fprintf(arg->file, "\n") != 1))
				arg->err = 1;
			i = strlen(footer) - 2 /*%s*/ + strlen(arg->pem_str);
			if (fprintf(arg->file, footer, arg->pem_str) != i)
				arg->err = 1;
			arg->state = STATE_DONE;
			arg->err = 0;
			break;

		default:
			return membsize*nmemb;
	}

	return membsize*nmemb;
}

static char **get_ca_issuers(X509 *cert, int *str_num)
{
	int i;
	AUTHORITY_INFO_ACCESS *info;
	ACCESS_DESCRIPTION *ad;
	char **str = NULL, **ptr;

	info = X509_get_ext_d2i(cert, NID_info_access, NULL, NULL);
	if (!info)
		return NULL;
	*str_num = 0;
	for (i = 0; i < sk_ACCESS_DESCRIPTION_num(info); i++) {
		ad = sk_ACCESS_DESCRIPTION_value(info, i);
		if (OBJ_obj2nid(ad->method) == NID_ad_ca_issuers) {
			if (ad->location->type == GEN_URI) {
				(*str_num)++;
				ptr = str;
				if (!(str = realloc(ptr ,sizeof(char*) * (*str_num)))) {
					AUTHORITY_INFO_ACCESS_free(info);
					free(ptr);
					return NULL;
				}
				str[(*str_num) - 1] = strdup((char*)ad->location->d.ia5->data);
			}
		}
	}
	AUTHORITY_INFO_ACCESS_free(info);
	return str;
}

static char **get_crldps(X509 *cert, int *str_num)
{
	int i, j;
	DIST_POINT *dp;
	GENERAL_NAME *gen;
	char **str = NULL, **ptr;
	STACK_OF(DIST_POINT) *crldp;

	crldp = X509_get_ext_d2i(cert, NID_crl_distribution_points, NULL, NULL);
	if (!crldp)
		return NULL;
	*str_num = 0;
	for (i = 0; i < sk_DIST_POINT_num(crldp); i++) {
		dp = sk_DIST_POINT_value(crldp, i);
		if (!dp->distpoint)
			continue;
		for (j = 0; j < sk_GENERAL_NAME_num(dp->distpoint->name.fullname); j++) {
			gen = sk_GENERAL_NAME_value(dp->distpoint->name.fullname, j);
			if (gen->type == GEN_URI) {
				(*str_num)++;
				ptr = str;
				if (!(str = realloc(ptr ,sizeof(char*) * (*str_num)))) {
					CRL_DIST_POINTS_free(crldp);
					free(ptr);
					return NULL;
				}
				str[(*str_num) - 1] = strdup((char*)gen->d.ia5->data);
			}
		}
	}
	CRL_DIST_POINTS_free(crldp);
    return str;
}

static int get_cert_from_hash(GHashTable *hash_table, const char *issuer, X509 **cert)
{
	int err = 1;
	char *cert_file;
	GSList *cert_list;
	BIO *bio = NULL;

	if (cert == NULL)
		return 1;

	if (!(cert_list = g_hash_table_lookup(hash_table, issuer))) {
		log_msg(LOG_DEBUG, "Failed to retrieve CA certificate for CRL");
		goto end;
	}

	cert_file = cert_list->data;
	if (!(bio = BIO_new(BIO_s_file())))
		goto end;
	if (read_cache_file(bio, cert, NULL, cert_file)) {
		log_msg(LOG_DEBUG, "Failed to read CA certificate");
		goto end;
	}

	err = 0;

end:
	BIO_free(bio);
	return err;
}

char* curl_load_file(const char* url, const char* tmp_path,
		const char* pem_string, const char* attr_name)
{
	int err = 1, fd;
	char *tmp_file;
	FILE *file = NULL;
	CURL *curl = NULL;
	struct LDIF2PEM_data arg = {0};
	arg.attr_name = attr_name;
	arg.pem_str = pem_string;
	arg.err = err;
	int ldap = strncmp("ldap", url, 4) == 0;

	if (!(tmp_file = g_build_filename(tmp_path, "susaninXXXXXXXX", NULL)))
		return NULL;
	if ((fd = mkstemp(tmp_file)) == -1)
		goto end;
	if (!(arg.file = file = fdopen(fd, "wb")))
		goto end;
	if (!(curl = curl_easy_init()))
		goto end;
	if ((curl_easy_setopt(curl, CURLOPT_URL, url)) != CURLE_OK)
		goto end;
	if ((curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION,
			ldap ? LDIF2PEM : NULL)) != CURLE_OK)
		goto end;
	if ((curl_easy_setopt(curl, CURLOPT_WRITEDATA,
			ldap ? &arg : file)) != CURLE_OK)
		goto end;
	if ((curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10)) != CURLE_OK)
		goto end;
	if ((curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1)))
		goto end;
	if ((curl_easy_perform(curl)) != CURLE_OK)
		goto end;
	err = ldap ? arg.err : 0;

end:
	curl_easy_cleanup(curl);
	if (file)
		fclose(file);
	if (!err)
		return tmp_file;
	remove(tmp_file);
	g_free(tmp_file);
	return NULL;
}

void load_ca(X509 *cert, STACK_OF(X509) *uchain, int depth)
{
	int i;
	BIO *bio;
	X509 *cert_tmp = NULL;
	EVP_PKEY *pkey;
	char *tmp_file = NULL;
	char **ca_issuers = NULL;
	int ca_issuers_num;

	if (depth > MAX_CERT_CHAIN_DEPTH)
		return;
	if (!(bio = BIO_new(BIO_s_file())))
		return;
	if (!(ca_issuers = get_ca_issuers(cert, &ca_issuers_num)))
		goto end;
	for (i = 0; i < ca_issuers_num; i++) {
		if (!(tmp_file = curl_load_file(ca_issuers[i], cfg.tmp_path,
		                                PEM_STRING_X509,
		                                "cACertificate;binary:: "))) {
			goto end;
		}
		if (!BIO_read_filename(bio, tmp_file))
			goto end;
		if (!(cert_tmp = PEM_read_bio_X509_AUX(bio, NULL, NULL, NULL)))
			goto end;
		remove(tmp_file);
		free(tmp_file);
		tmp_file = NULL;
		if (!(pkey = X509_get_pubkey(cert_tmp)))
			goto end;
		if (!X509_verify(cert_tmp, pkey)) {
			EVP_PKEY_free(pkey);
			goto end;
		}
		EVP_PKEY_free(pkey);
		if (!sk_X509_push(uchain, cert_tmp))
			goto end;
		load_ca(cert, uchain, depth + 1);
		X509_free(cert_tmp);
		cert_tmp = NULL;
	}

end:
	BIO_free(bio);
	if (ca_issuers) {
		for (i = 0; i < ca_issuers_num; i++)
			free(ca_issuers[i]);
		free(ca_issuers);
	}
	if (tmp_file) {
		remove(tmp_file);
		free(tmp_file);
	}
	X509_free(cert_tmp);
}

void load_ca_issuers(STACK_OF(X509) *uchain, int depth)
{
	int i;
	X509 *cert;

	if (!uchain)
		return;
	for (i = 0; i < sk_X509_num(uchain); i++) {
		if (!(cert = sk_X509_value(uchain, i)))
			return;
		load_ca(cert, uchain, depth);
	}
}

static int load_crl(const char* crl_url, X509 *cert, const char *crl_path, const char *tmp_path)
{
	int err = 1;
	char *tmp_file;
	BIO *bio = NULL;
	X509_CRL *crl = NULL;
	EVP_PKEY *pkey = NULL;
	int ldap = strncmp("ldap", crl_url, 4) == 0;

	if (!(tmp_file = curl_load_file(crl_url, tmp_path, PEM_STRING_X509_CRL,
		                            "certificateRevocationList;binary:: "))) {
		log_msg(LOG_DEBUG, "cURL failed to load CRL %s", crl_url);
		return 1;
	}
	if (!(bio = BIO_new(BIO_s_file())))
		goto end;
	if (!BIO_read_filename(bio, tmp_file))
		goto end;
	if (ldap || !(crl = d2i_X509_CRL_bio(bio, NULL)) )
		if (!(crl = PEM_read_bio_X509_CRL(bio, NULL, NULL, NULL))) {
			log_msg(LOG_DEBUG, "Failed to process loaded CRL");
			goto end;
		}
	if (!(pkey = X509_get_pubkey(cert))) {
		log_msg(LOG_DEBUG, "Failed to retrieve certificate public key");
		goto end;
	}
	if (!X509_CRL_verify(crl, pkey)) {
		log_msg(LOG_DEBUG, "Failed to verify CRL");
		goto end;
	}
	if (cache_crl(crl, cert, crl_path)) {
		log_msg(LOG_DEBUG, "Failed to cache CRL");
		goto end;
	}
	err = 0;

end:
	remove(tmp_file);
	free(tmp_file);
	BIO_free(bio);
	X509_CRL_free(crl);
	EVP_PKEY_free(pkey);
	return err;
}

static int update_cert_crl(X509 *ca_cert, X509 *cert, const char *crl_path, const char *tmp_path, int exactly)
{
	int i, crldps_num, err = 1;
	char **crldps;
	X509_CRL *crl;

	if (!exactly) {
		if ((crl = get_cert_crl(ca_cert, crl_path, NULL))) {
			ASN1_TIME *nextUpdate = X509_CRL_get_nextUpdate(crl);
			time_t tm = time(NULL);

			if (nextUpdate && ((X509_cmp_time(nextUpdate, &tm))) > 0) {
				X509_CRL_free(crl);
				return 0;
			}
		}
		X509_CRL_free(crl);
	}

	if (!(crldps = get_crldps(cert, &crldps_num)))
		return 0;
	for (i = 0; i < crldps_num; i++) {
		// RFC 5280 says: "If the DistributionPointName contains multiple
		//                values, each name describes a different mechanism
		//                to obtain the same CRL".
		// Оbserve "same" in the quote.
		if (load_crl(crldps[i], ca_cert, crl_path, tmp_path) == 0)
			err = 0;
		free(crldps[i]);
	}
	free(crldps);
	return err;
}

// It used as X509_STORE_CTX_verify
// 1 - Success
// 0 - Fail
int update_cert_chain_crl(X509_STORE_CTX *store_ctx)
{
	int i, ok = 1;
	X509 *ca_cert, *cert;

	ca_cert = sk_X509_value(store_ctx->chain, sk_X509_num(store_ctx->chain) - 1);
	if (ca_cert == NULL)
		return 1;

	for (i = sk_X509_num(store_ctx->chain) - 2; i >= 0; i--) {
		if (!(cert = sk_X509_value(store_ctx->chain, i)))
			break;
		if (update_cert_crl(ca_cert, cert, cfg.crl_path, cfg.tmp_path, 0) != 0)
			ok = 0;
		ca_cert = cert;
	}
	return ok;
}

static int hash_table_insert(GHashTable *hash_table, BIO *bio, char *file_path)
{
	X509 *cert;
	char *subject_name;
	GSList *cert_list;

	if (read_cache_file(bio, &cert, NULL, file_path))
		return 1;
	if (!(subject_name = X509_NAME_oneline(X509_get_subject_name(cert),
			NULL, 0))) {
		X509_free(cert);
		return 1;
	}

	cert_list = g_hash_table_lookup(hash_table, subject_name);
	cert_list = g_slist_append(cert_list, file_path);
	g_hash_table_insert(hash_table, subject_name, cert_list);

	X509_free(cert);
	return 0;
}

static GHashTable *hash_table_build(const char *cache_path)
{
	GDir *dir;
	BIO *bio = NULL;
	const gchar *file = NULL;
	GHashTable *hash_table = NULL;

	if (!(dir = g_dir_open(cache_path, 0, NULL))) {
		printf("Failed to open cache directory %s\n", cache_path);
		return NULL;
	}
	if (!(bio = BIO_new(BIO_s_file()))) {
		printf("OpenSSL BIO_new() failed");
		goto end;
	}
	if (!(hash_table = g_hash_table_new_full(g_str_hash, g_str_equal, free, NULL))) {
		printf("Failed to create hash table");
		goto end;
	}

	while ((file = g_dir_read_name(dir))) {
		gchar *file_path;

		if (!(file_path = g_build_filename(cache_path, file, NULL)))
			continue;
		if (g_file_test(file_path, G_FILE_TEST_IS_SYMLINK)) {
			g_free(file_path);
			continue;
		}
		if (hash_table_insert(hash_table, bio, file_path)) {
			g_free(file_path);
			continue;
		}
	}

end:
	g_dir_close(dir);
	BIO_free(bio);
	return hash_table;
}

static gboolean hash_table_destroy_value(gpointer key, gpointer value, gpointer data)
{
	GSList *iterator, *cert_list = value;

	for(iterator = cert_list; iterator; iterator = g_slist_next(iterator))
		free(iterator->data);
	g_slist_free(cert_list);
	return TRUE;
}

static void hash_table_destroy(GHashTable *hash_table)
{
	if (hash_table == NULL)
		return;
	g_hash_table_foreach_remove(hash_table, hash_table_destroy_value, NULL);
	g_hash_table_destroy(hash_table);
}

int update_ca_cert_crl(const char *cert_name, const char *ca_path, const char *crl_path,
		const char *tmp_path)
{
	int err = 1;
	GHashTable *hash_table = NULL;
	BIO *bio = NULL;
	gchar *file_path, *file_noext;
	X509 *cert = NULL;
	X509 *ca_cert = NULL;

	if (!(file_noext = g_build_filename(ca_path, cert_name, NULL)))
		return 1;
	if (!(file_path = g_strconcat(file_noext, ".pem", NULL))) {
		g_free(file_noext);
		return 1;
	}
	g_free(file_noext);

	if (!(bio = BIO_new(BIO_s_file())))
		goto end;

	if (!(hash_table = hash_table_build(ca_path)))
		goto end;

	if (read_cache_file(bio, &cert, NULL, file_path))
		goto end;

	g_free(file_path);
	file_path = NULL;

	err = 0;
	while (1) {
		char *issuer = NULL;

		if (!(issuer = X509_NAME_oneline(X509_get_issuer_name(cert),
				NULL, 0))) {
			log_msg(LOG_DEBUG, "Failed to retrieve issuer");
			err = 1;
			break;
		}
		if (get_cert_from_hash(hash_table, issuer, &ca_cert) != 0) {
			free(issuer);
			err = 1;
			break;
		}
		free(issuer);

		if (update_cert_crl(ca_cert, cert, crl_path, tmp_path, 1) != 0)
			err = 1;

		if (X509_cmp(cert, ca_cert) == 0) {
			X509_free(ca_cert);
			break;
		}

		X509_free(cert);
		cert = ca_cert;
	}

end:
	X509_free(cert);
	hash_table_destroy(hash_table);
	BIO_free(bio);
	g_free(file_path);
	return err;
}

int update_all_ca_certs_crl(const char *cert_path, const char *crl_path, const char *tmp_path)
{
	int err = 1;
	GDir *dir = NULL;
	const gchar *file = NULL;
	GHashTable *hash_table = NULL;
	BIO *bio = NULL;

	if (!(dir = g_dir_open(cert_path, 0, NULL))) {
		printf("Failed to open cache directory %s\n", cert_path);
		goto end;
	}
	if (!(hash_table = hash_table_build(cert_path)))
		goto end;

	if (!(bio = BIO_new(BIO_s_file())))
		goto end;

	err = 0;
	while ((file = g_dir_read_name(dir))) {
		gchar *file_path;
		X509 *cert = NULL;
		char *issuer = NULL;
		X509 *ca_cert = NULL;

		if (!(file_path = g_build_filename(cert_path, file, NULL)))
			continue;
		if (g_file_test(file_path, G_FILE_TEST_IS_SYMLINK)) {
			g_free(file_path);
			continue;
		}
		if (read_cache_file(bio, &cert, NULL, file_path)) {
			g_free(file_path);
			continue;
		}
		g_free(file_path);

		if (!(issuer = X509_NAME_oneline(X509_get_issuer_name(cert),
				NULL, 0))) {
			log_msg(LOG_DEBUG, "Failed to retrieve issuer");
			X509_free(cert);
			continue;
		}
		if (get_cert_from_hash(hash_table, issuer, &ca_cert) != 0) {
			free(issuer);
			X509_free(cert);
			continue;
		}
		free(issuer);

		if (update_cert_crl(ca_cert, cert, crl_path, tmp_path, 1) != 0)
			err = 1;

		X509_free(cert);
		X509_free(ca_cert);
	}

end:
	BIO_free(bio);
	hash_table_destroy(hash_table);
	g_dir_close(dir);
	return err;
}
