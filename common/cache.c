#include <unistd.h>
#include <sys/file.h>
#include <openssl/ssl.h>
#include <glib.h>

#include "scvp_defs.h"
#include "scvp_proto.h"
#include "cache.h"

#if 0
ASN1_INTEGER *convert_serial_to_asn1(const unsigned char *serial, int serial_len)
{
	ASN1_INTEGER *asn1_serial = NULL;
	BIGNUM *bn;

	if (!(bn = BN_bin2bn(serial, serial_len, NULL)))
		return NULL;
	asn1_serial = BN_to_ASN1_INTEGER(bn, NULL);
	BN_free(bn);
	return asn1_serial;
}
#endif

int convert_asn1_to_serial(const ASN1_INTEGER *asn1_serial, unsigned char *serial, unsigned int *serial_len)
{
	int err = 1, len;
	BIGNUM *bn;

	if (!(bn = ASN1_INTEGER_to_BN(asn1_serial, NULL)))
		return 1;
	if (BN_is_negative(bn) ||  BN_is_zero(bn))
		goto end;
	len = BN_bn2bin(bn, serial);
	if (len <= 0 || len > X509_SERIAL_NUMBER_MAX_SIZE)
		goto end;
	*serial_len = len;
	err = 0;

end:
	BN_free(bn);
	return err;
}

static FILE *open_cache_file(BIO *bio, const char *file_path, const char *__restrict modes)
{
	FILE *file;

	if (!(file = fopen(file_path, modes)))
		return NULL;
//	if (flock(fileno(file), LOCK_EX))
//		goto end;
	if (!BIO_set_fp(bio, file, BIO_NOCLOSE))
		goto end;
	return file;

end:
	fclose(file);
	return NULL;
}


static int read_cache_file(BIO *bio, X509 **cert, X509_CRL **crl, const char *file_path)
{
	FILE *file;

	if (!cert && !crl)
		return 1;
	if (!(file = open_cache_file(bio, file_path, "r")))
		return 1;
	if (cert) {
		if (!(*cert = PEM_read_bio_X509_AUX(bio, NULL, NULL, NULL)))
			goto end;
	} else {
		if (!(*crl = PEM_read_bio_X509_CRL(bio, NULL, NULL, NULL)))
			goto end;
	}
//	flock(fileno(file), LOCK_UN);
	fclose(file);
	return 0;

end:
	fclose(file);
	return 1;
}

static int write_cache_file(BIO *bio, X509 *cert, X509_CRL *crl, const char *file_path)
{
	FILE *file;

	if (!cert && !crl)
		return 1;
	if (!(file = open_cache_file(bio, file_path, "w")))
		return 1;
	if (cert) {
		if (!PEM_write_bio_X509_AUX(bio, cert))
			goto end;
	} else {
		if (!PEM_write_bio_X509_CRL(bio, crl))
			goto end;
	}
//	flock(fileno(file), LOCK_UN);
	fclose(file);
	return 0;

end:
	fclose(file);
	return 1;
}

struct scvp_cert_ref *get_cert_ref(const X509 *cert)
{
	struct scvp_cert_ref *cert_ref;

	if (!cert)
		return NULL;
	if (!(cert_ref = cert_ref_alloc()))
		return NULL;
	X509_digest(cert, EVP_sha1(), cert_ref->hash, &cert_ref->hash_len);
	cert_ref->hash_alg = HASH_ALG_SHA1;
	if (convert_asn1_to_serial(cert->cert_info->serialNumber, cert_ref->serial, &cert_ref->serial_len)) {
		cert_ref_free(cert_ref);
		return NULL;
	}
	return cert_ref;
}

int cert_ref_cmp(const struct scvp_cert_ref *cert1, const struct scvp_cert_ref *cert2)
{
	if (!cert1 || !cert2)
		return 1;
	if (cert1->serial_len != cert2->serial_len)
		return 1;
	if (memcmp(cert1->serial, cert2->serial, cert1->serial_len))
		return 1;
	if (cert1->hash_len != cert2->hash_len)
		return 1;
	if (memcmp(cert1->hash, cert2->hash, cert1->hash_len))
		return 1;
	return 0;
}

int check_cached_cert_ref(const struct scvp_cert_ref *cert_ref, const char *cache_path, X509 **cached_cert)
{
	int err = 0, i;
	BIO *bio;
	char file_name[32];
	gchar *file_path = NULL;
	X509 *cert_tmp = NULL;
	struct scvp_cert_ref *cached_cert_ref = NULL;

	if (!cert_ref || cert_ref->hash_len < 4)
		return -1;
	if (!(bio = BIO_new(BIO_s_file())))
		return -1;
	for (i = 0; i < MAX_CACHE_HASH_COLLISION_NUM; i++) {
		snprintf(file_name, sizeof(file_name),"%02x%02x%02x%02x.scvp%d", cert_ref->hash[0], cert_ref->hash[1],
				cert_ref->hash[2], cert_ref->hash[3], i);
		if (!(file_path = g_build_filename(cache_path, file_name, NULL)))
			goto end;
		if (access(file_path, F_OK)) {
			g_free(file_path);
			continue;
		}
		if (read_cache_file(bio, &cert_tmp, NULL, file_path)) {
			g_free(file_path);
			continue;
		}
		g_free(file_path);
		if (!(cached_cert_ref = get_cert_ref(cert_tmp))) {
			X509_free(cert_tmp);
			continue;
		}
		if (!cert_ref_cmp(cert_ref, cached_cert_ref)) {
			if (cached_cert)
				*cached_cert = cert_tmp;
			else
				X509_free(cert_tmp);
			err = 1;
			goto end;
		}
		X509_free(cert_tmp);
		cert_ref_free(cached_cert_ref);
		cached_cert_ref = NULL;
	}

end:
	BIO_free(bio);
	cert_ref_free(cached_cert_ref);
	return err;
}

int check_cached_cert(X509 *cert, const char *cache_path)
{
	int err = 0, i;
	unsigned long hash;
	char file_name[32];
	gchar *file_path;
	BIO *bio;
	X509 *cert_tmp;

	if (!(bio = BIO_new(BIO_s_file())))
		return -1;
	hash = X509_NAME_hash(X509_get_subject_name(cert));
	for (i = 0; i < MAX_CACHE_HASH_COLLISION_NUM; i++) {
		snprintf(file_name, sizeof(file_name),"%08lx.%d", hash, i);
		if (!(file_path = g_build_filename(cache_path, file_name, NULL)))
			goto end;
		if (access(file_path, F_OK)) {
			g_free(file_path);
			continue;
		}
		if (read_cache_file(bio, &cert_tmp, NULL, file_path)) {
			g_free(file_path);
			continue;
		}
		g_free(file_path);
		if (!X509_cmp(cert, cert_tmp)) {
			X509_free(cert_tmp);
			err = 1;
			goto end;
		}
		X509_free(cert_tmp);
	}

end:
	BIO_free(bio);
	return err;
}

static int create_cert_link(const X509 *cert, const char *cert_path, const char *cache_path)
{
	int err = 1, i;
	struct scvp_cert_ref *cert_ref;
	char file_name[32];
	gchar *link_path;


	if (!(cert_ref = get_cert_ref(cert)))
		return 1;
	for (i = 0; i < MAX_CACHE_HASH_COLLISION_NUM; i++) {
		snprintf(file_name, sizeof(file_name),"%02x%02x%02x%02x.scvp%d", cert_ref->hash[0], cert_ref->hash[1],
				cert_ref->hash[2], cert_ref->hash[3], i);
		if (!(link_path = g_build_filename(cache_path, file_name, NULL)))
			return 1;
		if (access(link_path, F_OK))
			break;
		g_free(link_path);
		link_path = NULL;
	}
	if (i == MAX_CACHE_HASH_COLLISION_NUM)
		goto end;
	if (symlink(cert_path, link_path))
		goto end;
	err = 0;

end:
	cert_ref_free(cert_ref);
	g_free(link_path);
	return err;
}

static int store_cert(X509 *cert, const char * cache_path)
{
	int err = 1, i;
	unsigned long hash;
	char file_name[32];
	gchar *file_path;
	BIO *bio = NULL;

	hash = X509_NAME_hash(X509_get_subject_name(cert));
	for (i = 0; i < MAX_CACHE_HASH_COLLISION_NUM; i++) {
		snprintf(file_name, sizeof(file_name),"%08lx.%d", hash, i);
		if (!(file_path = g_build_filename(cache_path, file_name, NULL)))
			return 1;
		if (access(file_path, F_OK))
			break;
		g_free(file_path);
		file_path = NULL;
	}
	if (i == MAX_CACHE_HASH_COLLISION_NUM)
		goto end;
	if (!(bio = BIO_new(BIO_s_file())))
		goto end;
	if (write_cache_file(bio, cert, NULL, file_path))
		goto end;
	if (create_cert_link(cert, file_path, cache_path))
		goto end;
	err = 0;

end:
	g_free(file_path);
	BIO_free(bio);
	return err;
}

int cache_cert(X509 *cert, const char *cache_path)
{
	int ret;

	if ((ret = check_cached_cert(cert, cache_path)) == -1)
		return 1;
	if (ret == 1)
		return 0;
	if (store_cert(cert, cache_path))
		return 1;
	return 0;
}

static int store_crl(X509_CRL *crl, const char *cache_path)
{
	int err = 1, i;
	unsigned long hash;
	BIO *bio = NULL;
	char file_name[32];
	gchar *file_path;

	hash = X509_NAME_hash(X509_CRL_get_issuer(crl));
	for (i = 0; i < MAX_CACHE_HASH_COLLISION_NUM; i++) {
		snprintf(file_name, sizeof(file_name),"%08lx.r%d", hash, i);
		if (!(file_path = g_build_filename(cache_path, file_name, NULL)))
			return 1;
		if (access(file_path, F_OK))
			break;
		g_free(file_path);
		file_path = NULL;
	}
	if (i == MAX_CACHE_HASH_COLLISION_NUM)
		goto end;
	if (!(bio = BIO_new(BIO_s_file())))
		goto end;
	if (write_cache_file(bio, NULL, crl, file_path))
		goto end;
	err = 0;

end:
	g_free(file_path);
	BIO_free(bio);
	return err;
}

static int update_crl(X509_CRL *crl, const char *cache_path)
{
	int err = 1, i;
	unsigned long hash;
	BIO *bio;
	X509_CRL *crl_cur;
	char file_name[32];
	gchar *file_path;

	if (!(bio = BIO_new(BIO_s_file())))
		return 1;
	hash = X509_NAME_hash(X509_CRL_get_issuer(crl));
	for (i = 0; i < MAX_CACHE_HASH_COLLISION_NUM; i++) {
		snprintf(file_name, sizeof(file_name),"%08lx.r%d", hash, i);
		if (!(file_path = g_build_filename(cache_path, file_name, NULL)))
			goto end;
		if (!access(file_path, F_OK)) {
			if (read_cache_file(bio, NULL, &crl_cur, file_path)) {
				g_free(file_path);
				file_path = NULL;
				continue;
			}
			if (!X509_NAME_cmp(X509_CRL_get_issuer(crl), X509_CRL_get_issuer(crl_cur)))	{
				X509_CRL_free(crl_cur);
				break;
			}
			X509_CRL_free(crl_cur);
		}
		g_free(file_path);
		file_path = NULL;
	}
	if (i == MAX_CACHE_HASH_COLLISION_NUM)
		goto end;
	if (write_cache_file(bio, NULL, crl, file_path))
		goto end;
	err = 0;

end:
	g_free(file_path);
	BIO_free(bio);
	return err;
}

int cache_crl(X509_STORE_CTX *store_ctx, X509_CRL *crl, const char *cache_path)
{
	int err = 0;
	X509_OBJECT xobj;

	if (X509_STORE_get_by_subject(store_ctx, X509_LU_CRL, X509_CRL_get_issuer(crl), &xobj)) {
		if (ASN1_INTEGER_get(crl->crl_number) > ASN1_INTEGER_get(xobj.data.crl->crl_number))
			if (!update_crl(crl, cache_path))
				err = 1;
		X509_OBJECT_free_contents(&xobj);
	} else {
		if (store_crl(crl, cache_path))
			err = 2;
	}
	return err;
}
