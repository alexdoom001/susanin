#include <string.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <glib.h>
#include <glib/gstdio.h>
#include <sys/file.h>

#include "scvp_defs.h"
#include "cache.h"

#define UPDATE_X509 0x01
#define UPDATE_CRL  0x02
#define SCVP_LINKS  0x04

static int check_cert_coincidence(const X509 *cert, const char *cache_path, const char *draft_name)
{
	int err = 1, i;
	char file_name[32];
	gchar *file_path;
	BIO *bio;
	X509 *cert_cur;

	if (!(bio = BIO_new(BIO_s_file()))) {
		printf("OpenSSL BIO_new() failed\n");
		return 1;
	}

	for (i = 0; i < MAX_CACHE_HASH_COLLISION_NUM; i++) {
		snprintf(file_name, sizeof(file_name),"%s%d", draft_name, i);
		if (!(file_path = g_build_filename(cache_path, file_name, NULL))) {
			printf("g_build_filename() failed\n");
			goto end;
		}
		if (access(file_path, F_OK)) {
			g_free(file_path);
			file_path = NULL;
			continue;
		}
		if (BIO_read_filename(bio, file_path) <= 0) {
			g_free(file_path);
			file_path = NULL;
			continue;
		}
		if (!(cert_cur = PEM_read_bio_X509_AUX(bio, NULL, NULL, NULL))) {
			g_free(file_path);
			file_path = NULL;
			continue;
		}
		if (!X509_cmp(cert, cert_cur))
			goto end;
		g_free(file_path);
		file_path = NULL;
	}
	if (i == MAX_CACHE_HASH_COLLISION_NUM)
		err = 0;

end:
	BIO_free(bio);
	g_free(file_path);
	return err;
}

static int check_crl_coincidence(const X509_CRL *crl, const char *cache_path, const char *draft_name)
{
	int err = 1, i;
	char file_name[32];
	gchar *file_path;
	BIO *bio;
	X509_CRL *crl_cur;

	if (!(bio = BIO_new(BIO_s_file()))) {
		printf("OpenSSL BIO_new() failed\n");
		return 1;
	}

	for (i = 0; i < MAX_CACHE_HASH_COLLISION_NUM; i++) {
		snprintf(file_name, sizeof(file_name),"%s%d", draft_name, i);
		if (!(file_path = g_build_filename(cache_path, file_name, NULL))) {
			printf("g_build_filename() failed\n");
			goto end;
		}
		if (access(file_path, F_OK)) {
			g_free(file_path);
			file_path = NULL;
			continue;
		}
		if (BIO_read_filename(bio, file_path) <= 0) {
			g_free(file_path);
			file_path = NULL;
			continue;
		}
		if (!(crl_cur = PEM_read_bio_X509_CRL(bio, NULL, NULL, NULL))) {
			g_free(file_path);
			file_path = NULL;
			continue;
		}
		//if (!X509_CRL_cmp(crl, crl_cur))
		if (!memcmp(crl->sha1_hash, crl_cur->sha1_hash, SHA_DIGEST_LENGTH))
			goto end;
		g_free(file_path);
		file_path = NULL;
	}
	if (i == MAX_CACHE_HASH_COLLISION_NUM)
		err = 0;

end:
	BIO_free(bio);
	g_free(file_path);
	return err;
}

static int create_file_link(const char *cert_file, const char *cache_path, const char *draft_name)
{
	int err = 1, i;
	char file_name[32];
	gchar *file_path;

	for (i = 0; i < MAX_CACHE_HASH_COLLISION_NUM; i++) {
		snprintf(file_name, sizeof(file_name),"%s%d", draft_name, i);
		if (!(file_path = g_build_filename(cache_path, file_name, NULL)))
			goto end;
		if (access(file_path, F_OK))
			break;
		g_free(file_path);
		file_path = NULL;
	}
	if (i == MAX_CACHE_HASH_COLLISION_NUM)
		goto end;
	if (symlink(cert_file, file_path))
		goto end;
	err = 0;

end:
	g_free(file_path);
	return err;
}

static void update_cert_link(BIO *bio, const char *cert_file, const char *cache_path, int flags)
{
	X509 *cert;
	struct scvp_cert_ref *cert_ref;
	char draft_name[32];
	unsigned long hash;

	if (!(cert = PEM_read_bio_X509_AUX(bio, NULL, NULL, NULL))) {
		printf("OpenSSL PEM_read_bio_X509_AUX() failed\n");
		return;
	}
	if (!(cert_ref = get_cert_ref(cert))) {
		printf("Failed to get certificate reference %s\n", cert_file);
		return;
	}

	if (flags & SCVP_LINKS) {
		snprintf(draft_name, sizeof(draft_name),"%02x%02x%02x%02x.scvp", cert_ref->hash[0], cert_ref->hash[1],
				cert_ref->hash[2], cert_ref->hash[3]);
		if (!check_cert_coincidence(cert, cache_path, draft_name))
			if (create_file_link(cert_file, cache_path, draft_name)) {
				printf("Failed to create certificate symlink1\n");
				return;
			}
	}

	hash = X509_NAME_hash(X509_get_subject_name(cert));
	snprintf(draft_name, sizeof(draft_name),"%08lx.", hash);
	if (!check_cert_coincidence(cert, cache_path, draft_name))
		if (create_file_link(cert_file, cache_path, draft_name)) {
			printf("Failed to create certificate symlink2\n");
			return;
		}
}

static void update_crl_link(BIO *bio, const char *cert_file, const char *cache_path)
{
	X509_CRL *crl;
	char draft_name[32];
	unsigned long hash;

	if (!(crl = PEM_read_bio_X509_CRL(bio, NULL, NULL, NULL)))
		return;

	hash = X509_NAME_hash(X509_CRL_get_issuer(crl));
	snprintf(draft_name, sizeof(draft_name),"%08lx.r", hash);
	if (!check_crl_coincidence(crl, cache_path, draft_name))
		if (create_file_link(cert_file, cache_path, draft_name)) {
			printf("Failed to create certificate symlink2\n");
			return;
		}
}

static void remove_symlink(const char *file)
{
	if (g_file_test(file, G_FILE_TEST_IS_SYMLINK))
    	g_remove(file);
}

static void update_links(const char *target_dir, int flags)
{
	GDir *dir;
	BIO *bio;
	const gchar* file = NULL;
	gchar* file_path;

	if (!(dir = g_dir_open(target_dir, 0, NULL))) {
		printf("Failed to open directory %s\n", target_dir);
		return;
	}
	if (!(bio = BIO_new(BIO_s_file()))) {
		printf("OpenSSL BIO_new() failed");
		return;
	}

	while ((file = g_dir_read_name(dir))) {
		if (!(file_path = g_build_filename(target_dir, file, NULL)))
			continue;
		remove_symlink(file_path);
		g_free(file_path);
	}

	g_dir_rewind(dir);
	while ((file = g_dir_read_name(dir))) {
		if (!(file_path = g_build_filename(target_dir, file, NULL)))
			continue;
		if (BIO_read_filename(bio, file_path) <= 0) {
			g_free(file_path);
			continue;
		}
		if (flags & UPDATE_X509)
			update_cert_link(bio, file, target_dir, flags);
		else
			update_crl_link(bio, file, target_dir);
		g_free(file_path);
	}
	g_dir_close(dir);
	BIO_free(bio);
}

int main(int argc, char **argv)
{
	int flags = 0;

	if (argc != 3 && argc != 4) {
		printf("Usage: rehash [path] [ X509 | CRL ] [scvplinks]\n");
		printf("X509 - certificate files\n");
		printf("CRL - CRL files\n");
		return 1;
	}
	if (!strcmp(argv[2], "X509"))
		flags = UPDATE_X509;
	else if (!strcmp(argv[2], "CRL"))
		flags = UPDATE_CRL;
	else {
		printf("Unknown rehash type\n");
		return 1;
	}
	if (argc == 4 && !strcmp(argv[3], "scvplinks"))
		flags |= SCVP_LINKS;
	update_links(argv[1], flags);
	return 0;
}
