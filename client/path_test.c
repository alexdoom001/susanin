#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <pthread.h>
#include <glib.h>

#include "scvp_cli.h"
#include "path_test.h"
#include "test_tables.c"

#define MAX_THREAD_NUMBER 1

int print_error;
const char *socket_file, *anchor_path, *untrusted_path;

X509 *load_cert(const char *file)
{
	BIO *bio;
	X509 *cert = NULL;

	if (!(bio = BIO_new(BIO_s_file()))) {
		fprintf(stderr, "OpenSSL BIO_new() failed\n");
		return NULL;
	}
	if (BIO_read_filename(bio, file) <= 0) {
		fprintf(stderr, "OpenSSL BIO_new() failed\n");
		goto end;
	}
	if (!(cert = PEM_read_bio_X509_AUX(bio, NULL, NULL, NULL))) {
		fprintf(stderr, "OpenSSL PEM_read_bio_X509_AUX() failed\n");
		goto end;
	}

end:
	BIO_free(bio);
	return cert;
}

void chain_free(STACK_OF(X509) *uchain)
{
	X509 *cert;

	if (!uchain)
		return;
	while (1) {
		if (!(cert = sk_X509_pop(uchain)))
			break;
		X509_free(cert);
	}
	sk_X509_free(uchain);
}

STACK_OF(X509) *get_uchain(X509 *cert, const char *untrust_path, int depth)
{
	int res, num = 1;
	X509_STORE *store;
	X509_LOOKUP *lookup;
	X509_STORE_CTX *store_ctx = NULL;
	STACK_OF(X509) *uchain = NULL;
	X509 *x, *xtmp;

	if (!(store = X509_STORE_new()))
		return NULL;
	if (!(lookup = X509_STORE_add_lookup(store, X509_LOOKUP_hash_dir())))
		goto end;
	if (!X509_LOOKUP_add_dir(lookup, untrust_path, X509_FILETYPE_PEM))
		goto end;
	if (!(store_ctx = X509_STORE_CTX_new()))
		goto end;
	if(!X509_STORE_CTX_init(store_ctx, store, cert, NULL))
		goto end;
	if (!(uchain = sk_X509_new_null()))
		goto end;

	x = cert;
	while (1) {
		if (depth < num)
			goto end;
		if (store_ctx->check_issued(store_ctx, x, x))
			break;
		if ((res = store_ctx->get_issuer(&xtmp, store_ctx, x)) < 0)
			goto end;
		if (res == 0)
			break;
		x = xtmp;
		if (!sk_X509_push(uchain, x)) {
			X509_free(xtmp);
			goto end;
		}
		num++;
	}
	if (!sk_X509_num(uchain))
		goto end;
	X509_STORE_CTX_free(store_ctx);
	X509_STORE_free(store);
	return uchain;

end:
	chain_free(uchain);
	X509_STORE_CTX_free(store_ctx);
	X509_STORE_free(store);
	return NULL;
}

int run_basic_test(const struct test_table *table, int table_size)
{
	int err = 1, i, res;
	X509 *cert, *anchor = NULL;
	char *file_path, file_name[64], *error_msg;
	scvp_cli_rqst cli_rqst;

	memset(&cli_rqst, 0 , sizeof(cli_rqst));
	cli_rqst.socket_file = socket_file;

	for (i = 0; i < table_size; i++) {
		snprintf(file_name, sizeof(file_name), "%s.crt.pem", table[i].cert_name);
		if (!(file_path = g_build_filename(untrusted_path, file_name, NULL))) {
			fprintf(stderr, "Failed to load certificate file\n");
			goto end;
		}
		if (!(cert = load_cert(file_path))) {
			fprintf(stderr, "Failed to load certificate file %s\n", file_name);
			goto end;
		}
		g_free(file_path);
		if (table[i].anchor_name) {
			snprintf(file_name, sizeof(file_name), "%s.crt.pem", table[i].anchor_name);
			if (!(file_path = g_build_filename(anchor_path, file_name, NULL))) {
				fprintf(stderr, "Failed to load trust anchor file %s\n", file_name);
				goto end;
			}
			if (!(anchor = load_cert(file_path))) {
				fprintf(stderr, "Failed to load anchor file\n");
				goto end;
			}
			g_free(file_path);
		}

		cli_rqst.rqst_ctx.cert = cert;
		cli_rqst.rqst_ctx.anchor = anchor;
		cli_rqst.rqst_ctx.uchain = get_uchain(cert, untrusted_path, 100);
		cli_rqst.rqst_ctx.checks = SCVP_CLI_BUILD_STATUS_CHECKED_PKC_PATH;

		res = scvp_cli_check_certificate(&cli_rqst, &error_msg);
		if (error_msg) {
			if (print_error)
				printf("%s error message: %s\n", table[i].test_name, error_msg);
			free(error_msg);
		}
		if (res != table[i].test_result)
			fprintf(stderr, "%s FAILED\n", table[i].test_name);
		X509_free(cert);
		X509_free(anchor);
		chain_free(cli_rqst.rqst_ctx.uchain);
	}
	err = 0;

end:
	return err;
}

static int run_policy_test(const struct test_policy_table *table, int table_size)
{
	int err = 1, i, res;
	X509 *cert;
	char *file_path, file_name[64], *error_msg;
	const char *user_poly_set[3];
	int user_poly_num;
	scvp_cli_rqst cli_rqst;

	memset(&cli_rqst, 0, sizeof(cli_rqst));
	cli_rqst.socket_file = socket_file;

	for (i = 0; i < table_size; i++) {
		snprintf(file_name, sizeof(file_name), "%s.crt.pem", table[i].cert_name);
		if (!(file_path = g_build_filename(untrusted_path, file_name, NULL))) {
			fprintf(stderr, "Failed to load certificate file\n");
			goto end;
		}
		if (!(cert = load_cert(file_path))) {
			fprintf(stderr, "Failed to load certificate file %s\n", file_name);
			goto end;
		}
		g_free(file_path);

		user_poly_num = 0;
		if (table[i].user_poly_set1) {
			user_poly_set[0] = table[i].user_poly_set1;
			user_poly_num++;
		}
		if (table[i].user_poly_set2) {
			user_poly_set[1] = table[i].user_poly_set2;
			user_poly_num++;
		}
		if (table[i].user_poly_set3) {
			user_poly_set[2] = table[i].user_poly_set3;
			user_poly_num++;
		}

		cli_rqst.rqst_ctx.cert = cert;
		cli_rqst.rqst_ctx.uchain = get_uchain(cert, untrusted_path, 100);
		cli_rqst.rqst_ctx.checks = SCVP_CLI_BUILD_STATUS_CHECKED_PKC_PATH;
		cli_rqst.rqst_ctx.user_poly_set = user_poly_set;
		cli_rqst.rqst_ctx.user_poly_num = user_poly_num;
		cli_rqst.rqst_ctx.user_poly_falgs = table[i].user_poly_flags;

		res = scvp_cli_check_certificate(&cli_rqst, &error_msg);
		if (error_msg) {
			if (print_error)
				fprintf(stderr, "%s error message: %s\n", table[i].test_name, error_msg);
			free(error_msg);
		}
		if (res != table[i].test_result)
			fprintf(stderr, "%s FAILED\n", table[i].test_name);
		X509_free(cert);
		chain_free(cli_rqst.rqst_ctx.uchain);
	}
	err = 0;

end:
	return err;
}

static void *test_thread(void* arg)
{
	int table_size;

	printf("\nSignature Verification\n");
	table_size = sizeof(signature_verify)/sizeof(signature_verify[0]);
	if (run_basic_test(signature_verify, table_size)) {
		fprintf(stderr, "Failed to run Signature Verification tests\n");
		return NULL;
	}

	printf("\nValidity Periods\n");
	table_size = sizeof(validity_periods)/sizeof(validity_periods[0]);
	if (run_basic_test(validity_periods, table_size)) {
		fprintf(stderr, "Failed to run Signature Validity Periods tests\n");
		return NULL;
	}

	printf("\nVerifying Name Chaining\n");
	table_size = sizeof(name_chaining)/sizeof(name_chaining[0]);
	if (run_basic_test(name_chaining, table_size)) {
		fprintf(stderr, "Failed to run Verifying Name Chaining tests\n");
		return NULL;
	}

	printf("\n\nBasic Certificate Revocation\n");
	table_size = sizeof(revocation_tests)/sizeof(revocation_tests[0]);
	if (run_basic_test(revocation_tests, table_size)) {
		fprintf(stderr, "Failed to run Basic Certificate Revocation tests\n");
		return NULL;
	}

	printf("\nVerifying Paths with Self-Issued Certificates\n");
	table_size = sizeof(verifying_paths)/sizeof(verifying_paths[0]);
	if (run_basic_test(verifying_paths, table_size)) {
		fprintf(stderr, "Failed to run Basic Certificate Verifying Paths with Self-Issued Certificates tests\n");
		return NULL;
	}

	printf("\nVerifying Basic Constraints\n");
	table_size = sizeof(basic_constraints)/sizeof(basic_constraints[0]);
	if (run_basic_test(basic_constraints, table_size)) {
		fprintf(stderr, "Failed to run Basic Certificate Verifying Basic Constraints tests\n");
		return NULL;
	}

	printf("\nKey Usage\n");
	table_size = sizeof(key_usage)/sizeof(key_usage[0]);
	if (run_basic_test(key_usage, table_size)) {
		fprintf(stderr, "Failed to run Key Usage tests\n");
		return NULL;
	}

	printf("\nName Constraints\n");
	table_size = sizeof(name_constraints)/sizeof(name_constraints[0]);
	if (run_basic_test(name_constraints, table_size)) {
		fprintf(stderr, "Failed to run Name Constraints tests\n");
		return NULL;
	}

	printf("\nDistribution Points\n");
	table_size = sizeof(distribution_points)/sizeof(distribution_points[0]);
	if (run_basic_test(distribution_points, table_size)) {
		fprintf(stderr, "Failed to run Distribution Points tests\n");
		return NULL;
	}

	printf("\nDelta-CRLs\n");
	table_size = sizeof(delta_crls)/sizeof(delta_crls[0]);
	if (run_basic_test(delta_crls, table_size)) {
		fprintf(stderr, "Failed to run Delta-CRLs tests\n");
		return NULL;
	}

	printf("\nPrivate Certificate Extensions\n");
	table_size = sizeof(private_extensions)/sizeof(private_extensions[0]);
	if (run_basic_test(private_extensions, table_size)) {
		fprintf(stderr, "Failed to run Private Certificate Extensions tests\n");
		return NULL;
	}

	printf("\nCertificate Policies\n");
	table_size = sizeof(certificate_policies)/sizeof(certificate_policies[0]);
	if (run_policy_test(certificate_policies, table_size)) {
		fprintf(stderr, "Failed to run Certificate Policies tests\n");
		return NULL;
	}

	printf("\nRequire Explicit Policy\n");
	table_size = sizeof(explicit_policy)/sizeof(explicit_policy[0]);
	if (run_policy_test(explicit_policy, table_size)) {
		fprintf(stderr, "Failed to run Require Explicit Policy tests\n");
		return NULL;
	}

	printf("\nPolicy Mappings\n");
	table_size = sizeof(policy_mappings)/sizeof(policy_mappings[0]);
	if (run_policy_test(policy_mappings, table_size)) {
		fprintf(stderr, "Failed to run Policy Mappings tests\n");
		return NULL;
	}

	printf("\nInhibit Policy Mapping\n");
	table_size = sizeof(inhibit_policy_mapping)/sizeof(inhibit_policy_mapping[0]);
	if (run_policy_test(inhibit_policy_mapping, table_size)) {
		fprintf(stderr, "Failed to run Inhibit Policy Mapping tests\n");
		return NULL;
	}

	printf("\nInhibit Any Policy\n");
	table_size = sizeof(inhibit_any_policy)/sizeof(inhibit_any_policy[0]);
	if (run_policy_test(inhibit_any_policy, table_size)) {
		fprintf(stderr, "Failed to run Inhibit Any Policy tests\n");
		return NULL;
	}

	return NULL;
}

int main(int argc, char **argv)
{
	int i, err;
	pthread_t thread[MAX_THREAD_NUMBER];

	if (argc < 4 || argc > 5) {
		printf("Usage: path_test socket_file trusted_path untrusted_path [print-err]\n");
		return 1;
	}
	socket_file = argv[1];
	anchor_path = argv[2];
	untrusted_path = argv[3];
	if (argc == 5)
		if (strcmp(argv[4], "print-error") == 0)
			print_error = 1;

	for (i = 0; i < MAX_THREAD_NUMBER; i++) {
		err = pthread_create(&thread[i], NULL, test_thread, NULL);
		if (err != 0) {
			fprintf(stderr, "Failed to create new thread\n");
			goto end;
		}
	}
	for (i = 0; i < MAX_THREAD_NUMBER; i++)
		pthread_join(thread[i],NULL);

end:
	return 0;
}

