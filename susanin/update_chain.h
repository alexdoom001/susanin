#ifndef UPDATE_CHAIN_H
#define UPDATE_CHAIN_H

#define MAX_CERT_CHAIN_DEPTH 100

void load_ca(X509 *cert, STACK_OF(X509) *uchain, int depth)
	__attribute__((nonnull));
void load_ca_issuers(STACK_OF(X509) *uchain, int depth)
	__attribute__((nonnull));
int update_cert_chain_crl(X509_STORE_CTX *store_ctx);
int update_ca_cert_crl(const char *ca_name, const char *ca_path, const char *crl_path,
		const char *tmp_path) __attribute__((nonnull));
int update_all_ca_certs_crl(const char *ca_path, const char *crl_path, const char *tmp_path)
	__attribute__((nonnull));

#endif /* UPDATE_CHAIN_H */
