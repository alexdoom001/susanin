#ifndef OCSP_VERIFY_H
#define OCSP_VERIFY_H

int check_revocation_ocsp(X509_STORE_CTX *ctx)
	__attribute__((nonnull));

#endif /* OCSP_VERIFY_H */
