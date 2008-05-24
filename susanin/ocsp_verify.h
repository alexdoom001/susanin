#ifndef VFY_OCSP_H
#define VFY_OCSP_H

#define OCSP_VALIDATE_DISABLED 	0
#define OCSP_VALIDATE_ENABLED 	0

struct cert_ocsp_ref {
	ASN1_INTEGER *serial;
	unsigned char hash[EVP_MAX_MD_SIZE];
	unsigned int hash_len;
	unsigned int validate;
	char *url;
};

struct cert_ocsp_ref *cert_ocsp_alloc(void);
void cert_ocsp_free(struct cert_ocsp_ref *cert_ocsp);
int check_revocation_ocsp(X509_STORE_CTX *ctx)
	__attribute__((nonnull));

#endif /* VFY_OCSP_H */
