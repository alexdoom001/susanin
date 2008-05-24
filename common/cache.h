#ifndef CACHE_H
#define CACHE_H

#define MAX_CACHE_HASH_COLLISION_NUM 100

#if 0
ASN1_INTEGER *convert_serial_to_asn1(const unsigned char *serial, int serial_len)
	__attribute__((nonnull));
#endif
int convert_asn1_to_serial(const ASN1_INTEGER *asn1_serial, unsigned char *serial, unsigned int *serial_len)
	__attribute__((nonnull));
struct scvp_cert_ref *get_cert_ref(const X509 *cert)
	__attribute__((nonnull));
int cert_ref_cmp(const struct scvp_cert_ref *cert1, const struct scvp_cert_ref *cert2);
int check_cached_cert_ref(const struct scvp_cert_ref *cert_ref, const char *cache_path, X509 **cached_cert);
int check_cached_cert(X509 *cert, const char *cache_path)
	__attribute__((nonnull));
int cache_cert(X509 *cert, const char *cache_path)
	__attribute__((nonnull));
int cache_crl(X509_STORE_CTX *store_ctx, X509_CRL *crl, const char *cache_path)
	__attribute__((nonnull));

#endif /* CACHE_H */
