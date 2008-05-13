#ifndef CACHE_H
#define CACHE_H

#define MAX_CACHE_HASH_COLLISION_NUM 100

ASN1_INTEGER *convert_serial_to_asn1(unsigned char *serial, int serial_len);
int convert_asn1_to_serial(ASN1_INTEGER *asn1_serial, unsigned char *serial, unsigned int *serial_len);
struct scvp_cert_ref *get_cert_ref(X509 *cert);
int cert_ref_cmp(struct scvp_cert_ref *cert1, struct scvp_cert_ref *cert2);
int check_cached_cert_ref(struct scvp_cert_ref *cert_ref, const char *cache_path, X509 **cached_cert);
int check_cached_cert(X509 *cert, const char *cache_path);
int cache_cert(X509 *cert, const char *cache_path);
int cache_crl(X509_STORE_CTX *store_ctx, X509_CRL *crl, const char *cache_path);

#endif /* CACHE_H */
