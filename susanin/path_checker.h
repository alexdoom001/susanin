#ifndef PATH_BUILDER_H
#define PATH_BUILDER_H

#define CHECK_AVAILABLE     0x01
#define CHECK_ACCURATE      0x02
#define CHECK_PEER          0x04
#define CHECK_ALL           0x08
#define DISABLE_NONCE       0x10

#define MAX_CRL_HASH_COLLISION 100

unsigned char *process_scvp_request(const unsigned char *rqst_data, int rqst_len, int *resp_len)
	__attribute__((nonnull));

#endif /* PATH_BUILDER_H */
