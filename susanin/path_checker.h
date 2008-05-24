#ifndef PATH_CHECKER_H
#define PATH_CHECKER_H

#define MAX_CRL_HASH_COLLISION 100

unsigned char *process_scvp_request(const unsigned char *rqst_data, int rqst_len, int *resp_len)
	__attribute__((nonnull));

#endif /* PATH_CHECKER_H */
