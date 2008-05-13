#ifndef SCVP_CLI_H
#define SCVP_CLI_H

#define SCVP_CLI_CERT_OK           0 /* SCVP certificate reply status SUCCESS */
#define SCVP_CLI_ERR_PARAMS        1 /* Parameters error */
#define SCVP_CLI_ERR_INTERNAL      2 /* Library internal error */
#define SCVP_CLI_ERR_CONNECT       3 /* connect() failed */
#define SCVP_CLI_ERR_SEND          4 /* send() failed */
#define SCVP_CLI_ERR_RECV          5 /* Connection timeout */
#define SCVP_CLI_ERR_BAD_RESP      7 /* Bad SCVP response */
#define SCVP_CLI_ERR_BAD_STATUS    8 /* Bad SCVP response status */
#define SCVP_CLI_ERR_BAD_CERT      9 /* Bad SCVP certificate reply status */
#define SCVP_CLI_ERR_BAD_RQST      10 /* Some request data seems to be non-conforming (for e.g. serial number)*/

#define SCVP_CLI_BUILD_PKC_PATH                0x01
#define SCVP_CLI_BUILD_VALID_PKC_PATH          0x02
#define SCVP_CLI_BUILD_STATUS_CHECKED_PKC_PATH 0x04

#define SCVP_POLY_INHIBIT_MAP                  0x01
#define SCVP_POLY_EXPLICIT_POLICY              0x02
#define SCVP_POLY_INHIBIT_ANY                  0x04

struct scvp_cli_ctx {
	char *socket_file;
	char *untrusted_path;
	void *asn1_defs;
};

#ifdef __cplusplus
extern "C"{
#endif

struct scvp_cli_ctx *scvp_cli_init(const char *socket_file, const char *untrusted_path);
void scvp_cli_deinit(struct scvp_cli_ctx *ctx);
int scvp_cli_check_certificate(struct scvp_cli_ctx *cli_ctx, X509 *cert, X509 *anchor, STACK_OF(X509) *uchain,
		unsigned int checks, const char **user_poly_set, int user_poly_num, int user_poly_falgs);

#ifdef __cplusplus
}
#endif

#endif /* SCVP_CLI_H */
