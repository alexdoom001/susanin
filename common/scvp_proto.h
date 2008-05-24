#ifndef SCVP_PROTO_H
#define SCVP_PROTO_H

#define SCVP_MSG_BLOCK_SIZE 4096
#define SCVP_OID_STR_MAX_SIZE 64
#define SCVP_ERR_MSG_MAX_SIZE 64

struct scvp_proto_ctx;

struct scvp_proto_ctx *scvp_init(void);
void scvp_deinit(struct scvp_proto_ctx *ctx)
	__attribute__((nonnull));
unsigned char *pack_scvp_request(const struct scvp_proto_ctx *ctx, const struct scvp_request *rqst, int *rqst_len)
	__attribute__((nonnull));
struct scvp_request *unpack_scvp_request(const struct scvp_proto_ctx *ctx, const unsigned char *rqst_data, int rqst_len)
	__attribute__((nonnull));
unsigned char *pack_scvp_response(const struct scvp_proto_ctx *ctx, const struct scvp_response_srv *resp, int *resp_len)
	__attribute__((nonnull));
struct scvp_response_cli *unpack_scvp_response(const struct scvp_proto_ctx *ctx, const unsigned char *resp_data, int resp_len)
	__attribute__((nonnull));

#endif /* SCVP_PROTO_H */
