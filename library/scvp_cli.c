#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <glib.h>
#include <openssl/ssl.h>

#include "scvp_proto.h"
#include "channel.h"
#include "cache.h"
#include "scvp_cli.h"

static struct scvp_request *create_scvp_request(X509 *cert, X509 *anchor, STACK_OF(X509) *uchain, unsigned int checks,
		const char **user_poly_set, int user_poly_num, int user_poly_falgs)
{
	int i;
	X509 *cert_tmp;
	struct scvp_request *rqst;
	struct scvp_cert_der *cert_der;
	struct scvp_cert_ref *anchor_ref = NULL;

	if (!(rqst = request_alloc()))
		return NULL;

	if (!(cert_der = cert_der_alloc()))
		goto end;
	cert_der->cert_len = i2d_X509(cert, &cert_der->cert);
	if (cert_der->cert_len <= 0) {
		cert_der_free(cert_der);
		goto end;
	}
	rqst->queried_certs = g_slist_append(rqst->queried_certs, cert_der);

	while (1) {
		if (!(cert_tmp = sk_X509_pop(uchain)))
			break;
		if (!(cert_der = cert_der_alloc()))
			goto end;
		cert_der->cert_len = i2d_X509(cert_tmp, &cert_der->cert);
		if (cert_der->cert_len <= 0) {
			cert_der_free(cert_der);
			goto end;
		}
		rqst->inter_certs = g_slist_append(rqst->inter_certs, cert_der);
	}

	if (anchor) {
		if (!(anchor_ref = get_cert_ref(anchor)))
			goto end;
		rqst->trust_anchors = g_slist_append(rqst->trust_anchors, anchor_ref);
	}

	rqst->checks = checks;
	rqst->val_poly = VAL_POLY_DEFAULT;

	for (i = 0; i < user_poly_num; i++) {
		if (strlen(user_poly_set[i]) > SCVP_OID_STR_MAX_SIZE - 1)
			goto end;
		rqst->user_poly_set = g_slist_append(rqst->user_poly_set, strdup(user_poly_set[i]));
	}
	rqst->user_poly_flags = user_poly_falgs;
	return rqst;

end:
	request_free(rqst);
	return NULL;
}

static int process_scvp_response(struct scvp_request *rqst, struct scvp_response *resp)
{
	struct scvp_cert_reply *cert_reply;
	struct scvp_cert_der *cert_der;

	if (resp->response_status != OKAY)
		return SCVP_CLI_ERR_BAD_STATUS;
	if (!resp->cert_reply)
		return SCVP_CLI_ERR_BAD_RESP;
	cert_reply = (struct scvp_cert_reply*)resp->cert_reply->data;
	if (!rqst->queried_certs)
		return SCVP_CLI_ERR_INTERNAL;
	if (cert_reply->reply_checks != rqst->checks)
		return SCVP_CLI_ERR_BAD_RESP;
	cert_der = (struct scvp_cert_der*)rqst->queried_certs->data;
	if (cert_der->cert_len != cert_reply->cert->cert_len)
		return SCVP_CLI_ERR_BAD_RESP;
	if (memcmp(cert_der->cert, cert_reply->cert->cert, cert_der->cert_len))
		return SCVP_CLI_ERR_BAD_RESP;
	if (cert_reply->reply_status != SUCCESS)
		return SCVP_CLI_ERR_BAD_CERT;
	return SCVP_CLI_CERT_OK;
}

int scvp_cli_check_certificate(struct scvp_cli_ctx *cli_ctx, X509 *cert, X509 *anchor, STACK_OF(X509) *uchain,
		unsigned int checks, const char **user_poly_set, int user_poly_num, int user_poly_falgs)
{
	int err = 0, ret, sd;
	struct sockaddr_un sa;
	struct scvp_request *scvp_rqst = NULL;
	struct scvp_response *scvp_resp = NULL;
	unsigned char *rqst_data = NULL, *resp_data = NULL;
	int rqst_len, resp_len;

	if (!cli_ctx->socket_file || !cli_ctx->asn1_defs)
		return SCVP_CLI_ERR_PARAMS;
	if (!checks)
		return SCVP_CLI_ERR_PARAMS;

	sd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
	if (sd == -1)
		return SCVP_CLI_ERR_INTERNAL;

	sa.sun_family = AF_UNIX;
	strcpy(sa.sun_path, cli_ctx->socket_file);

	ret = connect(sd, (struct sockaddr *) &sa, sizeof (sa));
	if (ret == -1) {
		err = SCVP_CLI_ERR_CONNECT;
		goto end;
	}

	if (!(scvp_rqst = create_scvp_request(cert, anchor, uchain, checks, user_poly_set, user_poly_num, user_poly_falgs))) {
		err = SCVP_CLI_ERR_BAD_RQST;
		goto end;
	}
	if (!(rqst_data = pack_scvp_request(cli_ctx->asn1_defs, scvp_rqst, &rqst_len))) {
		err = SCVP_CLI_ERR_INTERNAL;
		goto end;
	}
	if (send_data(sd, rqst_data, rqst_len)) {
		err = SCVP_CLI_ERR_SEND;
		goto end;
	}
	if (recv_data(sd, &resp_data, &resp_len)) {
		err = SCVP_CLI_ERR_RECV;
		goto end;
	}
	if (!(scvp_resp = unpack_scvp_response(cli_ctx->asn1_defs, resp_data, resp_len))) {
		err = SCVP_CLI_ERR_BAD_RESP;
		goto end;
	}
	err = process_scvp_response(scvp_rqst, scvp_resp);

end:
	request_free(scvp_rqst);
	response_free(scvp_resp);
	free(rqst_data);
	free(resp_data);
	close(sd);
	return err;
}

struct scvp_cli_ctx *scvp_cli_init(const char *socket_file, const char *untrusted_path)
{
	struct scvp_cli_ctx *cli_ctx;

	if (!socket_file)
		return NULL;
	if (!(cli_ctx = malloc(sizeof(*cli_ctx))))
		return NULL;
	if (!(cli_ctx->socket_file = strdup(socket_file))) {
		free(cli_ctx);
		return NULL;
	}
	if (!(cli_ctx->untrusted_path = strdup(untrusted_path))) {
		free(cli_ctx->socket_file);
		free(cli_ctx);
		return NULL;
	}
	if (!(cli_ctx->asn1_defs = scvp_initialize("scvp.asn"))) {
		free(cli_ctx->untrusted_path);
		free(cli_ctx->socket_file);
		free(cli_ctx);
		return NULL;
	}
	return cli_ctx;
}

void scvp_cli_deinit(struct scvp_cli_ctx *cli_ctx)
{
	scvp_deinitialize(cli_ctx->asn1_defs);
	free(cli_ctx->socket_file);
	free(cli_ctx->untrusted_path);
	free(cli_ctx);
}

