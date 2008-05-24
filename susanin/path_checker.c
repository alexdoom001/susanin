#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <time.h>
#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <glib.h>
#include <curl/curl.h>

#include "path_checker.h"
#include "scvp_defs.h"
#include "scvp_proto.h"
#include "ocsp_verify.h"
#include "cache.h"
#include "config.h"
#include "logger.h"
#include "update_chain.h"

enum error_code
{
	E_SUCCESS = 0,
	E_EE_CERT,
	E_INTER_CERT,
	E_CACHE_INT,
	E_CACHE_ANCHOR,
	E_OPENSSL_INT,
	E_VERIFY_TYPE,
	E_PATH_BUILD,
	E_POLICY_PARAMS,
	E_OCSP_CHECK,
	E_CRL_CHECK,
	E_PATH_CHECK,
	E_POLICY_CHECK,
	E_TRUST_ANCHOR,
	E_MAX
};

static const char *error_message[E_MAX] = {
	"No error",
	"Failed to retrieve SCVP EE certificate",
	"Failed to retrieve SCVP intermediate certificate",
	"Certificate cache internal error",
	"Failed to retrieve anchor certificate from cache",
	"OpenSSL internal error",
	"Undefined verify type for PKC path build",
	"Certificate path build failed",
	"Failed to set certificate path policy parameters",
	"Certificate path OCSP revocation check failed",
	"Certificate path revocation check failed",
	"Certificate path validation failed",
	"Certificate path policy check failed",
	"Chain doesn't include trust anchor certificate"
};

extern struct config cfg;

static inline int verify_stub(X509_STORE_CTX *store_ctx)
{
	return 1;
}

static inline int revocation_stub(X509_STORE_CTX *ctx)
{
	return 1;
}

static int verify_callback(int preverify_ok, X509_STORE_CTX *store_ctx)
{
	int err, *crl_values;

	if (!preverify_ok) {
		err = X509_STORE_CTX_get_error(store_ctx);

		crl_values = X509_STORE_CTX_get_ex_data(store_ctx, 0);

		if (err == X509_V_ERR_UNABLE_TO_GET_CRL && (*crl_values & CHECK_AVAILABLE))
			preverify_ok = 1;
		log_msg(LOG_DEBUG, "verify error: %d (%s)", err, X509_verify_cert_error_string(err));
	}
	return preverify_ok;
}

static int check_anchor_certificate(X509_STORE_CTX *store_ctx, X509 * anchor)
{
	int i;

	for (i = sk_X509_num(store_ctx->chain) - 1; i >= 0; i--)
		if(!X509_cmp(sk_X509_value(store_ctx->chain, i), anchor))
			return 0;
	return 1;
}

static X509_VERIFY_PARAM *cert_policy_values(const struct scvp_request *rqst)
{
	GSList *iterator;
	ASN1_OBJECT *obj;
	X509_VERIFY_PARAM *param;

	if (!(param = X509_VERIFY_PARAM_new())) {
		log_msg(LOG_DEBUG, "OpenSSL X509_VERIFY_PARAM_new() failed");
		return NULL;
	}
	if (!g_slist_length(rqst->user_poly_set)) {
		if (!(obj = OBJ_txt2obj("anyPolicy", 0))) {
			log_msg(LOG_DEBUG, "Failed to process anyPolicy value");
			goto end;
		}
		X509_VERIFY_PARAM_add0_policy(param, obj);
		X509_VERIFY_PARAM_set_depth(param, MAX_CERT_CHAIN_DEPTH);
		return param;
	}

	for (iterator = rqst->user_poly_set; iterator; iterator = g_slist_next(iterator)) {
		if (!(obj = OBJ_txt2obj((char*)iterator->data, 1))) {
			log_msg(LOG_DEBUG, "Failed to process userPolicySet value");
			goto end;
		}
		X509_VERIFY_PARAM_add0_policy(param, obj);
	}
	X509_VERIFY_PARAM_set_depth(param, MAX_CERT_CHAIN_DEPTH);
	return param;

end:
	X509_VERIFY_PARAM_free(param);
	return NULL;
}

static void cache_chain(STACK_OF(X509) *chain)
{
	int i;

	for (i = sk_X509_num(chain) - 1; i > 0; i--)
		cache_cert(sk_X509_value(chain, i), cfg.untrusted_path);
}

static void chain_free(STACK_OF(X509) *uchain)
{
	X509 *cert;

	if (!uchain)
		return;
	while (1) {
		if (!(cert = sk_X509_pop(uchain)))
			break;
		X509_free(cert);
	}
	sk_X509_free(uchain);
}

static enum error_code build_pkc_path(X509 *cert, X509 *anchor, STACK_OF(X509) *uchain, const struct scvp_request *scvp_rqst)
{
	enum error_code err = E_SUCCESS;
	X509_STORE *store;
	X509_LOOKUP *lookup;
	X509_STORE_CTX *store_ctx = NULL;
	int (*internal_verify)(X509_STORE_CTX *ctx) = NULL;
	int (*check_revocation)(X509_STORE_CTX *ctx) = NULL ;
	X509_VERIFY_PARAM *param = NULL;

	if (!(store = X509_STORE_new())) {
		err = E_OPENSSL_INT;
		goto end;
	}
	if (!(lookup = X509_STORE_add_lookup(store, X509_LOOKUP_hash_dir()))) {
		err = E_OPENSSL_INT;
		goto end;
	}
	if (!X509_LOOKUP_add_dir(lookup, cfg.ca_path, X509_FILETYPE_PEM)) {
		err = E_OPENSSL_INT;
		goto end;
	}
	if (!X509_LOOKUP_add_dir(lookup, cfg.crl_path, X509_FILETYPE_PEM)) {
		err = E_OPENSSL_INT;
		goto end;
	}
	if (!(store_ctx = X509_STORE_CTX_new())) {
		err = E_OPENSSL_INT;
		goto end;
	}

	if(!X509_STORE_CTX_init(store_ctx, store, cert, uchain)) {
		err = E_OPENSSL_INT;
		goto end;
	}

	check_revocation = store_ctx->check_revocation;
	store_ctx->check_revocation = revocation_stub;

	switch(scvp_rqst->checks) {
	case BUILD_PKC_PATH:
		store_ctx->verify = verify_stub;
		break;
	case BUILD_VALID_PKC_PATH:
		store_ctx->verify_cb = verify_callback;
		break;
	case BUILD_STATUS_CHECKED_PKC_PATH:
		internal_verify = store_ctx->verify;
		store_ctx->verify = update_cert_chain_crl;
		store_ctx->verify_cb = verify_callback;
		break;
	default:
		err = E_VERIFY_TYPE;
		goto end;
	}

	X509_STORE_CTX_set_flags(store_ctx, X509_V_FLAG_X509_STRICT);
	if (X509_verify_cert(store_ctx) <= 0) {
		err = E_PATH_BUILD;
		goto end;
	}

	if (anchor)
		if (check_anchor_certificate(store_ctx, anchor)) {
			err = E_TRUST_ANCHOR;
			goto end;
		}

	if (scvp_rqst->checks == BUILD_STATUS_CHECKED_PKC_PATH) {
		int flags = 0, crl_values;
		X509 *last_cert;

		last_cert = sk_X509_value(store_ctx->chain, sk_X509_num(store_ctx->chain) - 1);
		if (last_cert == NULL) {
			err = E_OPENSSL_INT;
			goto end;
		}
		crl_values = get_cert_values(last_cert, CRL_VALUES);
		if (!X509_STORE_CTX_set_ex_data(store_ctx, 0, &crl_values)) {
			err = E_OPENSSL_INT;
			goto end;
		}
		if (crl_values & CHECK_PEER)
			flags |= X509_V_FLAG_CRL_CHECK;
		else if (crl_values & CHECK_ALL)
			flags |= X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL;

		flags |= X509_V_FLAG_POLICY_CHECK;
		if (!(param = cert_policy_values(scvp_rqst))) {
			err = E_POLICY_PARAMS;
			goto end;
		}
		X509_STORE_CTX_set0_param(store_ctx, param);
		if (scvp_rqst->user_poly_flags & SCVP_POLY_INHIBIT_MAP)
			flags |= X509_V_FLAG_INHIBIT_MAP;
		if (scvp_rqst->user_poly_flags & SCVP_POLY_EXPLICIT_POLICY)
			flags |= X509_V_FLAG_EXPLICIT_POLICY;
		if (scvp_rqst->user_poly_flags & SCVP_POLY_INHIBIT_ANY)
			flags |= X509_V_FLAG_INHIBIT_ANY;
		flags |= X509_V_FLAG_X509_STRICT;
		flags |= X509_V_FLAG_USE_DELTAS;
		flags |= X509_V_FLAG_EXTENDED_CRL_SUPPORT;
		X509_STORE_CTX_set_flags(store_ctx, flags);

		if (check_revocation_ocsp(store_ctx)) {
			err = E_OCSP_CHECK;
			goto end;
		}
		if (!check_revocation(store_ctx)) {
			err = E_CRL_CHECK;
			goto end;
		}
		if (!internal_verify(store_ctx)) {
			err = E_PATH_CHECK;
			goto end;
		}
		if (flags & X509_V_FLAG_POLICY_MASK)
			if (!store_ctx->check_policy(store_ctx)) {
				err = E_POLICY_CHECK;
				goto end;
			}
	}
	cache_chain(store_ctx->chain);

end:
	X509_STORE_CTX_free(store_ctx);
	X509_STORE_free(store);
	return err;
}

struct scvp_response_srv *create_scvp_response(struct scvp_request *rqst, enum error_code error)
{
	struct scvp_response_srv *resp;
	struct scvp_cert_reply *cert_reply;

	if (!(resp = response_srv_alloc()))
		return NULL;
	if (!(cert_reply = cert_reply_alloc()))
		goto end;

	if (rqst->queried_certs) {
		cert_reply->cert = (struct scvp_cert_der*)rqst->queried_certs->data;
		rqst->queried_certs = g_slist_remove(rqst->queried_certs, rqst->queried_certs->data);
		g_slist_free(rqst->queried_certs);
		rqst->queried_certs = NULL;
	}

	cert_reply->reply_checks = rqst->checks;
	time(&cert_reply->reply_val_time);

	if (error) {
		cert_reply->reply_status = CERT_PATH_NOT_VALID;
		if (error > 0 && error < E_MAX)
			resp->error_msg = error_message[error];
	}
	else
		cert_reply->reply_status = SUCCESS;

	resp->cert_reply = g_slist_append(resp->cert_reply,  cert_reply);
	resp->val_poly = VAL_POLY_DEFAULT;
	time(&resp->produced_at);
	resp->response_status = OKAY;
	return resp;

end:
	response_srv_free(resp);
	return NULL;
}

extern struct scvp_proto_ctx *scvp_ctx;

unsigned char *process_scvp_request(const unsigned char *rqst_data, int rqst_len, int *resp_len)
{
	enum error_code err = E_SUCCESS;
	struct scvp_request *scvp_rqst;
	struct scvp_response_srv *scvp_resp = NULL;
	GSList *iterator;
	struct scvp_cert_der *cert_der;
	X509 *cert = NULL, *anchor = NULL, *cert_tmp;
	STACK_OF(X509) *uchain = NULL;
	unsigned char *resp_data = NULL, *ptr;

	if (!(scvp_rqst = unpack_scvp_request(scvp_ctx, rqst_data, rqst_len))) {
		log_msg(LOG_DEBUG, "SCVP request unpack failed");
		return NULL;
	}

	if (!scvp_rqst->queried_certs) {
		err = E_EE_CERT;
		goto end;
	}
	cert_der = (struct scvp_cert_der*)scvp_rqst->queried_certs->data;
	ptr = cert_der->cert;
	if (!(cert = d2i_X509(NULL, (const unsigned char**)&ptr, cert_der->cert_len))) {
		err = E_EE_CERT;
		goto end;
	}

	if (!(uchain = sk_X509_new_null())) {
		err = E_OPENSSL_INT;
		goto end;
	}
	if (scvp_rqst->inter_certs) {

		for (iterator = scvp_rqst->inter_certs; iterator; iterator = g_slist_next(iterator)) {
			cert_der = (struct scvp_cert_der*)iterator->data;
			ptr = cert_der->cert;
			if (!(cert_tmp = d2i_X509(NULL, (const unsigned char**)&ptr, cert_der->cert_len))) {
				err = E_INTER_CERT;
				goto end;
			}
			if (!sk_X509_push(uchain, cert_tmp)) {
				X509_free(cert_tmp);
				err = E_OPENSSL_INT;
				goto end;
			}
		}
	}
	load_ca(cert, uchain, MAX_CERT_CHAIN_DEPTH);
	load_ca_issuers(uchain, MAX_CERT_CHAIN_DEPTH);

	if (scvp_rqst->trust_anchors) {
		struct scvp_cert_ref *cert_ref;
		int ret;

		cert_ref = (struct scvp_cert_ref*)scvp_rqst->trust_anchors->data;
		if ((ret = check_cached_cert_ref(cert_ref, cfg.ca_path, &anchor)) == -1)
			err = E_CACHE_INT;
		if (ret == 0)
			err = E_CACHE_ANCHOR;
	}

end:
	if (err == E_SUCCESS)
		err = build_pkc_path(cert, anchor, uchain, scvp_rqst);
	if(!(scvp_resp = create_scvp_response(scvp_rqst, err))) {
		log_msg(LOG_DEBUG, "Failed to create SCVP response");
		goto end;
	}
	if (!(resp_data = pack_scvp_response(scvp_ctx, scvp_resp, resp_len))) {
		log_msg(LOG_DEBUG, "Failed to pack SCVP response");
		goto end;
	}

	X509_free(cert);
	X509_free(anchor);
	chain_free(uchain);
	request_free(scvp_rqst);
	response_srv_free(scvp_resp);
	return resp_data;
}
