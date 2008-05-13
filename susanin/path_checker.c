#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <time.h>
#include <linux/limits.h>
#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <glib.h>
#include <curl/curl.h>

#include "path_checker.h"
#include "scvp_proto.h"
#include "ocsp_verify.h"
#include "cache.h"
#include "config.h"
#include "logger.h"

static char **get_ca_issuers(X509 *cert, int *str_num)
{
	int i;
	AUTHORITY_INFO_ACCESS *info;
	ACCESS_DESCRIPTION *ad;
	char **str = NULL, **ptr;

	info = X509_get_ext_d2i(cert, NID_info_access, NULL, NULL);
	if (!info)
		return NULL;
	*str_num = 0;
	for (i = 0; i < sk_ACCESS_DESCRIPTION_num(info); i++) {
		ad = sk_ACCESS_DESCRIPTION_value(info, i);
		if (OBJ_obj2nid(ad->method) == NID_ad_ca_issuers) {
			if (ad->location->type == GEN_URI) {
				(*str_num)++;
				ptr = str;
				if (!(str = realloc(ptr ,sizeof(char*) * (*str_num)))) {
					free(ptr);
					return NULL;
				}
				str[(*str_num) - 1] = strdup((char*)ad->location->d.ia5->data);
			}
		}
	}
	AUTHORITY_INFO_ACCESS_free(info);
	return str;
}

static char **get_crldps(X509 *cert, int *str_num)
{
	int i, j;
	DIST_POINT *dp;
	GENERAL_NAME *gen;
	char **str = NULL, **ptr;

	*str_num = 0;
	for (i = 0; i < sk_DIST_POINT_num(cert->crldp); i++) {
	  dp = sk_DIST_POINT_value(cert->crldp, i);
	  if (!dp->distpoint)
	  	continue;
	  for (j = 0; j < sk_GENERAL_NAME_num(dp->distpoint->name.fullname); j++) {
	    gen = sk_GENERAL_NAME_value(dp->distpoint->name.fullname, j);
	    if (gen->type == GEN_URI) {
	    	(*str_num)++;
	    	ptr = str;
	    	if (!(str = realloc(ptr ,sizeof(char*) * (*str_num)))) {
	    		free(ptr);
				return NULL;
	    	}
	    	str[(*str_num) - 1] = strdup((char*)gen->d.ia5->data);
	    }
	  }
	}
    return str;
}

char* curl_load_file(const char* url)
{
	int err = 1;
	char *tmp_file;
	FILE *fp;
	CURL *curl = NULL;

	if (!(tmp_file = tempnam(cfg.tmp_path, NULL)))
		return NULL;
	if (!(fp = fopen(tmp_file, "wb")))
		goto end;
	if (!(curl = curl_easy_init()))
		goto end;
	if ((curl_easy_setopt(curl, CURLOPT_URL, url)) != CURLE_OK)
		goto end;
	if ((curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, NULL)) != CURLE_OK)
		goto end;
	if ((curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp)) != CURLE_OK)
		goto end;
	if ((curl_easy_perform(curl)) != CURLE_OK)
		goto end;
	err = 0;

end:
	curl_easy_cleanup(curl);
	fclose(fp);
	if (!err)
		return tmp_file;
	free(tmp_file);
	return NULL;
}

static void load_ca(X509 *cert, STACK_OF(X509) *uchain, int depth)
{
	int i;
	BIO *bio;
	X509 *cert_tmp = NULL;
	EVP_PKEY *pkey;
	char *tmp_file = NULL;
	char **ca_issuers = NULL;
	int ca_issuers_num;

	if (depth > 100)
		return;
	if (!(bio = BIO_new(BIO_s_file())))
		return;
	if (!(ca_issuers = get_ca_issuers(cert, &ca_issuers_num)))
		goto end;
	for (i = 0; i < ca_issuers_num; i++) {
		if (!(tmp_file = curl_load_file(ca_issuers[i]))) {
			goto end;
		}
		if (!BIO_read_filename(bio, tmp_file))
			goto end;
		if (!(cert_tmp = PEM_read_bio_X509_AUX(bio, NULL, NULL, NULL)))
			goto end;
		remove(tmp_file);
		free(tmp_file);
		tmp_file = NULL;
		if (!(pkey = X509_get_pubkey(cert_tmp)))
			goto end;
		if (!X509_verify(cert_tmp, pkey)) {
			EVP_PKEY_free(pkey);
			goto end;
		}
		EVP_PKEY_free(pkey);
		if (!sk_X509_push(uchain, cert_tmp))
			goto end;
		load_ca(cert, uchain, depth + 1);
		X509_free(cert_tmp);
		cert_tmp = NULL;
	}

end:
	BIO_free(bio);
	if (ca_issuers) {
		for (i = 0; i < ca_issuers_num; i++)
			free(ca_issuers[i]);
		free(ca_issuers);
	}
	if (tmp_file) {
		remove(tmp_file);
		free(tmp_file);
	}
	X509_free(cert_tmp);
}

static void load_ca_issuers(STACK_OF(X509) *uchain, int depth)
{
	int i;
	X509 *cert;

	if (!uchain)
		return;
	for (i = 0; i < sk_X509_num(uchain); i++) {
		if (!(cert = sk_X509_value(uchain, i)))
			return;
		load_ca(cert, uchain, depth);
	}
}

static int update_crl(const char* crl_url, X509_STORE_CTX *store_ctx, EVP_PKEY *pkey)
{
	int err = 1;
	char *tmp_file;
	BIO *bio;
	X509_CRL *crl = NULL;

	if (!(tmp_file = curl_load_file(crl_url))) {
		log_msg(LOG_DEBUG, "cURL failed to load CRL %s", crl_url);
		return 1;
	}
	if (!(bio = BIO_new(BIO_s_file())))
		goto end;
	if (!BIO_read_filename(bio, tmp_file))
		goto end;
	if (!(crl = PEM_read_bio_X509_CRL(bio, NULL, NULL, NULL))) {
		log_msg(LOG_DEBUG, "Failed to process loaded CRL");
		goto end;
	}
	if (!X509_CRL_verify(crl, pkey)) {
		log_msg(LOG_DEBUG, "Failed to verify CRL");
		goto end;
	}
	if (cache_crl(store_ctx, crl, cfg.crl_path)) {
		log_msg(LOG_DEBUG, "Failed to cache CRL");
		goto end;
	}
	err = 0;

end:
	remove(tmp_file);
	free(tmp_file);
	BIO_free(bio);
	X509_CRL_free(crl);
	return err;
}

static int update_chain_crl(X509_STORE_CTX *store_ctx)
{
	int i, j;
	X509 *cert;
	EVP_PKEY *pkey;
	char **crldps;
	int crldps_num;

	for (i = sk_X509_num(store_ctx->chain) - 1; i >= 0; i--) {
		if (!(cert = sk_X509_value(store_ctx->chain, i)))
			continue;
		if (!(crldps = get_crldps(cert, &crldps_num)))
			continue;
		if (!(pkey = X509_get_pubkey(cert))) {
			for (j = 0; j < crldps_num; j++)
				free(crldps[j]);
			free(crldps);
			continue;
		}
		for (j = 0; j < crldps_num; j++) {
			update_crl(crldps[j], store_ctx, pkey);
			free(crldps[j]);
		}
		EVP_PKEY_free(pkey);
		free(crldps);
	}
	return 1;
}

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
	int err;

	if (!preverify_ok) {
		err = X509_STORE_CTX_get_error(store_ctx);
		if (err == X509_V_ERR_UNABLE_TO_GET_CRL && (cfg.crl_values & CHECK_AVAILABLE))
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

X509_VERIFY_PARAM *cert_policy_values(struct scvp_request *rqst)
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
		X509_VERIFY_PARAM_set_depth(param, 100);
		return param;
	}

	for (iterator = rqst->user_poly_set; iterator; iterator = g_slist_next(iterator)) {
		if (!(obj = OBJ_txt2obj((char*)iterator->data, 1))) {
			log_msg(LOG_DEBUG, "Failed to process userPolicySet value");
			goto end;
		}
		X509_VERIFY_PARAM_add0_policy(param, obj);
	}
	X509_VERIFY_PARAM_set_depth(param, 100);
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

int build_pkc_path(X509 *cert, X509 *anchor, STACK_OF(X509) *uchain, struct scvp_request *scvp_rqst)
{
	int err = 1, flags = 0;
	X509_STORE *store;
	X509_LOOKUP *lookup;
	X509_STORE_CTX *store_ctx = NULL;
	int (*internal_verify)(X509_STORE_CTX *ctx) = NULL;
	int (*check_revocation)(X509_STORE_CTX *ctx) = NULL ;
	X509_VERIFY_PARAM *param = NULL;

	if (!(store = X509_STORE_new())) {
		log_msg(LOG_DEBUG, "OpenSSL X509_STORE_new() failed");
		return 1;
	}
	if (!(lookup = X509_STORE_add_lookup(store, X509_LOOKUP_hash_dir()))) {
		log_msg(LOG_DEBUG, "OpenSSL X509_STORE_add_lookup() failed");
		goto end;
	}
	if (!X509_LOOKUP_add_dir(lookup, cfg.ca_path, X509_FILETYPE_PEM)) {
		log_msg(LOG_DEBUG, "OpenSSL X509_LOOKUP_add_dir() failed");
		goto end;
	}
	if (!X509_LOOKUP_add_dir(lookup, cfg.crl_path, X509_FILETYPE_PEM)) {
		log_msg(LOG_DEBUG, "OpenSSL X509_LOOKUP_add_dir() failed");
		goto end;
	}
	if (!(store_ctx = X509_STORE_CTX_new())) {
		log_msg(LOG_DEBUG, "OpenSSL X509_STORE_CTX_new() failed");
		goto end;
	}

	if(!X509_STORE_CTX_init(store_ctx, store, cert, uchain)) {
		log_msg(LOG_DEBUG, "OpenSSL X509_STORE_CTX_init() failed");
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
		store_ctx->verify = update_chain_crl;
		store_ctx->verify_cb = verify_callback;
		break;
	default:
		log_msg(LOG_DEBUG, "Undefined verify type for PKC path build");
		goto end;
	}

	X509_STORE_CTX_set_flags(store_ctx, X509_V_FLAG_X509_STRICT);
	if (X509_verify_cert(store_ctx) <= 0) {
		log_msg(LOG_DEBUG, "Certificate PKC path verify failed");
		goto end;
	}

	if (anchor)
		if (check_anchor_certificate(store_ctx, anchor)) {
			log_msg(LOG_DEBUG, "Chain doesn't include trust anchor certificate");
			goto end;
		}

	if (scvp_rqst->checks == BUILD_STATUS_CHECKED_PKC_PATH) {
		flags |= X509_V_FLAG_POLICY_CHECK;
		if (!(param = cert_policy_values(scvp_rqst))) {
			log_msg(LOG_DEBUG, "Failed to set certificate path policy parameters");
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
		if (cfg.crl_values & CHECK_PEER)
			flags |= X509_V_FLAG_CRL_CHECK;
		else if (cfg.crl_values & CHECK_ALL)
			flags |= X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL;
		X509_STORE_CTX_set_flags(store_ctx, flags);

		if (check_revocation_ocsp(store_ctx)) {
			log_msg(LOG_DEBUG, "Certificate path OCSP revocation check failed");
			goto end;
		}
		if (!check_revocation(store_ctx)) {
			log_msg(LOG_DEBUG, "Certificate path revocation check failed");
			goto end;
		}
		if (!internal_verify(store_ctx)) {
			log_msg(LOG_DEBUG, "Certificate path validate failed");
			goto end;
		}
		if (flags & X509_V_FLAG_POLICY_MASK)
			if (!store_ctx->check_policy(store_ctx)) {
				log_msg(LOG_DEBUG, "Certificate path validate failed");
				goto end;
			}
	}
	err = 0;
	cache_chain(store_ctx->chain);

end:
	X509_STORE_CTX_free(store_ctx);
	X509_STORE_free(store);
	return err;
}

struct scvp_response *create_scvp_response(struct scvp_request *rqst, int error)
{
	struct scvp_response *resp;
	struct scvp_cert_reply *cert_reply;

	if (!(resp = response_alloc()))
		return NULL;
	if (!(cert_reply = cert_reply_alloc()))
		goto end;

	cert_reply->cert = (struct scvp_cert_der*)rqst->queried_certs->data;
	rqst->queried_certs = g_slist_remove(rqst->queried_certs, rqst->queried_certs->data);
	g_slist_free(rqst->queried_certs);
	rqst->queried_certs = NULL;

	cert_reply->reply_checks = rqst->checks;
	time(&cert_reply->reply_val_time);

	if (error)
		cert_reply->reply_status = CERT_PATH_NOT_VALID;
	else
		cert_reply->reply_status = SUCCESS;

	resp->cert_reply = g_slist_append(resp->cert_reply,  cert_reply);
	resp->val_poly = VAL_POLY_DEFAULT;
	time(&resp->produced_at);
	resp->response_status = OKAY;
	return resp;

end:
	response_free(resp);
	return NULL;
}

extern void *asn1_definitions;

unsigned char *process_scvp_request(unsigned char *rqst_data, int rqst_len, int *resp_len)
{
	int path_err, ret;
	struct scvp_request *scvp_rqst;
	struct scvp_response *scvp_resp = NULL;
	GSList *iterator;
	struct scvp_cert_der *cert_der;
	struct scvp_cert_ref *cert_ref;
	X509 *cert = NULL, *anchor = NULL, *cert_tmp;
	STACK_OF(X509) *uchain = NULL;
	unsigned char *resp_data = NULL, *ptr;

	if (!(scvp_rqst = unpack_scvp_request(asn1_definitions, rqst_data, rqst_len))) {
		log_msg(LOG_DEBUG, "SCVP request unpack failed");
		return NULL;
	}

	if (!scvp_rqst->queried_certs) {
		log_msg(LOG_DEBUG, "Failed to retrieve SCVP request certificate");
		goto end;
	}
	cert_der = (struct scvp_cert_der*)scvp_rqst->queried_certs->data;
	ptr = cert_der->cert;
	if (!(cert = d2i_X509(NULL, (const unsigned char**)&ptr, cert_der->cert_len))) {
		log_msg(LOG_DEBUG, "Failed to decode SCVP request certificate");
		goto end;
	}

	if (!(uchain = sk_X509_new_null())) {
		log_msg(LOG_DEBUG, "Failed alloc untrusted chain");
		goto end;
	}
	if (scvp_rqst->inter_certs) {

		for (iterator = scvp_rqst->inter_certs; iterator; iterator = g_slist_next(iterator)) {
			cert_der = (struct scvp_cert_der*)iterator->data;
			ptr = cert_der->cert;
			if (!(cert_tmp = d2i_X509(NULL, (const unsigned char**)&ptr, cert_der->cert_len))) {
				log_msg(LOG_DEBUG, "Failed to decode SCVP untrusted certificate");
				goto end;
			}
			if (!sk_X509_push(uchain, cert_tmp)) {
				X509_free(cert_tmp);
				goto end;
			}
		}
	}
	load_ca(cert, uchain, 100);
	load_ca_issuers(uchain, 100);

	if (scvp_rqst->trust_anchors) {
		cert_ref = (struct scvp_cert_ref*)scvp_rqst->trust_anchors->data;
		if ((ret = check_cached_cert_ref(cert_ref, cfg.ca_path, &anchor)) == -1) {
			log_msg(LOG_ERR, "Certificate cache error");
			goto end;
		}
		if (ret == 0) {
			log_msg(LOG_DEBUG, "Failed to retrieve anchor certificate from cache");
			goto end;
		}
	}

	if (!(scvp_rqst->checks == BUILD_PKC_PATH || scvp_rqst->checks == BUILD_VALID_PKC_PATH ||
			scvp_rqst->checks == BUILD_STATUS_CHECKED_PKC_PATH)) {
		log_msg(LOG_DEBUG, "Undefined verify type for PKC path build");
		goto end;
	}

	path_err = build_pkc_path(cert, anchor, uchain, scvp_rqst);
	if(!(scvp_resp = create_scvp_response(scvp_rqst, path_err))) {
		log_msg(LOG_DEBUG, "Failed to create scvp response");
		goto end;
	}
	if (!(resp_data = pack_scvp_response(asn1_definitions, scvp_resp, resp_len))) {
		log_msg(LOG_DEBUG, "Failed to create SCVP response");
		goto end;
	}

end:
	X509_free(cert);
	X509_free(anchor);
	chain_free(uchain);
	request_free(scvp_rqst);
	response_free(scvp_resp);
	return resp_data;
}
