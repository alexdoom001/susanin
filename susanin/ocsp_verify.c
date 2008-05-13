#include <openssl/crypto.h>
#include <openssl/lhash.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/ocsp.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <syslog.h>

#include "path_checker.h"
#include "ocsp_verify.h"
#include "config.h"
#include "logger.h"

struct cert_ocsp_ref *cert_ocsp_alloc(void)
{
	struct cert_ocsp_ref *cert_ocsp;

	if (!(cert_ocsp = malloc(sizeof(*cert_ocsp)))) {
		log_msg(LOG_ERR, "malloc() failed");
		return NULL;
	}
	memset(cert_ocsp, 0, sizeof(*cert_ocsp));
	return cert_ocsp;
}

void cert_ocsp_free(struct cert_ocsp_ref *cert_ocsp)
{
	if (!cert_ocsp)
		return;
	ASN1_INTEGER_free(cert_ocsp->serial);
	free(cert_ocsp->url);
	free(cert_ocsp);
}

static OCSP_RESPONSE *query_responder(BIO *cbio, char *path, STACK_OF(CONF_VALUE) *headers,
		OCSP_REQUEST *rqst, int rqst_timeout)
{
	int fd, rv, i;
	OCSP_REQ_CTX *ctx = NULL;
	OCSP_RESPONSE *rsp = NULL;
	fd_set confds;
	struct timeval tv;

	if (rqst_timeout != -1)
		BIO_set_nbio(cbio, 1);
	rv = BIO_do_connect(cbio);
	if ((rv <= 0) && ((rqst_timeout == -1) || !BIO_should_retry(cbio)))
		return NULL;
	if (BIO_get_fd(cbio, &fd) <= 0)
		goto end;

	if (rqst_timeout != -1 && rv <= 0) {
		FD_ZERO(&confds);
		FD_SET(fd, &confds);
		tv.tv_usec = 0;
		tv.tv_sec = rqst_timeout;
		rv = select(fd + 1, NULL, (void *)&confds, NULL, &tv);
		if (rv == 0) {
			log_msg(LOG_DEBUG, "OCSP responder connection timeout");
			return NULL;
		}
	}
	if (!(ctx = OCSP_sendreq_new(cbio, path, NULL, -1)))
		return NULL;
	for (i = 0; i < sk_CONF_VALUE_num(headers); i++) {
		CONF_VALUE *hdr = sk_CONF_VALUE_value(headers, i);
		if (!OCSP_REQ_CTX_add1_header(ctx, hdr->name, hdr->value))
			goto end;
	}
	if (!OCSP_REQ_CTX_set1_req(ctx, rqst))
		goto end;

	while (1) {
		if ((rv = OCSP_sendreq_nbio(&rsp, ctx)) != -1)
			break;
		if (rqst_timeout == -1)
			continue;
		FD_ZERO(&confds);
		FD_SET(fd, &confds);
		tv.tv_usec = 0;
		tv.tv_sec = rqst_timeout;
		if (BIO_should_read(cbio))
			rv = select(fd + 1, (void *)&confds, NULL, NULL, &tv);
		else if (BIO_should_write(cbio))
			rv = select(fd + 1, NULL, (void *)&confds, NULL, &tv);
		else {
			log_msg(LOG_DEBUG, "OCSP responder unexpected retry condition");
			goto end;
		}
		if (rv == 0) {
			log_msg(LOG_DEBUG, "OCSP responder request timeout");
			break;
		}
		if (rv == -1) {
			log_msg(LOG_DEBUG, "OCSP responder select error");
			break;
		}
	}

end:
	OCSP_REQ_CTX_free(ctx);
	return rsp;
}

static OCSP_RESPONSE *connect_responder(char *host, char *path, char *port, int use_ssl,
		STACK_OF(CONF_VALUE) *headers, OCSP_REQUEST *rqst, int rqst_timeout)
{
	BIO *cbio = NULL, *sbio;
	SSL_CTX *ssl_ctx = NULL;
	OCSP_RESPONSE *resp = NULL;

	if (!(cbio = BIO_new_connect(host)))
		goto end;
	if (port)
		BIO_set_conn_port(cbio, port);
	if (use_ssl == 1) {
#if !defined(OPENSSL_NO_SSL2) && !defined(OPENSSL_NO_SSL3)
		ssl_ctx = SSL_CTX_new(SSLv23_client_method());
#elif !defined(OPENSSL_NO_SSL3)
		ssl_ctx = SSL_CTX_new(SSLv3_client_method());
#elif !defined(OPENSSL_NO_SSL2)
		ssl_ctx = SSL_CTX_new(SSLv2_client_method());
#else
		log_msg(LOG_DEBUG, "SSL is disabled");
		goto end;
#endif
		if (ssl_ctx == NULL)
			goto end;
		SSL_CTX_set_mode(ssl_ctx, SSL_MODE_AUTO_RETRY);
		sbio = BIO_new_ssl(ssl_ctx, 1);
		cbio = BIO_push(sbio, cbio);
	}
	resp = query_responder(cbio, path, headers, rqst, rqst_timeout);

end:
	BIO_free_all(cbio);
	SSL_CTX_free(ssl_ctx);
	return resp;
}

static int get_params(X509 *cert, char **host, char **port, char **path, int *use_ssl)
{
	int err = -1;
	GSList *iterator;
	struct cert_ocsp_ref *cert_ocsp = NULL;
	char *url = NULL;
	STACK_OF(OPENSSL_STRING) *url_str = NULL;
	ASN1_INTEGER *serial;
	unsigned char cert_hash[EVP_MAX_MD_SIZE];
	unsigned int cert_hash_len;

	X509_digest(cert, EVP_sha1(), cert_hash, &cert_hash_len);
	serial = X509_get_serialNumber(cert);
	for (iterator = cfg.cert_ocsp_list; iterator; iterator = g_slist_next(iterator))
		if (!M_ASN1_INTEGER_cmp(serial, ((struct cert_ocsp_ref*)iterator->data)->serial))
			if (!memcmp(cert_hash, ((struct cert_ocsp_ref*)iterator->data)->hash, cert_hash_len)) {
				cert_ocsp = (struct cert_ocsp_ref*)iterator->data;
				break;
			}
	if (cert_ocsp) {
		if (cert_ocsp->validate == OCSP_VALIDATE_DISABLED)
			goto end;
		url = cert_ocsp->url;
	}
	if (!url)
		if ((url_str = X509_get1_ocsp(cert)))
			url = sk_OPENSSL_STRING_value(url_str, 0);
	if (!url) {
		if (cfg.ocsp_values & CHECK_AVAILABLE) {
			err = 0;
			goto end;
		}
		log_msg(LOG_DEBUG, "Failed to retrieve certificate OCSP URL");
		goto end;
	}
	if (!OCSP_parse_url(url, host, port, path, use_ssl)) {
		log_msg(LOG_DEBUG, "Certificate OCSP URL parse failed");
		goto end;
	}
	err = 1;

end:
	X509_email_free(url_str);
	return err;
}

static int process_response(X509_STORE_CTX *store_ctx, OCSP_REQUEST *rqst, OCSP_RESPONSE *resp, OCSP_CERTID *cert_id)
{
	int err = 1, i, status, reason;
	OCSP_BASICRESP *bs;
	ASN1_GENERALIZEDTIME *rev, *thisupd, *nextupd;

	if ((i = OCSP_response_status(resp)) != OCSP_RESPONSE_STATUS_SUCCESSFUL) {
		log_msg(LOG_DEBUG, "OCSP responder error: %s (%d)", OCSP_response_status_str(i), i);
		return 1;
	}
	if (!(bs = OCSP_response_get1_basic(resp))) {
		log_msg(LOG_DEBUG, "Failed to parse OCSP response");
		return 1;
	}
	if (!(cfg.ocsp_values & DISABLE_NONCE)) {
		if ((OCSP_check_nonce(rqst, bs)) <= 0) {
			log_msg(LOG_DEBUG, "OCSP nonce check failed");
			goto end;
		}
	}
	i = OCSP_basic_verify(bs, store_ctx->chain, store_ctx->ctx, 0);
	if (i < 0)
		i = OCSP_basic_verify(bs, NULL, store_ctx->ctx, 0);
	if(i <= 0) {
		log_msg(LOG_DEBUG, "OCSP response verification failed");
		goto end;
	}

	if(!OCSP_resp_find_status(bs, cert_id, &status, &reason, &rev, &thisupd, &nextupd)) {
		log_msg(LOG_DEBUG, "No status found in OCSP response");
		goto end;
	}
	switch(status) {
	case V_OCSP_CERTSTATUS_GOOD:
		break;
	case V_OCSP_CERTSTATUS_REVOKED:
	case V_OCSP_CERTSTATUS_UNKNOWN:
	default:
		log_msg(LOG_DEBUG, "Bad OCSP status: %s", OCSP_cert_status_str(status));
		goto end;
	}
	err = 0;

end:
	OCSP_BASICRESP_free(bs);
	return err;
}

static int cert_ocsp_verify(X509_STORE_CTX *store_ctx, int depth)
{
	int err = 1, ret, pssl;
	X509 *cert, *issuer_cert;
	OCSP_REQUEST *rqst = NULL;
	OCSP_RESPONSE *resp = NULL;
	OCSP_CERTID *cert_id;
	char *host = NULL, *port = NULL, *path = NULL;

	if (!(cert = sk_X509_value(store_ctx->chain, depth)))
		return 1;
	if (!(issuer_cert = sk_X509_value(store_ctx->chain, depth + 1)))
		return 1;
	if ((ret = get_params(issuer_cert, &host, &port, &path, &pssl)) == -1)
		return 1;
	if (!ret)
		return 0;
	if (pssl) {
		log_msg(LOG_DEBUG, "HTTPS connection to OCSP responder is not supported");
		goto end;
	}
	if (!(rqst = OCSP_REQUEST_new()))
		goto end;
	if (!(cert_id = OCSP_cert_to_id(NULL, cert, issuer_cert)))
		goto end;
	if (!OCSP_request_add0_id(rqst, cert_id)) {
		OCSP_CERTID_free(cert_id);
		goto end;
	}
	if (!(cfg.ocsp_values & DISABLE_NONCE))
		OCSP_request_add1_nonce(rqst, NULL, -1);

	if (!(resp = connect_responder(host, path, port, pssl, NULL, rqst, -1)))	{
		log_msg(LOG_DEBUG, "Failed to connect OCSP responder");
		goto end;
	}
	if (process_response(store_ctx, rqst, resp, cert_id))
		goto end;
	err = 0;

end:
	if (host)
		OPENSSL_free(host);
	if (path)
		OPENSSL_free(path);
	if (port)
		OPENSSL_free(port);
	if (rqst)
		OCSP_REQUEST_free(rqst);
	if (resp)
		OCSP_RESPONSE_free(resp);
	return err;
}

int check_revocation_ocsp(X509_STORE_CTX *ctx)
{
	int i, last;

	if (!(cfg.ocsp_values & (CHECK_AVAILABLE | CHECK_ACCURATE)))
		return 0;
	if (sk_X509_num(ctx->chain) == 1) {
		log_msg(LOG_DEBUG, "Skip OCSP check for single certificate in chain");
		return 0;
	}
	if (cfg.ocsp_values & CHECK_ALL)
		last = sk_X509_num(ctx->chain) - 1;
	else {
		if (ctx->parent)
			return 1;
		last = 1;
	}
	for(i = 0; i < last; i++)
		if (cert_ocsp_verify(ctx, i))
			return 1;
	return 0;
}
