#include <stdlib.h>
#include <string.h>
#include <glib.h>

#include "scvp_defs.h"

struct scvp_cert_der *cert_der_alloc(void)
{
	struct scvp_cert_der *cert;

	if (!(cert = malloc(sizeof(*cert))))
		return NULL;
	memset(cert, 0, sizeof(*cert));
	return cert;
}

void cert_der_free(struct scvp_cert_der *cert)
{
	if (!cert)
		return;
	free(cert->cert);
	free(cert);
}

struct scvp_cert_ref *cert_ref_alloc(void)
{
	struct scvp_cert_ref *cert;

	if (!(cert = malloc(sizeof(*cert))))
		return NULL;
	memset(cert, 0, sizeof(*cert));
	return cert;
}

void cert_ref_free(struct scvp_cert_ref *cert)
{
	free(cert);
}

struct scvp_request *request_alloc(void)
{
	struct scvp_request *rqst;

	if (!(rqst = malloc(sizeof(*rqst))))
		return NULL;
	memset(rqst, 0, sizeof(*rqst));
	return rqst;
}

void request_free(struct scvp_request *rqst)
{
	GSList *iterator;

	if (!rqst)
		return;
	for(iterator = rqst->trust_anchors; iterator; iterator = g_slist_next(iterator))
		cert_ref_free((struct scvp_cert_ref *)iterator->data);
	g_slist_free(rqst->trust_anchors);
	for(iterator = rqst->queried_certs; iterator; iterator = g_slist_next(iterator))
		cert_der_free((struct scvp_cert_der *)iterator->data);
	g_slist_free(rqst->queried_certs);
	for(iterator = rqst->inter_certs; iterator; iterator = g_slist_next(iterator))
		cert_der_free((struct scvp_cert_der *)iterator->data);
	g_slist_free(rqst->inter_certs);
	for(iterator = rqst->user_poly_set; iterator; iterator = g_slist_next(iterator))
		free(iterator->data);
	g_slist_free(rqst->user_poly_set);
	free(rqst);
}

struct scvp_cert_reply *cert_reply_alloc(void)
{
	struct scvp_cert_reply *cert_reply;

	if (!(cert_reply = malloc(sizeof(*cert_reply))))
		return NULL;
	memset(cert_reply, 0, sizeof(*cert_reply));
	return cert_reply;
}

void cert_reply_free(struct scvp_cert_reply *cert_reply)
{
	if (!cert_reply)
		return;
	cert_der_free(cert_reply->cert);
	free(cert_reply);
}

struct scvp_response *response_alloc(void)
{
	struct scvp_response *resp;

	if (!(resp = malloc(sizeof(*resp))))
		return NULL;
	memset(resp, 0, sizeof(*resp));
	return resp;
}

void response_free(struct scvp_response *resp)
{
	GSList *iterator;

	if (!resp)
		return;
	for(iterator = resp->cert_reply; iterator; iterator = g_slist_next(iterator))
		cert_reply_free((struct scvp_cert_reply *)iterator->data);
	g_slist_free(resp->cert_reply);
	free(resp);
}
