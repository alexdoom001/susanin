#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <glib.h>
#include <libtasn1.h>

#include "scvp_proto.h"
#include "channel.h"

static char error_description[ASN1_MAX_ERROR_DESCRIPTION_SIZE];

#define ASN1_ERR(err) if (err != 0) { goto end; }

struct oid_table check_oid[] = {
	{"id-stc-build-pkc-path", "",                                   BUILD_PKC_PATH},
	{"id-stc-build-valid-pkc-path", "",                             BUILD_VALID_PKC_PATH},
	{"id-stc-build-status-checked-pkc-path", "",                    BUILD_STATUS_CHECKED_PKC_PATH},
	{"id-stc-build-aa-path", "",                                    BUILD_AA_PATH},
	{"id-stc-build-valid-aa-path", "",                              BUILD_VALID_AA_PATH},
	{"id-stc-build-status-checked-aa-path", "",                     BUILD_STATUS_CHECKED_AA_PATH},
	{"id-stc-status-check-ac-and-build-status-checked-aa-path", "", STATUS_CHECK_AC_AND_BUILD_STATUS_CHECKED_AA_PATH}
};

struct oid_table alg_err_oid[] = {
	{"id-bvae-expired", "",           EXPIRED},
	{"id-bvae-not-yet-valid", "",     NOT_YET_VALID},
	{"id-bvae-wrongTrustAnchor", "",  WRONG_TRUST_ANCHOR},
	{"id-bvae-noValidCertPath", "",   NO_VALID_CERT_PATH},
	{"id-bvae-revoked", "",           REVOKED},
	{"id-bvae-invalidKeyPurpose", "", INVALID_KEY_PURPOSE},
	{"id-bvae-invalidKeyUsage", "",   INVALID_KEY_USAGE},
	{"id-bvae-invalidCertPolicy", "", INVALID_CERT_POLICY}
};

struct oid_table hash_alg_oid[] = {
	{"sha-1", "", HASH_ALG_SHA1}
};

struct oid_table val_poly_oid[] = {
	{"id-svp-defaultValPolicy", "", VAL_POLY_DEFAULT}
};

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

static int oid_table_initialize(asn1_node *asn1_defs, struct oid_table *oid_list, int list_len)
{
	int err, i, len;
	char str[64];

	for (i = 0; i < list_len; i++) {
		sprintf(str, "SCVP.%s", oid_list[i].oid_name);
		len = sizeof(oid_list[i].oid_str) - 1;
		if ((err = asn1_read_value(*asn1_defs, str, oid_list[i].oid_str, &len)))
			return err;
	}
	return 0;
}

static char *get_oid_str_by_flag(struct oid_table *oid_list, int list_len, unsigned int oid_flag)
{
	int i;

	for (i = 0; i < list_len; i++)
		if (oid_flag == oid_list[i].oid_flag)
			return oid_list[i].oid_str;
	return NULL;
}

static unsigned int get_oid_flag_by_str(struct oid_table *oid_list, int list_len, char *oid_str)
{
	int i;

	for (i = 0; i < list_len; i++)
		if (!strcmp(oid_str, oid_list[i].oid_str))
			return oid_list[i].oid_flag;
	return 0;
}

void *scvp_initialize(const char *asn1_file)
{
	int err;
	asn1_node *asn1_defs;

	if (!(asn1_defs = malloc(sizeof(*asn1_defs))))
		return NULL;
	memset(asn1_defs, 0, sizeof(*asn1_defs));
	if ((err = asn1_parser2tree(asn1_file, asn1_defs, error_description))) {
		free(asn1_defs);
		return NULL;
	}

	if (oid_table_initialize(asn1_defs, check_oid, sizeof(check_oid)/sizeof(check_oid[0])))
		goto end;
	if (oid_table_initialize(asn1_defs, alg_err_oid, sizeof(alg_err_oid)/sizeof(alg_err_oid[0])))
		goto end;
	if (oid_table_initialize(asn1_defs, hash_alg_oid, sizeof(hash_alg_oid)/sizeof(hash_alg_oid[0])))
		goto end;
	if (oid_table_initialize(asn1_defs, val_poly_oid, sizeof(val_poly_oid)/sizeof(val_poly_oid[0])))
		goto end;
	return (void*)asn1_defs;

end:
	asn1_delete_structure(asn1_defs);
	free(asn1_defs);
	return NULL;
}

void scvp_deinitialize(void *asn1_defs)
{
	asn1_node *defs = (asn1_node*)asn1_defs;

	asn1_delete_structure(defs);
	free(defs);
}

unsigned char *pack_scvp_request(void *asn1_defs, struct scvp_request *rqst, int *rqst_len)
{
	int err, rqst_ver = 1;
	asn1_node *defs = (asn1_node*)asn1_defs;
	GSList *iterator;
	asn1_node asn1 = NULL;
	struct scvp_cert_der *cert_der;
	struct scvp_cert_ref *cert_ref;
	unsigned char *rqst_data = NULL;
	char *str_ptr;

	err = asn1_create_element(*defs, "SCVP.CVRequest", &asn1);
	ASN1_ERR(err);
	err = asn1_write_value(asn1, "cvRequestVersion", &rqst_ver, 1);
	ASN1_ERR(err);
	err = asn1_write_value(asn1, "query.checks", "NEW", 1);
	ASN1_ERR(err);
	if (!(str_ptr = get_oid_str_by_flag(check_oid, sizeof(check_oid)/sizeof(check_oid[0]), rqst->checks)))
		goto end;
	err = asn1_write_value(asn1, "query.checks.?1", str_ptr, 0);
	ASN1_ERR(err);
	if (!(str_ptr = get_oid_str_by_flag(val_poly_oid, sizeof(val_poly_oid)/sizeof(val_poly_oid[0]), rqst->val_poly)))
		goto end;
	err = asn1_write_value(asn1, "query.validationPolicy.validationPolRef.valPolId", str_ptr, 0);
	ASN1_ERR(err);

	/* Add certificate policies */
	for(iterator = rqst->user_poly_set; iterator; iterator = g_slist_next(iterator)) {
		str_ptr = (char*)iterator->data;
		err = asn1_write_value(asn1, "query.validationPolicy.userPolicySet", "NEW", 1);
		ASN1_ERR(err);
		err = asn1_write_value(asn1, "query.validationPolicy.userPolicySet.?LAST", str_ptr, 0);
		ASN1_ERR(err);
	}
	if (rqst->user_poly_flags & SCVP_POLY_INHIBIT_MAP) {
		err = asn1_write_value(asn1, "query.validationPolicy.inhibitPolicyMapping", "TRUE", 1);
		ASN1_ERR(err);
	} else {
		err = asn1_write_value(asn1, "query.validationPolicy.inhibitPolicyMapping", NULL, 0);
		ASN1_ERR(err);
	}
	if (rqst->user_poly_flags & SCVP_POLY_EXPLICIT_POLICY) {
		err = asn1_write_value(asn1, "query.validationPolicy.requireExplicitPolicy", "TRUE", 1);
		ASN1_ERR(err);
	} else {
		err = asn1_write_value(asn1, "query.validationPolicy.requireExplicitPolicy", NULL, 0);
		ASN1_ERR(err);
	}
	if (rqst->user_poly_flags & SCVP_POLY_INHIBIT_ANY) {
		err = asn1_write_value(asn1, "query.validationPolicy.inhibitAnyPolicy", "TRUE", 1);
		ASN1_ERR(err);
	} else {
		err = asn1_write_value(asn1, "query.validationPolicy.inhibitAnyPolicy", NULL, 0);
		ASN1_ERR(err);
	}

	/* Add trusted anchor certificate */
	if (rqst->trust_anchors) {
		cert_ref = (struct scvp_cert_ref *)rqst->trust_anchors->data;
		err = asn1_write_value(asn1, "query.validationPolicy.trustAnchors", "NEW", 1);
		ASN1_ERR(err);
		err = asn1_write_value(asn1, "query.validationPolicy.trustAnchors.?1", "pkcRef", 1);
		ASN1_ERR(err);
		err = asn1_write_value(asn1, "query.validationPolicy.trustAnchors.?1.pkcRef.issuerSerial.serialNumber",
				cert_ref->serial, cert_ref->serial_len);
		ASN1_ERR(err);
		err = asn1_write_value(asn1, "query.validationPolicy.trustAnchors.?1.pkcRef.certHash",
				cert_ref->hash, cert_ref->hash_len);
		ASN1_ERR(err);
		if (!(str_ptr = get_oid_str_by_flag(hash_alg_oid, sizeof(hash_alg_oid)/sizeof(hash_alg_oid[0]), cert_ref->hash_alg)))
			goto end;
		err = asn1_write_value(asn1, "query.validationPolicy.trustAnchors.?1.pkcRef.hashAlgorithm.algorithm", str_ptr, 0);
		ASN1_ERR(err);
	}

	/* Add queried certificate */
	if (!rqst->queried_certs)
		goto end;
	cert_der = (struct scvp_cert_der*)rqst->queried_certs->data;
	err = asn1_write_value(asn1, "query.queriedCerts", "pkcRefs", 1);
	ASN1_ERR(err);
	err = asn1_write_value(asn1, "query.queriedCerts.pkcRefs", "NEW", 1);
	ASN1_ERR(err);
	err = asn1_write_value(asn1, "query.queriedCerts.pkcRefs.?1", "cert", 1);
	ASN1_ERR(err);
	err = asn1_write_value(asn1, "query.queriedCerts.pkcRefs.?1.cert", cert_der->cert, cert_der->cert_len);
	ASN1_ERR(err);

	/* Add intermediate certificates */
	for(iterator = rqst->inter_certs; iterator; iterator = g_slist_next(iterator)) {
		cert_der = (struct scvp_cert_der*)iterator->data;
		err = asn1_write_value(asn1, "query.intermediateCerts", "NEW", 1);
		ASN1_ERR(err);
		err = asn1_write_value(asn1, "query.intermediateCerts.?LAST", cert_der->cert, cert_der->cert_len);
		ASN1_ERR(err);
	}

	if (!(rqst_data = malloc(SCVP_MSG_BLOCK_SIZE)))
		goto end;
	*rqst_len = SCVP_MSG_BLOCK_SIZE;
	if ((err = asn1_der_coding(asn1, "", rqst_data, rqst_len, error_description))) {
		if (err == ASN1_MEM_ERROR) {
			if (!(rqst_data = realloc(rqst_data, *rqst_len)))
				goto end;
			if ((err = asn1_der_coding(asn1, "", rqst_data, rqst_len, error_description)))
				goto end;
		}
		else
			goto end;
	}

	asn1_delete_structure(&asn1);
	return rqst_data;

end:
	asn1_delete_structure(&asn1);
	free(rqst_data);
	return NULL;
}

struct scvp_request *unpack_scvp_request(void *asn1_defs, unsigned char *rqst_data, int rqst_len)
{
	int err, rqst_ver = 0, i, len, num;
	asn1_node *defs = (asn1_node*)asn1_defs;
	asn1_node asn1 = NULL;
	struct scvp_request *rqst;
	struct scvp_cert_der *cert_der;
	struct scvp_cert_ref *cert_ref;
	char str_tmp[64], *str_ptr;

	if (!(rqst = request_alloc()))
		return NULL;

	err = asn1_create_element(*defs, "SCVP.CVRequest", &asn1);
	ASN1_ERR(err);
	if ((err = asn1_der_decoding(&asn1, rqst_data, rqst_len, error_description)))
		goto end;
	len = sizeof(rqst_ver);
	err = asn1_read_value(asn1, "cvRequestVersion", &rqst_ver, &len);
	ASN1_ERR(err);
	if (rqst_ver != 1)
		goto end;
	len = sizeof(str_tmp) - 1;
	err = asn1_read_value(asn1, "query.checks.?1", str_tmp, &len);
	ASN1_ERR(err);
	if (!(rqst->checks = get_oid_flag_by_str(check_oid, sizeof(check_oid)/sizeof(check_oid[0]), str_tmp)))
		goto end;
	len = sizeof(str_tmp) - 1;
	err = asn1_read_value(asn1, "query.validationPolicy.validationPolRef.valPolId", str_tmp, &len);
	ASN1_ERR(err);
	if (!(rqst->val_poly = get_oid_flag_by_str(val_poly_oid, sizeof(val_poly_oid)/sizeof(val_poly_oid[0]), str_tmp)))
		goto end;

	/* Get certificate policies */
	err = asn1_number_of_elements(asn1, "query.validationPolicy.userPolicySet", &num);
	ASN1_ERR(err);
	for (i = 0; i < num; i++) {
		if (!(str_ptr = malloc(SCVP_OID_STR_MAX_SIZE)))
			goto end;
		len = SCVP_OID_STR_MAX_SIZE - 1;
		sprintf(str_tmp, "query.validationPolicy.userPolicySet.?%d", i + 1);
		err = asn1_read_value(asn1, str_tmp, str_ptr, &len);
		ASN1_ERR(err);
		rqst->user_poly_set = g_slist_append(rqst->user_poly_set, str_ptr);
	}
	len = sizeof(str_tmp) - 1;
	err = asn1_read_value(asn1, "query.validationPolicy.inhibitPolicyMapping", str_tmp, &len);
	if (err == ASN1_SUCCESS) {
		if (!strcmp(str_tmp, "TRUE"))
			rqst->user_poly_flags |= SCVP_POLY_INHIBIT_MAP;
	}
	len = sizeof(str_tmp) - 1;
	err = asn1_read_value(asn1, "query.validationPolicy.requireExplicitPolicy", str_tmp, &len);
	if (err == ASN1_SUCCESS) {
		if (!strcmp(str_tmp, "TRUE"))
			rqst->user_poly_flags |= SCVP_POLY_EXPLICIT_POLICY;
	}
	len = sizeof(str_tmp) - 1;
	err = asn1_read_value(asn1, "query.validationPolicy.inhibitAnyPolicy", str_tmp, &len);
	if (err == ASN1_SUCCESS) {
		if (!strcmp(str_tmp, "TRUE"))
			rqst->user_poly_flags |= SCVP_POLY_INHIBIT_ANY;
	}

	/* Get trusted anchor certificate */
	err = asn1_number_of_elements(asn1, "query.validationPolicy.trustAnchors", &num);
	ASN1_ERR(err);
	if (num) {
		if (!(cert_ref = cert_ref_alloc()))
			goto end;
		cert_ref->serial_len = X509_SERIAL_NUMBER_MAX_SIZE;
		err = asn1_read_value(asn1, "query.validationPolicy.trustAnchors.?1.pkcRef.issuerSerial.serialNumber",
				cert_ref->serial, (int*)(&cert_ref->serial_len));
		if (err != ASN1_SUCCESS) {
			cert_ref_free(cert_ref);
			goto end;
		}
		cert_ref->hash_len = sizeof(cert_ref->hash);
		err = asn1_read_value(asn1, "query.validationPolicy.trustAnchors.?1.pkcRef.certHash", &cert_ref->hash,
				(int*)(&cert_ref->hash_len));
		if (err != ASN1_SUCCESS) {
			cert_ref_free(cert_ref);
			goto end;
		}
		len = sizeof(str_tmp) - 1;
		err = asn1_read_value(asn1, "query.validationPolicy.trustAnchors.?1.pkcRef.hashAlgorithm.algorithm", str_tmp, &len);
		if (err != ASN1_SUCCESS) {
			cert_ref_free(cert_ref);
			goto end;
		}
		if (!(cert_ref->hash_alg = get_oid_flag_by_str(hash_alg_oid, sizeof(hash_alg_oid)/sizeof(hash_alg_oid[0]), str_tmp)))
			goto end;
		rqst->trust_anchors = g_slist_append(rqst->queried_certs, cert_ref);
	}

	/* Get queried certificate */
	if (!(cert_der = cert_der_alloc()))
		goto end;
	if (!(cert_der->cert = malloc(SCVP_MSG_BLOCK_SIZE))) {
		cert_der_free(cert_der);
		goto end;
	}
	cert_der->cert_len = SCVP_MSG_BLOCK_SIZE;
	err = asn1_read_value(asn1, "query.queriedCerts.pkcRefs.?1.cert", cert_der->cert, (int*)(&cert_der->cert_len));
	if (err != ASN1_SUCCESS) {
		if (err == ASN1_MEM_ERROR) {
			if (!(cert_der->cert = realloc(cert_der->cert, cert_der->cert_len))) {
				cert_der_free(cert_der);
				goto end;
			}
			err = asn1_read_value(asn1, "query.queriedCerts.pkcRefs.?1.cert", cert_der->cert, (int*)(&cert_der->cert_len));
			if (err != ASN1_SUCCESS) {
				cert_der_free(cert_der);
				goto end;
			}
		} else {
			cert_der_free(cert_der);
			goto end;
		}
	}
	rqst->queried_certs = g_slist_append(rqst->queried_certs, cert_der);

	/* Get intermediate certificates */
	err = asn1_number_of_elements(asn1, "query.intermediateCerts", &num);
	ASN1_ERR(err);
	for (i = 0; i < num; i++) {
		if (!(cert_der = cert_der_alloc()))
			goto end;
		if (!(cert_der->cert = malloc(SCVP_MSG_BLOCK_SIZE))) {
			cert_der_free(cert_der);
			goto end;
		}
		cert_der->cert_len = SCVP_MSG_BLOCK_SIZE;
		sprintf(str_tmp, "query.intermediateCerts.?%d", i + 1);
		err = asn1_read_value(asn1, str_tmp, cert_der->cert, (int*)(&cert_der->cert_len));
		if (err != ASN1_SUCCESS) {
			if (err == ASN1_MEM_ERROR) {
				if (!(cert_der->cert = realloc(cert_der->cert, cert_der->cert_len))) {
					cert_der_free(cert_der);
					goto end;
				}
				sprintf(str_tmp, "query.intermediateCerts.?%d", i + 1);
				err = asn1_read_value(asn1, str_tmp, cert_der->cert, (int*)(&cert_der->cert_len));
				if (err != ASN1_SUCCESS) {
					cert_der_free(cert_der);
					goto end;
				}
			} else {
				cert_der_free(cert_der);
				goto end;
			}
		}
		rqst->inter_certs = g_slist_append(rqst->inter_certs, cert_der);
	}

	asn1_delete_structure(&asn1);
	return rqst;

end:
	asn1_delete_structure(&asn1);
	request_free(rqst);
	return NULL;
}

unsigned char *pack_scvp_response(void *asn1_defs, struct scvp_response *resp, int *resp_len)
{
	int err, resp_ver = 1, config_id = 1;
	asn1_node *defs = (asn1_node*)asn1_defs;
	asn1_node asn1 = NULL;
	struct scvp_cert_reply *cert_reply;
	unsigned char *resp_data = NULL;
	char str_tmp[64], *str_ptr;

	err = asn1_create_element(*defs, "SCVP.CVResponse", &asn1);
	ASN1_ERR(err);
	err = asn1_write_value(asn1, "cvResponseVersion", &resp_ver, 1);
	ASN1_ERR(err);
	err = asn1_write_value(asn1, "serverConfigurationID", &config_id, 1);
	ASN1_ERR(err);
	strftime(str_tmp, sizeof(str_tmp) - 1, "%Y%m%d%H%M%SZ", localtime(&resp->produced_at));
	err = asn1_write_value(asn1, "producedAt", str_tmp, 1);
	ASN1_ERR(err);
	err = asn1_write_value(asn1, "responseStatus.statusCode", &resp->response_status, 1);
	ASN1_ERR(err);

	if (resp->response_status == OKAY) {
		err = asn1_write_value(asn1, "respValidationPolicy", NULL, 0);
		ASN1_ERR(err);
		cert_reply = (struct scvp_cert_reply *)resp->cert_reply->data;
		err = asn1_write_value(asn1, "replyObjects", "NEW", 1);
		ASN1_ERR(err);
		err = asn1_write_value(asn1, "replyObjects.?1.replyChecks", "NEW", 1);
		ASN1_ERR(err);
		if (!(str_ptr = get_oid_str_by_flag(check_oid, sizeof(check_oid)/sizeof(check_oid[0]), cert_reply->reply_checks)))
			goto end;
		err = asn1_write_value(asn1, "replyObjects.?1.replyChecks.?1.check", str_ptr, 0);
		ASN1_ERR(err);
		err = asn1_write_value(asn1, "replyObjects.?1.replyStatus", &cert_reply->reply_status, 1);
		ASN1_ERR(err);
		strftime(str_tmp, sizeof(str_tmp) - 1, "%Y%m%d%H%M%SZ", localtime(&cert_reply->reply_val_time));
		err = asn1_write_value(asn1, "replyObjects.?1.replyValTime", str_tmp, 1);
		ASN1_ERR(err);

		if (!cert_reply->cert)
			goto end;
		err = asn1_write_value(asn1, "replyObjects.?1.cert", "cert", 1);
		ASN1_ERR(err);
		err = asn1_write_value(asn1, "replyObjects.?1.cert.cert", cert_reply->cert->cert, cert_reply->cert->cert_len);
		ASN1_ERR(err);

		if (cert_reply->val_errors) {
			if (!(str_ptr = get_oid_str_by_flag(alg_err_oid, sizeof(alg_err_oid)/sizeof(alg_err_oid[0]), cert_reply->val_errors)))
				goto end;
			err = asn1_write_value(asn1, "replyObjects.?1.validationErrors", "NEW", 1);
			ASN1_ERR(err);
			err = asn1_write_value(asn1, "replyObjects.?1.validationErrors.?1", str_ptr, 0);
			ASN1_ERR(err);
		}
	}

	if (!(resp_data = malloc(SCVP_MSG_BLOCK_SIZE)))
		goto end;
	*resp_len = SCVP_MSG_BLOCK_SIZE;
	if ((err = asn1_der_coding(asn1, "", resp_data, resp_len, error_description))) {
		if (err == ASN1_MEM_ERROR) {
			if (!(resp_data = realloc(resp_data, *resp_len)))
				goto end;
			if ((err = asn1_der_coding(asn1, "", resp_data, resp_len, error_description)))
				goto end;
		}
		else
			goto end;
	}
	asn1_delete_structure(&asn1);
	return resp_data;

end:
	asn1_delete_structure(&asn1);
	free(resp_data);
	return NULL;
}

struct scvp_response *unpack_scvp_response(void *asn1_defs, unsigned char *resp_data, int resp_len)
{
	int err, rspn_ver = 0, config_id = 0, len;
	asn1_node *defs = (asn1_node*)asn1_defs;
	asn1_node asn1 = NULL;
	struct scvp_response *resp;
	struct scvp_cert_reply *cert_reply = NULL;
	struct tm time_val;
	char str_tmp[64];

	if (!(resp = response_alloc()))
		return NULL;

	err = asn1_create_element(*defs, "SCVP.CVResponse", &asn1);
	ASN1_ERR(err);
	if ((err = asn1_der_decoding(&asn1, resp_data, resp_len, error_description)))
		goto end;
	len = sizeof(rspn_ver);
	err = asn1_read_value(asn1, "cvResponseVersion", &rspn_ver, &len);
	ASN1_ERR(err);
	if (rspn_ver != 1)
		goto end;
	len = sizeof(config_id);
	err = asn1_read_value(asn1, "serverConfigurationID", &config_id, &len);
	ASN1_ERR(err);
	if (config_id != 1)
		goto end;
	len = sizeof(str_tmp) - 1;
	err = asn1_read_value(asn1, "producedAt", str_tmp, &len);
	ASN1_ERR(err);
	strptime(str_tmp, "%Y%m%d%H%M%SZ", &time_val);
	resp->produced_at = mktime(&time_val);
	if (resp->produced_at == -1)
		goto end;
	len = sizeof(resp->response_status);
	resp->response_status = 1;
	err = asn1_read_value(asn1, "responseStatus.statusCode", &resp->response_status, &len);
	ASN1_ERR(err);
	if (resp->response_status != OKAY) {
		asn1_delete_structure(&asn1);
		return resp;
	}

	if (!(cert_reply = cert_reply_alloc()))
		goto end;
	if (!(cert_reply->cert =cert_der_alloc()))
		goto end;
	len = sizeof(str_tmp) - 1;
	err = asn1_read_value(asn1, "replyObjects.?1.replyChecks.?1.check", str_tmp, &len);
	ASN1_ERR(err);
	if (!(cert_reply->reply_checks = get_oid_flag_by_str(check_oid, sizeof(check_oid)/sizeof(check_oid[0]), str_tmp)))
		goto end;
	len = sizeof(str_tmp) - 1;
	err = asn1_read_value(asn1, "replyObjects.?1.replyValTime", str_tmp, &len);
	ASN1_ERR(err);
	strptime(str_tmp, "%Y%m%d%H%M%SZ", &time_val);
	cert_reply->reply_val_time = mktime(&time_val);
	if (cert_reply->reply_val_time == -1)
		goto end;
	len = sizeof(str_tmp) - 1;
	err = asn1_read_value(asn1, "replyObjects.?1.validationErrors.?1", str_tmp, &len);
	if (!err)
		if (!(cert_reply->val_errors = get_oid_flag_by_str(alg_err_oid, sizeof(alg_err_oid)/sizeof(alg_err_oid[0]), str_tmp)))
			goto end;

	if (!(cert_reply->cert = cert_der_alloc()))
		goto end;
	if (!(cert_reply->cert->cert = malloc(SCVP_MSG_BLOCK_SIZE)))
		goto end;
	cert_reply->cert->cert_len = SCVP_MSG_BLOCK_SIZE;
	err = asn1_read_value(asn1, "replyObjects.?1.cert.cert", cert_reply->cert->cert, (int*)(&cert_reply->cert->cert_len));
	if (err != ASN1_SUCCESS) {
		if (err == ASN1_MEM_ERROR) {
			if (!(cert_reply->cert->cert = realloc(cert_reply->cert->cert, cert_reply->cert->cert_len)))
				goto end;
			err = asn1_read_value(asn1, "replyObjects.?1.cert.cert", cert_reply->cert->cert, (int*)(&cert_reply->cert->cert_len));
			if (err != ASN1_SUCCESS)
				goto end;
		} else
			goto end;
	}

	len = sizeof(cert_reply->reply_status);
	err = asn1_read_value(asn1, "replyObjects.?1.replyStatus", &cert_reply->reply_status, &len);
	ASN1_ERR(err);
	resp->cert_reply = g_slist_append(resp->cert_reply, cert_reply);
	asn1_delete_structure(&asn1);
	return resp;

end:
	asn1_delete_structure(&asn1);
	response_free(resp);
	cert_reply_free(cert_reply);
	return NULL;
}
