#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <glib.h>
#include <libtasn1.h>

#include "scvp_defs.h"
#include "scvp_proto.h"
#include "channel.h"

#include "asn1_defs.c"

struct scvp_proto_ctx {
	asn1_node asn1_defs;
};

#define ASN1_ERR(err) if (err != ASN1_SUCCESS) { goto end; }

static const struct oid_table check_oid[] = {
	{"1.3.6.1.5.5.7.17.1", BUILD_PKC_PATH},                                     /* id-stc-build-pkc-path */
	{"1.3.6.1.5.5.7.17.2", BUILD_VALID_PKC_PATH},                               /* id-stc-build-valid-pkc-path */
	{"1.3.6.1.5.5.7.17.3", BUILD_STATUS_CHECKED_PKC_PATH},                      /* id-stc-build-status-checked-pkc-path */
	{"1.3.6.1.5.5.7.17.4", BUILD_AA_PATH},                                      /* id-stc-build-aa-path */
	{"1.3.6.1.5.5.7.17.5", BUILD_VALID_AA_PATH},                                /* id-stc-build-valid-aa-path */
	{"1.3.6.1.5.5.7.17.6", BUILD_STATUS_CHECKED_AA_PATH},                       /* id-stc-build-status-checked-aa-path */
	{"1.3.6.1.5.5.7.17.7", STATUS_CHECK_AC_AND_BUILD_STATUS_CHECKED_AA_PATH}    /* id-stc-status-check-ac-and-build-status-checked-aa-path */
};

static const struct oid_table alg_err_oid[] = {
	{"1.3.6.1.5.5.7.19.3.1", EXPIRED},                                          /* id-bvae-expired */
	{"1.3.6.1.5.5.7.19.3.2", NOT_YET_VALID},                                    /* id-bvae-not-yet-valid */
	{"1.3.6.1.5.5.7.19.3.3", WRONG_TRUST_ANCHOR},                               /* id-bvae-wrongTrustAnchor */
	{"1.3.6.1.5.5.7.19.3.4", NO_VALID_CERT_PATH},                               /* id-bvae-noValidCertPath */
	{"1.3.6.1.5.5.7.19.3.5", REVOKED},                                          /* id-bvae-revoked */
	{"1.3.6.1.5.5.7.19.3.9", INVALID_KEY_PURPOSE},                              /* id-bvae-invalidKeyPurpose */
	{"1.3.6.1.5.5.7.19.3.10", INVALID_KEY_USAGE},                               /* id-bvae-invalidKeyUsage */
	{"1.3.6.1.5.5.7.19.3.11", INVALID_CERT_POLICY}                              /* id-bvae-invalidCertPolicy */
};

static const struct oid_table hash_alg_oid[] = {
	{"1.3.14.3.2.26", HASH_ALG_SHA1}                                            /* sha-1 */
};

static const struct oid_table val_poly_oid[] = {
	{"1.3.6.1.5.5.7.19.1", VAL_POLY_DEFAULT}                                    /* id-svp-defaultValPolicy */
};

static const char *get_oid_str_by_flag(const struct oid_table *table, int table_len, unsigned int flag)
{
	int i;

	for (i = 0; i < table_len; i++)
		if (flag == table[i].flag)
			return table[i].str;
	return NULL;
}

static unsigned int get_oid_flag_by_str(const struct oid_table *table, int table_len, const char *str)
{
	int i;

	for (i = 0; i < table_len; i++)
		if (strcmp(str, table[i].str) == 0)
			return table[i].flag;
	return 0;
}

struct scvp_proto_ctx *scvp_init(void)
{
	struct scvp_proto_ctx *ctx;

	if (!(ctx = malloc(sizeof(*ctx))))
		return NULL;
	memset(ctx, 0, sizeof(*ctx));
	if (asn1_array2tree(asn1_defs_array, &ctx->asn1_defs, NULL)) {
		free(ctx);
		return NULL;
	}
	return ctx;
}

void scvp_deinit(struct scvp_proto_ctx *ctx)
{
	if (!ctx)
		return;
	asn1_delete_structure(&ctx->asn1_defs);
	free(ctx);
}

unsigned char *pack_scvp_request(const struct scvp_proto_ctx *ctx, const struct scvp_request *rqst, int *rqst_len)
{
	int err, rqst_ver = 1;
	GSList *iterator;
	asn1_node asn1 = NULL;
	struct scvp_cert_der *cert_der;
	struct scvp_cert_ref *cert_ref;
	unsigned char *rqst_data = NULL;
	const char *str_ptr;

	err = asn1_create_element(ctx->asn1_defs, "SCVP.CVRequest", &asn1);
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
	if ((err = asn1_der_coding(asn1, "", rqst_data, rqst_len, NULL))) {
		if (err == ASN1_MEM_ERROR) {
			unsigned char *ptr;

			ptr = realloc(rqst_data, *rqst_len);
			if (ptr == NULL)
				goto end;
			rqst_data = ptr;
			if ((err = asn1_der_coding(asn1, "", rqst_data, rqst_len, NULL)))
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

struct scvp_request *unpack_scvp_request(const struct scvp_proto_ctx *ctx, const unsigned char *rqst_data, int rqst_len)
{
	int err, rqst_ver = 0, i, len, num;
	asn1_node asn1 = NULL;
	struct scvp_request *rqst;
	struct scvp_cert_der *cert_der;
	struct scvp_cert_ref *cert_ref;
	char str_tmp[64], *str_ptr;

	if (!(rqst = request_alloc()))
		return NULL;

	err = asn1_create_element(ctx->asn1_defs, "SCVP.CVRequest", &asn1);
	ASN1_ERR(err);
	if ((err = asn1_der_decoding(&asn1, rqst_data, rqst_len, NULL)))
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
		if (strcmp(str_tmp, "TRUE") == 0)
			rqst->user_poly_flags |= SCVP_POLY_INHIBIT_MAP;
	}
	len = sizeof(str_tmp) - 1;
	err = asn1_read_value(asn1, "query.validationPolicy.requireExplicitPolicy", str_tmp, &len);
	if (err == ASN1_SUCCESS) {
		if (strcmp(str_tmp, "TRUE") == 0)
			rqst->user_poly_flags |= SCVP_POLY_EXPLICIT_POLICY;
	}
	len = sizeof(str_tmp) - 1;
	err = asn1_read_value(asn1, "query.validationPolicy.inhibitAnyPolicy", str_tmp, &len);
	if (err == ASN1_SUCCESS) {
		if (strcmp(str_tmp, "TRUE") == 0)
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
			unsigned char *ptr;

			ptr = realloc(cert_der->cert, cert_der->cert_len);
			if (ptr == NULL) {
				cert_der_free(cert_der);
				goto end;
			}
			cert_der->cert = ptr;
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
				unsigned char *ptr;

				ptr = realloc(cert_der->cert, cert_der->cert_len);
				if (ptr == NULL) {
					cert_der_free(cert_der);
					goto end;
				}
				cert_der->cert = ptr;
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

unsigned char *pack_scvp_response(const struct scvp_proto_ctx *ctx, const struct scvp_response_srv *resp, int *resp_len)
{
	int err, resp_ver = 1, config_id = 1;
	asn1_node asn1 = NULL;
	struct scvp_cert_reply *cert_reply;
	unsigned char *resp_data = NULL;
	char str_tmp[64];
	const char *str_ptr;

	err = asn1_create_element(ctx->asn1_defs, "SCVP.CVResponse", &asn1);
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
	if (resp->error_msg) {
		err = asn1_write_value(asn1, "responseStatus.errorMessage", resp->error_msg, 0);
		ASN1_ERR(err);
	} else {
		err = asn1_write_value(asn1, "responseStatus.errorMessage", NULL, 0);
		ASN1_ERR(err);
	}

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
	if ((err = asn1_der_coding(asn1, "", resp_data, resp_len, NULL))) {
		if (err == ASN1_MEM_ERROR) {
			unsigned char *ptr;

			ptr = realloc(resp_data, *resp_len);
			if (ptr == NULL)
				goto end;
			resp_data = ptr;
			if ((err = asn1_der_coding(asn1, "", resp_data, resp_len, NULL)))
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

static time_t string_to_time(const char *str)
{
	int res;
	struct tm t;

	memset(&t, 0, sizeof(t));
	res = sscanf(str, "%4d%2d%2d%2d%2d%2dZ", &t.tm_year, &t.tm_mon, &t.tm_mday,
			&t.tm_hour, &t.tm_min, &t.tm_sec);
	if (res != 6)
		return 1;
	if (t.tm_year < 1900)
		return 1;
	t.tm_year -= 1900;
	if (t.tm_mon < 1 || t.tm_mon > 12)
		return 1;
	--t.tm_mon;
	if(t.tm_mday < 1 || t.tm_mday > 31)
		return 1;
	if(t.tm_hour < 0 || t.tm_hour > 23)
		return 1;
	if (t.tm_min < 0 || t.tm_min > 59)
		return 1;
	if (t.tm_sec < 0 || t.tm_sec > 59)
		return 1;
	t.tm_isdst = -1;
	return mktime(&t);
}

struct scvp_response_cli *unpack_scvp_response(const struct scvp_proto_ctx *ctx, const unsigned char *resp_data, int resp_len)
{
	int err, rspn_ver = 0, config_id = 0, len;
	asn1_node asn1 = NULL;
	struct scvp_response_cli *resp;
	struct scvp_cert_reply *cert_reply = NULL;
	char str_tmp[64];

	if (!(resp = response_cli_alloc()))
		return NULL;

	err = asn1_create_element(ctx->asn1_defs, "SCVP.CVResponse", &asn1);
	ASN1_ERR(err);
	if ((err = asn1_der_decoding(&asn1, resp_data, resp_len, NULL)))
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
	resp->produced_at = string_to_time(str_tmp);
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
	if (!(resp->error_msg = malloc(SCVP_ERR_MSG_MAX_SIZE)))
		goto end;
	len = SCVP_ERR_MSG_MAX_SIZE - 1;
	err = asn1_read_value(asn1, "responseStatus.errorMessage", resp->error_msg, &len);
	if (err == ASN1_SUCCESS)
		resp->error_msg[len] = 0;
	else {
		free(resp->error_msg);
		resp->error_msg = NULL;
	}

	if (!(cert_reply = cert_reply_alloc()))
		goto end;
	if (!(cert_reply->cert = cert_der_alloc()))
		goto end;
	if (!(cert_reply->cert->cert = malloc(SCVP_MSG_BLOCK_SIZE)))
		goto end;
	cert_reply->cert->cert_len = SCVP_MSG_BLOCK_SIZE;

	len = sizeof(str_tmp) - 1;
	err = asn1_read_value(asn1, "replyObjects.?1.replyChecks.?1.check", str_tmp, &len);
	ASN1_ERR(err);
	if (!(cert_reply->reply_checks = get_oid_flag_by_str(check_oid, sizeof(check_oid)/sizeof(check_oid[0]), str_tmp)))
		goto end;
	len = sizeof(str_tmp) - 1;
	err = asn1_read_value(asn1, "replyObjects.?1.replyValTime", str_tmp, &len);
	ASN1_ERR(err);
	cert_reply->reply_val_time = string_to_time(str_tmp);
	if (cert_reply->reply_val_time == -1)
		goto end;
	len = sizeof(str_tmp) - 1;
	err = asn1_read_value(asn1, "replyObjects.?1.validationErrors.?1", str_tmp, &len);
	if (!err)
		if (!(cert_reply->val_errors = get_oid_flag_by_str(alg_err_oid, sizeof(alg_err_oid)/sizeof(alg_err_oid[0]), str_tmp)))
			goto end;

	err = asn1_read_value(asn1, "replyObjects.?1.cert.cert", cert_reply->cert->cert, (int*)(&cert_reply->cert->cert_len));
	if (err != ASN1_SUCCESS) {
		if (err == ASN1_MEM_ERROR) {
			unsigned char *ptr;

			ptr = realloc(cert_reply->cert->cert, cert_reply->cert->cert_len);
			if (ptr == NULL)
				goto end;
			cert_reply->cert->cert = ptr;
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
	response_cli_free(resp);
	cert_reply_free(cert_reply);
	return NULL;
}
