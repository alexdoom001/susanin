#ifndef SCVP_DEFS_H
#define SCVP_DEFS_H_

/* SCVP Check Identifiers */
#define BUILD_PKC_PATH                                      0x01
#define BUILD_VALID_PKC_PATH                                0x02
#define BUILD_STATUS_CHECKED_PKC_PATH                       0x04
#define BUILD_AA_PATH                                       0x08
#define BUILD_VALID_AA_PATH                                 0x10
#define BUILD_STATUS_CHECKED_AA_PATH                        0x20
#define STATUS_CHECK_AC_AND_BUILD_STATUS_CHECKED_AA_PATH    0x40

/* SCVP Basic Validation Algorithm Errors */
#define EXPIRED                                             0x01
#define NOT_YET_VALID                                       0x02
#define WRONG_TRUST_ANCHOR                                  0x04
#define NO_VALID_CERT_PATH                                  0x08
#define REVOKED                                             0x10
#define INVALID_KEY_PURPOSE                                 0x20
#define INVALID_KEY_USAGE                                   0x40
#define INVALID_CERT_POLICY                                 0x80

/* CVResponse CVStatusCode */
#define OKAY                                                0
#define SKIP_UNRECOGNIZED_ITEMS                             1
#define TOO_BUSY                                            10
#define INVALID_REQUEST                                     11
#define INTERNAL_ERROR                                      12
#define BAD_STRUCTURE                                       20
#define UNSUPPORTED_VERSION                                 21
#define ABORT_UNRECOGNIZED_ITEMS                            22
#define UNRECOGNIZED_SIG_KEY                                23
#define BAD_SIGNATURE_OR_MAC                                24
#define UNABLE_TO_DECODE                                    25
#define NOT_AUTHORIZED                                      26
#define UNSUPPORTED_CHECKS                                  27
#define UNSUPPORTED_WANT_BACKS                              28
#define UNSUPPORTED_SIGNATURE_OR_MAC                        29
#define INVALID_SIGNATURE_OR_MAC                            30
#define PROTECTED_RESPONSE_UNSUPPORTED                      31
#define UNRECOGNIZED_RESPONDER_NAME                         32
#define RELAYING_LOOP                                       40
#define UNRECOGNIZED_VAL_POL                                50
#define UNRECOGNIZED_VAL_ALG                                51
#define FULL_REQUEST_IN_RESPONSE_UNSUPPORTED                52
#define FULL_POL_RESPONSE_UNSUPPORTED                       53
#define INHIBIT_POLICY_MAPPING_UNSUPPORTED                  54
#define REQUIRE_EXPLICT_POLICY_UNSUPPORTED                  55
#define INHIBIT_ANY_POLICY_UNSUPPORTED                      56
#define VALIDATION_TIME_UNSUPPORTED                         57
#define UNRECOGNIZED_CRIT_QUERY_EXT                         63
#define UNRECOGNIZED_CRIT_REQUEST_EXT                       64

/* CertReply ReplyStatus */
#define SUCCESS                                             0
#define MALFORMED_PKC                                       1
#define MALFORMED_AC                                        2
#define UNAVAILABLE_VALIDATION_TIME                         3
#define REFERENCE_CERT_HASH_FAIL                            4
#define CERT_PATH_CONSTRUCT_FAIL                            5
#define CERT_PATH_NOT_VALID                                 6
#define CERT_PATH_NOT_VALID_NOW                             7
#define WANT_BACK_UNSATISFIED                               9

/* Hash Algorithms */
#define HASH_ALG_SHA1                                       1

/* Validation Policies */
#define VAL_POLY_DEFAULT                                    1

#define SCVP_POLY_INHIBIT_MAP                               0x01
#define SCVP_POLY_EXPLICIT_POLICY                           0x02
#define SCVP_POLY_INHIBIT_ANY                               0x04

#define SCVP_HASH_MAX_SIZE 64
#define X509_SERIAL_NUMBER_MAX_SIZE 20 /* According to RFC 5280 4.1.2.2. */

struct oid_table {
	char str[32];
	unsigned int flag;
};

struct scvp_cert_der {
	unsigned char *cert;
	unsigned int cert_len;
};

struct scvp_cert_ref {
	unsigned char serial[X509_SERIAL_NUMBER_MAX_SIZE];
	unsigned int serial_len;
	unsigned char hash[SCVP_HASH_MAX_SIZE];
	unsigned int hash_len;
	unsigned int hash_alg;
};

struct scvp_request {
	GSList *queried_certs;
	GSList *trust_anchors;
	GSList *inter_certs;
	unsigned int checks;
	unsigned int val_poly;
	GSList *user_poly_set;
	int user_poly_flags;
};

struct scvp_cert_reply {
	struct scvp_cert_der *cert;
	unsigned int reply_status;
	time_t reply_val_time;
	unsigned int reply_checks;
	unsigned int val_errors;
};

struct scvp_response {
	time_t produced_at;
	unsigned int response_status;
	unsigned int val_poly;
	GSList *cert_reply;
};

struct scvp_cert_der *cert_der_alloc(void);
void cert_der_free(struct scvp_cert_der *cert);
struct scvp_cert_ref *cert_ref_alloc(void);
void cert_ref_free(struct scvp_cert_ref *cert);
struct scvp_request *request_alloc(void);
void request_free(struct scvp_request *rqst);
struct scvp_cert_reply *cert_reply_alloc(void);
void cert_reply_free(struct scvp_cert_reply *cert_reply);
struct scvp_response *response_alloc(void);
void response_free(struct scvp_response *resp);

#endif /* SCVP_DEFS_H */
