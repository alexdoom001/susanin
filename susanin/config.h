#ifndef CONFIG_H
#define CONFIG_H

#define CRL_VALUES 0
#define OCSP_VALUES 1

#define CHECK_AVAILABLE     0x01
#define CHECK_ACCURATE      0x02
#define CHECK_PEER          0x04
#define CHECK_ALL           0x08
#define DISABLE_NONCE       0x10
#define UNDEFINED_VALUE     0x20

struct validation_values {
	char *value;
	unsigned int flag;
};

struct config_cert_ref {
	ASN1_INTEGER *serial;
	unsigned char hash[EVP_MAX_MD_SIZE];
	unsigned int hash_len;
	unsigned int crl_values;
	unsigned int ocsp_values;
};

struct config {
	int daemon;
	char *socket_path;
	char *pid_path;
	char *ca_path;
	char *crl_path;
	char *tmp_path;
	char *untrusted_path;
	unsigned int crl_values;
	unsigned int ocsp_values;
	GSList *config_cert_list;
};

int load_config(const char *conf_file)
	__attribute__((nonnull));
int get_cert_values(X509 *cert, int type)
	__attribute__((nonnull));

#endif /* CONFIG_H */
