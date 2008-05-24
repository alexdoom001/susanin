#ifndef PATH_TEST_H
#define PATH_TEST_H

struct test_table {
	const char *test_name;
	const char *cert_name;
	const char *anchor_name;
	int test_result;
};

struct test_policy_table {
	const char *test_name;
	const char *cert_name;
	int test_result;
	int user_poly_flags;
	const char *user_poly_set1;
	const char *user_poly_set2;
	const char *user_poly_set3;
};

#endif /* PATH_TEST_H */
