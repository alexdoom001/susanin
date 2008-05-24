const char anyPolicy[] = "2.5.29.32.0";
const char NIST_test_policy_1[] = "2.16.840.1.101.3.2.1.48.1";
const char NIST_test_policy_2[] = "2.16.840.1.101.3.2.1.48.2";
const char NIST_test_policy_3[] = "2.16.840.1.101.3.2.1.48.3";
const char NIST_test_policy_4[] = "2.16.840.1.101.3.2.1.48.4";
const char NIST_test_policy_5[] = "2.16.840.1.101.3.2.1.48.5";
const char NIST_test_policy_6[] = "2.16.840.1.101.3.2.1.48.6";

const struct test_table signature_verify[] = {
	{"4.1.1", "ValidCertificatePathTest1EE", NULL, SCVP_CLI_CERT_OK},
	{"4.1.2", "InvalidCASignatureTest2EE", NULL, SCVP_CLI_ERR_BAD_CERT},
	{"4.1.3", "InvalidEESignatureTest3EE", NULL, SCVP_CLI_ERR_BAD_CERT},
	{"4.1.4", "ValidDSASignaturesTest4EE", NULL, SCVP_CLI_CERT_OK},
	{"4.1.5", "ValidDSAParameterInheritanceTest5EE", NULL, SCVP_CLI_CERT_OK},
	{"4.1.6", "InvalidDSASignatureTest6EE", NULL, SCVP_CLI_ERR_BAD_CERT}
};

const struct test_table validity_periods[] = {
	{"4.2.1", "InvalidCAnotBeforeDateTest1EE", "TrustAnchorRootCertificate", SCVP_CLI_ERR_BAD_CERT},
	{"4.2.2", "InvalidEEnotBeforeDateTest2EE", "TrustAnchorRootCertificate", SCVP_CLI_ERR_BAD_CERT},
	{"4.2.3", "Validpre2000UTCnotBeforeDateTest3EE", "TrustAnchorRootCertificate", SCVP_CLI_CERT_OK},
	{"4.2.4", "ValidGeneralizedTimenotBeforeDateTest4EE", "TrustAnchorRootCertificate", SCVP_CLI_CERT_OK},
	{"4.2.5", "InvalidCAnotAfterDateTest5EE", "TrustAnchorRootCertificate", SCVP_CLI_ERR_BAD_CERT},
	{"4.2.6", "InvalidEEnotAfterDateTest6EE", "TrustAnchorRootCertificate", SCVP_CLI_ERR_BAD_CERT},
	{"4.2.7", "Invalidpre2000UTCEEnotAfterDateTest7EE", "TrustAnchorRootCertificate", SCVP_CLI_ERR_BAD_CERT},
	{"4.2.8", "ValidGeneralizedTimenotAfterDateTest8EE", "TrustAnchorRootCertificate", SCVP_CLI_CERT_OK}
};

const struct test_table name_chaining[] = {
	{"4.3.1", "InvalidNameChainingTest1EE", "TrustAnchorRootCertificate", SCVP_CLI_ERR_BAD_CERT},
	{"4.3.2", "InvalidNameChainingOrderTest2EE", "TrustAnchorRootCertificate", SCVP_CLI_ERR_BAD_CERT},
	{"4.3.3", "ValidNameChainingWhitespaceTest3EE", "TrustAnchorRootCertificate", SCVP_CLI_CERT_OK},
	{"4.3.4", "ValidNameChainingWhitespaceTest4EE", "TrustAnchorRootCertificate", SCVP_CLI_CERT_OK},
	{"4.3.5", "ValidNameChainingCapitalizationTest5EE", "TrustAnchorRootCertificate", SCVP_CLI_CERT_OK},
	{"4.3.6", "ValidNameUIDsTest6EE", "TrustAnchorRootCertificate", SCVP_CLI_CERT_OK},
	{"4.3.7", "ValidRFC3280MandatoryAttributeTypesTest7EE", "TrustAnchorRootCertificate", SCVP_CLI_CERT_OK},
	{"4.3.8", "ValidRFC3280OptionalAttributeTypesTest8EE", "TrustAnchorRootCertificate", SCVP_CLI_CERT_OK},
	{"4.3.9", "ValidUTF8StringEncodedNamesTest9EE", "TrustAnchorRootCertificate", SCVP_CLI_CERT_OK},
	{"4.3.10", "ValidRolloverfromPrintableStringtoUTF8StringTest10EE", "TrustAnchorRootCertificate", SCVP_CLI_CERT_OK},
	{"4.3.11", "ValidUTF8StringCaseInsensitiveMatchTest11EE", "TrustAnchorRootCertificate", SCVP_CLI_CERT_OK}
};

const struct test_table revocation_tests[] = {
	{"4.4.1", "InvalidMissingCRLTest1EE", "TrustAnchorRootCertificate", SCVP_CLI_ERR_BAD_CERT},
	{"4.4.2", "InvalidRevokedCATest2EE", "TrustAnchorRootCertificate", SCVP_CLI_ERR_BAD_CERT},
	{"4.4.3", "InvalidRevokedEETest3EE", "TrustAnchorRootCertificate", SCVP_CLI_ERR_BAD_CERT},
	{"4.4.4", "InvalidBadCRLSignatureTest4EE", "TrustAnchorRootCertificate", SCVP_CLI_ERR_BAD_CERT},
	{"4.4.5", "InvalidBadCRLIssuerNameTest5EE", "TrustAnchorRootCertificate", SCVP_CLI_ERR_BAD_CERT},
	{"4.4.6", "InvalidWrongCRLTest6EE", "TrustAnchorRootCertificate", SCVP_CLI_ERR_BAD_CERT},
	{"4.4.7", "ValidTwoCRLsTest7EE", "TrustAnchorRootCertificate", SCVP_CLI_CERT_OK},
	{"4.4.8", "InvalidUnknownCRLEntryExtensionTest8EE", "TrustAnchorRootCertificate", SCVP_CLI_ERR_BAD_CERT},
	{"4.4.9", "InvalidUnknownCRLExtensionTest9EE", "TrustAnchorRootCertificate", SCVP_CLI_ERR_BAD_CERT},
	{"4.4.10", "InvalidUnknownCRLExtensionTest10EE", "TrustAnchorRootCertificate", SCVP_CLI_ERR_BAD_CERT},
	{"4.4.11", "InvalidOldCRLnextUpdateTest11EE", "TrustAnchorRootCertificate", SCVP_CLI_ERR_BAD_CERT},
	{"4.4.12", "Invalidpre2000CRLnextUpdateTest12EE", "TrustAnchorRootCertificate", SCVP_CLI_ERR_BAD_CERT},
	{"4.4.13", "ValidGeneralizedTimeCRLnextUpdateTest13EE", "TrustAnchorRootCertificate", SCVP_CLI_CERT_OK},
	{"4.4.14", "ValidNegativeSerialNumberTest14EE", "TrustAnchorRootCertificate", SCVP_CLI_CERT_OK},
	/* Non-conforming negative serial is detected on request creation */
	{"4.4.15", "InvalidNegativeSerialNumberTest15EE", "TrustAnchorRootCertificate", SCVP_CLI_ERR_BAD_RQST},
	{"4.4.16", "ValidLongSerialNumberTest16EE", "TrustAnchorRootCertificate", SCVP_CLI_CERT_OK},
	{"4.4.17", "ValidLongSerialNumberTest17EE", "TrustAnchorRootCertificate", SCVP_CLI_CERT_OK},
	{"4.4.18", "InvalidLongSerialNumberTest18EE", "TrustAnchorRootCertificate", SCVP_CLI_ERR_BAD_CERT},
	{"4.4.19", "ValidSeparateCertificateandCRLKeysTest19EE", "TrustAnchorRootCertificate", SCVP_CLI_CERT_OK},
	{"4.4.20", "InvalidSeparateCertificateandCRLKeysTest20EE", "TrustAnchorRootCertificate", SCVP_CLI_ERR_BAD_CERT},
	{"4.4.21", "InvalidSeparateCertificateandCRLKeysTest21EE", "TrustAnchorRootCertificate", SCVP_CLI_ERR_BAD_CERT}
};

const struct test_table verifying_paths[] = {
	{"4.5.1", "ValidBasicSelfIssuedOldWithNewTest1EE", "TrustAnchorRootCertificate", SCVP_CLI_CERT_OK},
	{"4.5.2", "InvalidBasicSelfIssuedOldWithNewTest2EE", "TrustAnchorRootCertificate", SCVP_CLI_ERR_BAD_CERT},
	{"4.5.3", "ValidBasicSelfIssuedNewWithOldTest3EE", "TrustAnchorRootCertificate", SCVP_CLI_CERT_OK},
	{"4.5.4", "ValidBasicSelfIssuedNewWithOldTest4EE", "TrustAnchorRootCertificate", SCVP_CLI_CERT_OK},
	{"4.5.5", "InvalidBasicSelfIssuedNewWithOldTest5EE", "TrustAnchorRootCertificate", SCVP_CLI_ERR_BAD_CERT},
	{"4.5.6", "ValidBasicSelfIssuedCRLSigningKeyTest6EE", "TrustAnchorRootCertificate", SCVP_CLI_CERT_OK},
	{"4.5.7", "InvalidBasicSelfIssuedCRLSigningKeyTest7EE", "TrustAnchorRootCertificate", SCVP_CLI_ERR_BAD_CERT},
	{"4.5.8", "InvalidBasicSelfIssuedCRLSigningKeyTest8EE", "TrustAnchorRootCertificate", SCVP_CLI_ERR_BAD_CERT}
};

const struct test_table basic_constraints[] = {
	{"4.6.1", "InvalidMissingbasicConstraintsTest1EE", "TrustAnchorRootCertificate", SCVP_CLI_ERR_BAD_CERT},
	{"4.6.2", "InvalidcAFalseTest2EE", "TrustAnchorRootCertificate", SCVP_CLI_ERR_BAD_CERT},
	{"4.6.3", "InvalidcAFalseTest3EE", "TrustAnchorRootCertificate", SCVP_CLI_ERR_BAD_CERT},
	{"4.6.4", "ValidbasicConstraintsNotCriticalTest4EE", "TrustAnchorRootCertificate", SCVP_CLI_CERT_OK},
	{"4.6.5", "InvalidpathLenConstraintTest5EE", "TrustAnchorRootCertificate", SCVP_CLI_ERR_BAD_CERT},
	{"4.6.6", "InvalidpathLenConstraintTest6EE", "TrustAnchorRootCertificate", SCVP_CLI_ERR_BAD_CERT},
	{"4.6.7", "ValidpathLenConstraintTest7EE", "TrustAnchorRootCertificate", SCVP_CLI_CERT_OK},
	{"4.6.8", "ValidpathLenConstraintTest8EE", "TrustAnchorRootCertificate", SCVP_CLI_CERT_OK},
	{"4.6.9", "InvalidpathLenConstraintTest9EE", "TrustAnchorRootCertificate", SCVP_CLI_ERR_BAD_CERT},
	{"4.6.10", "InvalidpathLenConstraintTest10EE", "TrustAnchorRootCertificate", SCVP_CLI_ERR_BAD_CERT},
	{"4.6.11", "InvalidpathLenConstraintTest11EE", "TrustAnchorRootCertificate", SCVP_CLI_ERR_BAD_CERT},
	{"4.6.12", "InvalidpathLenConstraintTest12EE", "TrustAnchorRootCertificate", SCVP_CLI_ERR_BAD_CERT},
	{"4.6.13", "ValidpathLenConstraintTest13EE", "TrustAnchorRootCertificate", SCVP_CLI_CERT_OK},
	{"4.6.14", "ValidpathLenConstraintTest14EE", "TrustAnchorRootCertificate", SCVP_CLI_CERT_OK},
	{"4.6.15", "ValidSelfIssuedpathLenConstraintTest15EE", "TrustAnchorRootCertificate", SCVP_CLI_CERT_OK},
	{"4.6.16", "InvalidSelfIssuedpathLenConstraintTest16EE", "TrustAnchorRootCertificate", SCVP_CLI_ERR_BAD_CERT},
	{"4.6.17", "ValidSelfIssuedpathLenConstraintTest17EE", "TrustAnchorRootCertificate", SCVP_CLI_CERT_OK}
};

const struct test_table key_usage[] = {
	{"4.7.1", "InvalidkeyUsageCriticalkeyCertSignFalseTest1EE", "TrustAnchorRootCertificate", SCVP_CLI_ERR_BAD_CERT},
	{"4.7.2", "InvalidkeyUsageNotCriticalkeyCertSignFalseTest2EE", "TrustAnchorRootCertificate", SCVP_CLI_ERR_BAD_CERT},
	{"4.7.3", "ValidkeyUsageNotCriticalTest3EE", "TrustAnchorRootCertificate", SCVP_CLI_CERT_OK},
	{"4.7.4", "InvalidkeyUsageCriticalcRLSignFalseTest4EE", "TrustAnchorRootCertificate", SCVP_CLI_ERR_BAD_CERT},
	{"4.7.6", "InvalidkeyUsageNotCriticalcRLSignFalseTest5EE", "TrustAnchorRootCertificate", SCVP_CLI_ERR_BAD_CERT}
};

const struct test_table name_constraints[] = {
	{"4.13.1", "ValidDNnameConstraintsTest1EE", "TrustAnchorRootCertificate", SCVP_CLI_CERT_OK},
	{"4.13.2", "InvalidDNnameConstraintsTest2EE", "TrustAnchorRootCertificate", SCVP_CLI_ERR_BAD_CERT},
	{"4.13.3", "InvalidDNnameConstraintsTest3EE", "TrustAnchorRootCertificate", SCVP_CLI_ERR_BAD_CERT},
	{"4.13.4", "ValidDNnameConstraintsTest4EE", "TrustAnchorRootCertificate", SCVP_CLI_CERT_OK},
	{"4.13.5", "ValidDNnameConstraintsTest5EE", "TrustAnchorRootCertificate", SCVP_CLI_CERT_OK},
	{"4.13.6", "ValidDNnameConstraintsTest6EE", "TrustAnchorRootCertificate", SCVP_CLI_CERT_OK},
	{"4.13.7", "InvalidDNnameConstraintsTest7EE", "TrustAnchorRootCertificate", SCVP_CLI_ERR_BAD_CERT},
	{"4.13.8", "InvalidDNnameConstraintsTest8EE", "TrustAnchorRootCertificate", SCVP_CLI_ERR_BAD_CERT},
	{"4.13.9", "InvalidDNnameConstraintsTest9EE", "TrustAnchorRootCertificate", SCVP_CLI_ERR_BAD_CERT},
	{"4.13.10", "InvalidDNnameConstraintsTest10EE", "TrustAnchorRootCertificate", SCVP_CLI_ERR_BAD_CERT},
	{"4.13.11", "ValidDNnameConstraintsTest11EE", "TrustAnchorRootCertificate", SCVP_CLI_CERT_OK},
	{"4.13.12", "InvalidDNnameConstraintsTest12EE", "TrustAnchorRootCertificate", SCVP_CLI_ERR_BAD_CERT},
	{"4.13.13", "InvalidDNnameConstraintsTest13EE", "TrustAnchorRootCertificate", SCVP_CLI_ERR_BAD_CERT},
	{"4.13.14", "ValidDNnameConstraintsTest14EE", "TrustAnchorRootCertificate", SCVP_CLI_CERT_OK},
	{"4.13.15", "InvalidDNnameConstraintsTest15EE", "TrustAnchorRootCertificate", SCVP_CLI_ERR_BAD_CERT},
	{"4.13.16", "InvalidDNnameConstraintsTest16EE", "TrustAnchorRootCertificate", SCVP_CLI_ERR_BAD_CERT},
	{"4.13.17", "InvalidDNnameConstraintsTest17EE", "TrustAnchorRootCertificate", SCVP_CLI_ERR_BAD_CERT},
	{"4.13.18", "ValidDNnameConstraintsTest18EE", "TrustAnchorRootCertificate", SCVP_CLI_CERT_OK},
	{"4.13.19", "ValidDNnameConstraintsTest19EE", "TrustAnchorRootCertificate", SCVP_CLI_CERT_OK},
	{"4.13.20", "InvalidDNnameConstraintsTest20EE", "TrustAnchorRootCertificate", SCVP_CLI_ERR_BAD_CERT},
	{"4.13.21", "ValidRFC822nameConstraintsTest21EE", "TrustAnchorRootCertificate", SCVP_CLI_CERT_OK},
	{"4.13.22", "InvalidRFC822nameConstraintsTest22EE", "TrustAnchorRootCertificate", SCVP_CLI_ERR_BAD_CERT},
	{"4.13.23", "ValidRFC822nameConstraintsTest23EE", "TrustAnchorRootCertificate", SCVP_CLI_CERT_OK},
	{"4.13.24", "InvalidRFC822nameConstraintsTest24EE", "TrustAnchorRootCertificate", SCVP_CLI_ERR_BAD_CERT},
	{"4.13.25", "ValidRFC822nameConstraintsTest25EE", "TrustAnchorRootCertificate", SCVP_CLI_CERT_OK},
	{"4.13.26", "InvalidRFC822nameConstraintsTest26EE", "TrustAnchorRootCertificate", SCVP_CLI_ERR_BAD_CERT},
	{"4.13.27", "ValidDNandRFC822nameConstraintsTest27EE", "TrustAnchorRootCertificate", SCVP_CLI_CERT_OK},
	{"4.13.28", "InvalidDNandRFC822nameConstraintsTest28EE", "TrustAnchorRootCertificate", SCVP_CLI_ERR_BAD_CERT},
	{"4.13.29", "InvalidDNandRFC822nameConstraintsTest29EE", "TrustAnchorRootCertificate", SCVP_CLI_ERR_BAD_CERT},
	{"4.13.30", "ValidDNSnameConstraintsTest30EE", "TrustAnchorRootCertificate", SCVP_CLI_CERT_OK},
	{"4.13.31", "InvalidDNSnameConstraintsTest31EE", "TrustAnchorRootCertificate", SCVP_CLI_ERR_BAD_CERT},
	{"4.13.32", "ValidDNSnameConstraintsTest32EE", "TrustAnchorRootCertificate", SCVP_CLI_CERT_OK},
	{"4.13.33", "InvalidDNSnameConstraintsTest33EE", "TrustAnchorRootCertificate", SCVP_CLI_ERR_BAD_CERT},
	{"4.13.34", "ValidURInameConstraintsTest34EE", "TrustAnchorRootCertificate", SCVP_CLI_CERT_OK},
	{"4.13.35", "InvalidURInameConstraintsTest35EE", "TrustAnchorRootCertificate", SCVP_CLI_ERR_BAD_CERT},
	{"4.13.36", "ValidURInameConstraintsTest36EE", "TrustAnchorRootCertificate", SCVP_CLI_CERT_OK},
	{"4.13.37", "InvalidURInameConstraintsTest37EE", "TrustAnchorRootCertificate", SCVP_CLI_ERR_BAD_CERT},
	{"4.13.38", "InvalidDNSnameConstraintsTest38EE", "TrustAnchorRootCertificate", SCVP_CLI_ERR_BAD_CERT}
};

const struct test_table distribution_points[] = {
	{"4.14.1", "ValiddistributionPointTest1EE", "TrustAnchorRootCertificate", SCVP_CLI_CERT_OK},
	{"4.14.2", "InvaliddistributionPointTest2EE", "TrustAnchorRootCertificate", SCVP_CLI_ERR_BAD_CERT},
	{"4.14.3", "InvaliddistributionPointTest3EE", "TrustAnchorRootCertificate", SCVP_CLI_ERR_BAD_CERT},
	{"4.14.4", "ValiddistributionPointTest4EE", "TrustAnchorRootCertificate", SCVP_CLI_CERT_OK},
	{"4.14.5", "ValiddistributionPointTest5EE", "TrustAnchorRootCertificate", SCVP_CLI_CERT_OK},
	{"4.14.6", "InvaliddistributionPointTest6EE", "TrustAnchorRootCertificate", SCVP_CLI_ERR_BAD_CERT},
	{"4.14.7", "ValiddistributionPointTest7EE", "TrustAnchorRootCertificate", SCVP_CLI_CERT_OK},
	{"4.14.8", "InvaliddistributionPointTest8EE", "TrustAnchorRootCertificate", SCVP_CLI_ERR_BAD_CERT},
	{"4.14.9", "InvaliddistributionPointTest9EE", "TrustAnchorRootCertificate", SCVP_CLI_ERR_BAD_CERT},
	{"4.14.10", "ValidNoissuingDistributionPointTest10EE", "TrustAnchorRootCertificate", SCVP_CLI_CERT_OK},
	{"4.14.11", "InvalidonlyContainsUserCertsTest11EE", "TrustAnchorRootCertificate", SCVP_CLI_ERR_BAD_CERT},
	{"4.14.12", "InvalidonlyContainsCACertsTest12EE", "TrustAnchorRootCertificate", SCVP_CLI_ERR_BAD_CERT},
	{"4.14.13", "ValidonlyContainsCACertsTest13EE", "TrustAnchorRootCertificate", SCVP_CLI_CERT_OK},
	{"4.14.14", "InvalidonlyContainsAttributeCertsTest14EE", "TrustAnchorRootCertificate", SCVP_CLI_ERR_BAD_CERT},
	{"4.14.15", "InvalidonlySomeReasonsTest15EE", "TrustAnchorRootCertificate", SCVP_CLI_ERR_BAD_CERT},
	{"4.14.16", "InvalidonlySomeReasonsTest16EE", "TrustAnchorRootCertificate", SCVP_CLI_ERR_BAD_CERT},
	{"4.14.17", "InvalidonlySomeReasonsTest17EE", "TrustAnchorRootCertificate", SCVP_CLI_ERR_BAD_CERT},
	{"4.14.18", "ValidonlySomeReasonsTest18EE", "TrustAnchorRootCertificate", SCVP_CLI_CERT_OK},
	{"4.14.19", "ValidonlySomeReasonsTest19EE", "TrustAnchorRootCertificate", SCVP_CLI_CERT_OK},
	{"4.14.20", "InvalidonlySomeReasonsTest20EE", "TrustAnchorRootCertificate", SCVP_CLI_ERR_BAD_CERT},
	{"4.14.21", "InvalidonlySomeReasonsTest21EE", "TrustAnchorRootCertificate", SCVP_CLI_ERR_BAD_CERT},
	{"4.14.22", "ValidIDPwithindirectCRLTest22EE", "TrustAnchorRootCertificate", SCVP_CLI_CERT_OK},
	{"4.14.23", "InvalidIDPwithindirectCRLTest23EE", "TrustAnchorRootCertificate", SCVP_CLI_ERR_BAD_CERT},
	{"4.14.24", "ValidIDPwithindirectCRLTest24EE", "TrustAnchorRootCertificate", SCVP_CLI_CERT_OK},
	{"4.14.25", "ValidIDPwithindirectCRLTest25EE", "TrustAnchorRootCertificate", SCVP_CLI_CERT_OK},
	{"4.14.26", "InvalidIDPwithindirectCRLTest26EE", "TrustAnchorRootCertificate", SCVP_CLI_ERR_BAD_CERT},
	{"4.14.27", "InvalidcRLIssuerTest27EE", "TrustAnchorRootCertificate", SCVP_CLI_ERR_BAD_CERT},
	{"4.14.28", "ValidcRLIssuerTest28EE", "TrustAnchorRootCertificate", SCVP_CLI_CERT_OK},
	{"4.14.29", "ValidcRLIssuerTest29EE", "TrustAnchorRootCertificate", SCVP_CLI_CERT_OK},
	{"4.14.30", "ValidcRLIssuerTest30EE", "TrustAnchorRootCertificate", SCVP_CLI_CERT_OK},
	{"4.14.31", "InvalidcRLIssuerTest31EE", "TrustAnchorRootCertificate", SCVP_CLI_ERR_BAD_CERT},
	{"4.14.32", "InvalidcRLIssuerTest32EE", "TrustAnchorRootCertificate", SCVP_CLI_ERR_BAD_CERT},
	{"4.14.33", "ValidcRLIssuerTest33EE", "TrustAnchorRootCertificate", SCVP_CLI_CERT_OK},
	{"4.14.34", "InvalidcRLIssuerTest34EE", "TrustAnchorRootCertificate", SCVP_CLI_ERR_BAD_CERT},
	{"4.14.35", "InvalidcRLIssuerTest35EE", "TrustAnchorRootCertificate", SCVP_CLI_ERR_BAD_CERT}
};

const struct test_table delta_crls[] = {
	{"4.15.1", "InvaliddeltaCRLIndicatorNoBaseTest1EE", "TrustAnchorRootCertificate", SCVP_CLI_ERR_BAD_CERT},
	{"4.15.2", "ValiddeltaCRLTest2EE", "TrustAnchorRootCertificate", SCVP_CLI_CERT_OK},
	{"4.15.3", "InvaliddeltaCRLTest3EE", "TrustAnchorRootCertificate", SCVP_CLI_ERR_BAD_CERT},
	{"4.15.4", "InvaliddeltaCRLTest4EE", "TrustAnchorRootCertificate", SCVP_CLI_ERR_BAD_CERT},
	{"4.15.5", "ValiddeltaCRLTest5EE", "TrustAnchorRootCertificate", SCVP_CLI_CERT_OK},
	{"4.15.6", "InvaliddeltaCRLTest6EE", "TrustAnchorRootCertificate", SCVP_CLI_ERR_BAD_CERT},
	{"4.15.7", "ValiddeltaCRLTest7EE", "TrustAnchorRootCertificate", SCVP_CLI_CERT_OK},
	{"4.15.8", "ValiddeltaCRLTest8EE", "TrustAnchorRootCertificate", SCVP_CLI_CERT_OK},
	{"4.15.9", "InvaliddeltaCRLTest9EE", "TrustAnchorRootCertificate", SCVP_CLI_ERR_BAD_CERT},
	{"4.15.10", "InvaliddeltaCRLTest10EE", "TrustAnchorRootCertificate", SCVP_CLI_ERR_BAD_CERT}
};

const struct test_table private_extensions[] = {
	{"4.16.1", "ValidUnknownNotCriticalCertificateExtensionTest1EE", "TrustAnchorRootCertificate", SCVP_CLI_CERT_OK},
	{"4.16.2", "InvalidUnknownCriticalCertificateExtensionTest2EE", "TrustAnchorRootCertificate", SCVP_CLI_ERR_BAD_CERT}
};

const struct test_policy_table certificate_policies[] = {
	{"4.8.1.1", "ValidCertificatePathTest1EE", SCVP_CLI_CERT_OK, SCVP_POLY_EXPLICIT_POLICY, anyPolicy},
	{"4.8.1.2", "ValidCertificatePathTest1EE", SCVP_CLI_CERT_OK, SCVP_POLY_EXPLICIT_POLICY, NIST_test_policy_1},
	{"4.8.1.3", "ValidCertificatePathTest1EE", SCVP_CLI_ERR_BAD_CERT, SCVP_POLY_EXPLICIT_POLICY, NIST_test_policy_2},
	{"4.8.1.4", "ValidCertificatePathTest1EE", SCVP_CLI_CERT_OK, SCVP_POLY_EXPLICIT_POLICY, NIST_test_policy_1, NIST_test_policy_2},
	{"4.8.2.1", "AllCertificatesNoPoliciesTest2EE", SCVP_CLI_CERT_OK, 0},
	{"4.8.2.2", "AllCertificatesNoPoliciesTest2EE", SCVP_CLI_ERR_BAD_CERT, SCVP_POLY_EXPLICIT_POLICY},
	{"4.8.3.1", "DifferentPoliciesTest3EE", SCVP_CLI_CERT_OK, 0, anyPolicy},
	{"4.8.3.2", "DifferentPoliciesTest3EE", SCVP_CLI_ERR_BAD_CERT, SCVP_POLY_EXPLICIT_POLICY},
	{"4.8.3.3", "DifferentPoliciesTest3EE", SCVP_CLI_ERR_BAD_CERT, SCVP_POLY_EXPLICIT_POLICY, NIST_test_policy_1, NIST_test_policy_2},
	{"4.8.4", "DifferentPoliciesTest4EE", SCVP_CLI_ERR_BAD_CERT, 0},
	{"4.8.5", "DifferentPoliciesTest5EE", SCVP_CLI_ERR_BAD_CERT, 0},
	{"4.8.6.1", "OverlappingPoliciesTest6EE", SCVP_CLI_CERT_OK, 0},
	{"4.8.6.2", "OverlappingPoliciesTest6EE", SCVP_CLI_CERT_OK, 0, NIST_test_policy_1},
	{"4.8.6.3", "OverlappingPoliciesTest6EE", SCVP_CLI_ERR_BAD_CERT, 0, NIST_test_policy_2},
	{"4.8.7", "DifferentPoliciesTest7EE", SCVP_CLI_ERR_BAD_CERT, 0},
	{"4.8.8", "DifferentPoliciesTest8EE", SCVP_CLI_ERR_BAD_CERT, 0},
	{"4.8.9", "DifferentPoliciesTest9EE", SCVP_CLI_ERR_BAD_CERT, 0},
	{"4.8.10.1", "AllCertificatesSamePoliciesTest10EE", SCVP_CLI_CERT_OK, 0},
	{"4.8.10.2", "AllCertificatesSamePoliciesTest10EE", SCVP_CLI_CERT_OK, 0, NIST_test_policy_1},
	{"4.8.10.3", "AllCertificatesSamePoliciesTest10EE", SCVP_CLI_CERT_OK, 0, NIST_test_policy_2},
	{"4.8.11.1", "AllCertificatesanyPolicyTest11EE", SCVP_CLI_CERT_OK, 0},
	{"4.8.11.2", "AllCertificatesanyPolicyTest11EE", SCVP_CLI_CERT_OK, 0, NIST_test_policy_1},
	{"4.8.12", "DifferentPoliciesTest12EE", SCVP_CLI_ERR_BAD_CERT, 0},
	{"4.8.13.1", "AllCertificatesSamePoliciesTest13EE", SCVP_CLI_CERT_OK, 0, NIST_test_policy_1},
	{"4.8.13.2", "AllCertificatesSamePoliciesTest13EE", SCVP_CLI_CERT_OK, 0, NIST_test_policy_2},
	{"4.8.13.3", "AllCertificatesSamePoliciesTest13EE", SCVP_CLI_CERT_OK, 0, NIST_test_policy_3},
	{"4.8.14.1", "AnyPolicyTest14EE", SCVP_CLI_CERT_OK, 0, NIST_test_policy_1},
	{"4.8.14.2", "AnyPolicyTest14EE", SCVP_CLI_ERR_BAD_CERT, 0, NIST_test_policy_2},
	{"4.8.15", "UserNoticeQualifierTest15EE", SCVP_CLI_CERT_OK, 0},
	{"4.8.16", "UserNoticeQualifierTest16EE", SCVP_CLI_CERT_OK, 0},
	{"4.8.17", "UserNoticeQualifierTest17EE", SCVP_CLI_CERT_OK, 0},
	{"4.8.18.1", "UserNoticeQualifierTest18EE", SCVP_CLI_CERT_OK, 0, NIST_test_policy_1},
	{"4.8.18.2", "UserNoticeQualifierTest18EE", SCVP_CLI_CERT_OK, 0, NIST_test_policy_2},
	{"4.8.19", "UserNoticeQualifierTest19EE", SCVP_CLI_CERT_OK, 0},
	{"4.8.20", "CPSPointerQualifierTest20EE", SCVP_CLI_CERT_OK, 0},
};

const struct test_policy_table explicit_policy[] = {
	{"4.9.1", "ValidrequireExplicitPolicyTest1EE", SCVP_CLI_CERT_OK, 0, anyPolicy},
	{"4.9.2", "ValidrequireExplicitPolicyTest2EE", SCVP_CLI_CERT_OK, 0, anyPolicy},
	{"4.9.3", "InvalidrequireExplicitPolicyTest3EE", SCVP_CLI_ERR_BAD_CERT, 0, anyPolicy},
	{"4.9.4", "ValidrequireExplicitPolicyTest4EE", SCVP_CLI_CERT_OK, 0, anyPolicy},
	{"4.9.5", "InvalidrequireExplicitPolicyTest5EE", SCVP_CLI_ERR_BAD_CERT, 0, anyPolicy},
	{"4.9.6", "ValidSelfIssuedrequireExplicitPolicyTest6EE", SCVP_CLI_CERT_OK, 0, anyPolicy},
	{"4.9.7", "InvalidSelfIssuedrequireExplicitPolicyTest7EE", SCVP_CLI_ERR_BAD_CERT, 0, anyPolicy},
	{"4.9.8", "InvalidSelfIssuedrequireExplicitPolicyTest8EE", SCVP_CLI_ERR_BAD_CERT, 0, anyPolicy},
};

const struct test_policy_table policy_mappings[] = {
	{"4.10.1.1", "ValidPolicyMappingTest1EE", SCVP_CLI_CERT_OK, 0, NIST_test_policy_1},
	{"4.10.1.2", "ValidPolicyMappingTest1EE", SCVP_CLI_ERR_BAD_CERT, 0, NIST_test_policy_2},
	{"4.10.1.3", "ValidPolicyMappingTest1EE", SCVP_CLI_ERR_BAD_CERT, SCVP_POLY_INHIBIT_MAP, anyPolicy},
	{"4.10.2.1", "InvalidPolicyMappingTest2EE", SCVP_CLI_ERR_BAD_CERT, 0, anyPolicy},
	{"4.10.2.2", "InvalidPolicyMappingTest2EE", SCVP_CLI_ERR_BAD_CERT, SCVP_POLY_INHIBIT_MAP, anyPolicy},
	{"4.10.3.1", "ValidPolicyMappingTest3EE", SCVP_CLI_ERR_BAD_CERT, 0, NIST_test_policy_1},
	{"4.10.3.2", "ValidPolicyMappingTest3EE", SCVP_CLI_CERT_OK, 0, NIST_test_policy_2},
	{"4.10.4", "InvalidPolicyMappingTest4EE", SCVP_CLI_ERR_BAD_CERT, 0, anyPolicy},
	{"4.10.5.1", "ValidPolicyMappingTest5EE", SCVP_CLI_CERT_OK, 0, NIST_test_policy_1},
	{"4.10.5.2", "ValidPolicyMappingTest5EE", SCVP_CLI_ERR_BAD_CERT, 0, NIST_test_policy_6},
	{"4.10.6.1", "ValidPolicyMappingTest6EE", SCVP_CLI_CERT_OK, 0, NIST_test_policy_1},
	{"4.10.6.2", "ValidPolicyMappingTest6EE", SCVP_CLI_ERR_BAD_CERT, 0, NIST_test_policy_6},
	{"4.10.7", "InvalidMappingFromanyPolicyTest7EE", SCVP_CLI_ERR_BAD_CERT, 0},
	{"4.10.8", "InvalidMappingToanyPolicyTest8EE", SCVP_CLI_ERR_BAD_CERT, 0},
	{"4.10.9", "ValidPolicyMappingTest9EE", SCVP_CLI_CERT_OK, 0, anyPolicy},
	{"4.10.10", "InvalidPolicyMappingTest10EE", SCVP_CLI_ERR_BAD_CERT, 0, anyPolicy},
	{"4.10.11", "ValidPolicyMappingTest11EE", SCVP_CLI_CERT_OK, 0, anyPolicy},
	{"4.10.12.1", "ValidPolicyMappingTest12EE", SCVP_CLI_CERT_OK, 0, NIST_test_policy_1},
	{"4.10.12.2", "ValidPolicyMappingTest12EE", SCVP_CLI_CERT_OK, 0, NIST_test_policy_2},
	{"4.10.13", "ValidPolicyMappingTest13EE", SCVP_CLI_CERT_OK, 0, anyPolicy},
	{"4.10.14", "ValidPolicyMappingTest14EE", SCVP_CLI_CERT_OK, 0, anyPolicy}
};

const struct test_policy_table inhibit_policy_mapping[] = {
	{"4.11.1", "InvalidinhibitPolicyMappingTest1EE", SCVP_CLI_ERR_BAD_CERT, 0, anyPolicy},
	{"4.11.2", "ValidinhibitPolicyMappingTest2EE", SCVP_CLI_CERT_OK, 0, anyPolicy},
	{"4.11.3", "InvalidinhibitPolicyMappingTest3EE", SCVP_CLI_ERR_BAD_CERT, 0, anyPolicy},
	{"4.11.4", "ValidinhibitPolicyMappingTest4EE", SCVP_CLI_CERT_OK, 0, anyPolicy},
	{"4.11.5", "InvalidinhibitPolicyMappingTest5EE", SCVP_CLI_ERR_BAD_CERT, 0, anyPolicy},
	{"4.11.6", "InvalidinhibitPolicyMappingTest6EE", SCVP_CLI_ERR_BAD_CERT, 0, anyPolicy},
	{"4.11.7", "ValidSelfIssuedinhibitPolicyMappingTest7EE", SCVP_CLI_CERT_OK, 0, anyPolicy},
	{"4.11.8", "InvalidSelfIssuedinhibitPolicyMappingTest8EE", SCVP_CLI_ERR_BAD_CERT, 0, anyPolicy},
	{"4.11.9", "InvalidSelfIssuedinhibitPolicyMappingTest9EE", SCVP_CLI_ERR_BAD_CERT, 0, anyPolicy},
	{"4.11.10", "InvalidSelfIssuedinhibitPolicyMappingTest10EE", SCVP_CLI_ERR_BAD_CERT, 0, anyPolicy},
	{"4.11.11", "InvalidSelfIssuedinhibitPolicyMappingTest11EE", SCVP_CLI_ERR_BAD_CERT, 0, anyPolicy}
};

const struct test_policy_table inhibit_any_policy[] = {
	{"4.12.1", "InvalidinhibitAnyPolicyTest1EE", SCVP_CLI_ERR_BAD_CERT, 0, anyPolicy},
	{"4.12.2", "ValidinhibitAnyPolicyTest2EE", SCVP_CLI_CERT_OK, 0, anyPolicy},
	{"4.12.3.1", "inhibitAnyPolicyTest3EE", SCVP_CLI_CERT_OK, 0, anyPolicy},
	{"4.12.3.2", "inhibitAnyPolicyTest3EE", SCVP_CLI_ERR_BAD_CERT, SCVP_POLY_INHIBIT_ANY, anyPolicy},
	{"4.12.4", "InvalidinhibitAnyPolicyTest4EE", SCVP_CLI_ERR_BAD_CERT, 0, anyPolicy},
	{"4.12.5", "InvalidinhibitAnyPolicyTest5EE", SCVP_CLI_ERR_BAD_CERT, 0, anyPolicy},
	{"4.12.6", "InvalidinhibitAnyPolicyTest6EE", SCVP_CLI_ERR_BAD_CERT, 0, anyPolicy},
	{"4.12.7", "ValidSelfIssuedinhibitAnyPolicyTest7EE", SCVP_CLI_CERT_OK, 0},
	{"4.12.8", "InvalidSelfIssuedinhibitAnyPolicyTest8EE", SCVP_CLI_ERR_BAD_CERT, 0},
	{"4.12.9", "ValidSelfIssuedinhibitAnyPolicyTest9EE", SCVP_CLI_CERT_OK, 0},
	{"4.12.10", "InvalidSelfIssuedinhibitAnyPolicyTest10EE", SCVP_CLI_ERR_BAD_CERT, 0}
};
