This is RFC3280 compliant daemon with client api.


To run with NIST PKI Test:

untar nist_tests.tar
run susanin with default config:
./susanin -c susanin.conf (or set -d to run as daemon)
run client:
./path_test ../susanin/socket ../nist_tests/trusted ../nist_tests/untrusted_cli

susanin/socket - socket file
../nist_tests/trusted - pki trusted path
../nist_tests/untrusted_cli - pki untrusted path
