#include <pthread.h>
#include <openssl/ssl.h>

static pthread_mutex_t *lock_cs;
static long *lock_count;
static int openssl_inited = 0;

static void pthreads_locking_callback(int mode, int type, char *file, int line)
{
	if (mode & CRYPTO_LOCK) {
		pthread_mutex_lock(&(lock_cs[type]));
		lock_count[type]++;
	}
	else
		pthread_mutex_unlock(&(lock_cs[type]));
}

static unsigned long pthreads_thread_id(void)
{
	unsigned long ret;

	ret = (unsigned long)pthread_self();
	return(ret);
}
static void CRYPTO_thread_setup(void)
{
	int i;

	lock_cs = OPENSSL_malloc(CRYPTO_num_locks() * sizeof(pthread_mutex_t));
	lock_count = OPENSSL_malloc(CRYPTO_num_locks() * sizeof(long));
	for (i=0; i<CRYPTO_num_locks(); i++) {
		lock_count[i] = 0;
		pthread_mutex_init(&(lock_cs[i]), NULL);
	}

	CRYPTO_set_id_callback((unsigned long (*)())pthreads_thread_id);
	CRYPTO_set_locking_callback((void (*)())pthreads_locking_callback);
}

static void CRYPTO_thread_cleanup(void)
{
	int i;

	CRYPTO_set_locking_callback(NULL);
	for (i=0; i<CRYPTO_num_locks(); i++)
		pthread_mutex_destroy(&(lock_cs[i]));
	OPENSSL_free(lock_cs);
	OPENSSL_free(lock_count);
}

void openssl_init(void)
{
	if (openssl_inited)
		return;
	CRYPTO_thread_setup();
	OpenSSL_add_all_algorithms ();
	OpenSSL_add_all_ciphers();
}

void openssl_deinit(void) {
	if (openssl_inited) {
		openssl_inited = 0;
		CRYPTO_thread_cleanup();
	}
}


