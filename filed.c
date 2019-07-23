/*
 * Copyright (c) 2014 - 2016, Roy Keene
 * macOS port by Ephraim Kunz
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 	1. Redistributions of source code must retain the above copyright
 * 	   notice, this list of conditions and the following disclaimer.
 * 	2. Redistributions in binary form must reproduce the above copyright
 * 	   notice, this list of conditions and the following disclaimer in the
 * 	   documentation and/or other materials provided with the distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" 
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE 
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR 
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF 
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) 
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE 
 * POSSIBILITY OF SUCH DAMAGE.
 */
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <pthread.h>
#include <strings.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <getopt.h>
#include <stdarg.h>
#include <fcntl.h>
#include <stdio.h>
#include <errno.h>
#include <time.h>
#include <pwd.h>

/*
 * Determine if the C compiler supports C11 atomics
 */
#if __STDC_VERSION__ >= 201112L
#  ifndef __STDC_NO_ATOMICS__
#    define FILED_FEATURE_C11_ATOMICS 1
#  endif
#endif

/*
 * If the C compiler does not support C11 atomics, disable TIMEOUT support
 * since it relies upon it
 */
#ifndef FILED_FEATURE_C11_ATOMICS
#  define FILED_DONT_TIMEOUT 1
#endif

/*
 * These headers are only required for TIMEOUT support
 */
#ifndef FILED_DONT_TIMEOUT
#include <stdatomic.h>
#include <stdbool.h>
#endif

/* Compile time constants */
#define FILED_VERSION "1.21"
#define FILED_SENDFILE_MAX 16777215
#define FILED_MAX_FAILURE_COUNT 30
#define FILED_DEFAULT_TYPE "application/octet-stream"
#define FILED_PATH_BUFFER_SIZE 1010

/* Default values */
#define PORT 80
#define THREAD_COUNT 5
#define BIND_ADDR "::"
#define CACHE_SIZE 8209
#define LOG_FILE "-"

/* Fuzzing Test Code */
#ifdef FILED_TEST_AFL
#define FILED_DONT_LOG 1
#define FILED_DONT_TIMEOUT 1
#define pthread_create(a, x, y, z) afl_pthread_create(a, x, y, z)
#define bind(x, y, z) afl_bind(x, y, z)
#define socket(x, y, z) 8193
#define listen(x, y) 0
#define accept(x, y, z) afl_accept(x, y, z)
#define close(x) { if (strcmp(#x, "random_fd") == 0) { close(x); } else { exit(0); } }
#define fclose(x) exit(0)

static int afl_accept(int x, void *addr, void *z) {
	((struct sockaddr_in6 *) addr)->sin6_family = AF_INET + AF_INET6 + 1;
	return(STDIN_FILENO);
	x = x;
	z = z;
}

static int afl_bind(int x, void *y, socklen_t z) {
	return(8194);
	x = x;
	y = y;
	z = z;
}

static int afl_pthread_create(pthread_t *thread, const pthread_attr_t *attr, void *(*start_routine) (void *), void *arg) {
	start_routine(arg);
	exit(3);
	thread = thread;
	attr = attr;
}
#endif

/* Configuration options that work threads need to be aware of */
struct filed_options {
	int vhosts_enabled;
	const char *fake_newroot;
};

/* Arguments for worker threads */
struct filed_worker_thread_args {
	int fd;
	struct filed_options options;
};

/* Arguments for logging threads */
struct filed_logging_thread_args {
	FILE *fp;
};

/* File information */
struct filed_fileinfo {
	pthread_mutex_t mutex;
	char path[FILED_PATH_BUFFER_SIZE];
	int fd;
	off_t len;
	char *lastmod;
	char lastmod_b[64];
	const char *type;
	char etag[64];
};

/* Request variables */
struct filed_http_request {
	/** Buffers **/
	struct filed_fileinfo fileinfo;
	char tmpbuf[FILED_PATH_BUFFER_SIZE];

	/** HTTP Request information **/
	/*** Type of request (HEAD or GET) ***/
	enum {
		FILED_REQUEST_METHOD_GET,
		FILED_REQUEST_METHOD_HEAD
	} method;

	/*** Path being requested ***/
	char path[FILED_PATH_BUFFER_SIZE]; 

	/*** Path type ***/
	enum {
		FILED_REQUEST_TYPE_DIRECTORY,
		FILED_REQUEST_TYPE_OTHER
	} type;

	struct {
		struct {
			int present;
			off_t offset;   /*** Range start ***/
			off_t length;   /*** Range length ***/
		} range;

		struct {
			int present;
			char host[FILED_PATH_BUFFER_SIZE];
		} host;

		enum {
			FILED_CONNECTION_CLOSE,
			FILED_CONNECTION_KEEP_ALIVE
		} connection;
	} headers;
};

/* Log record */
struct filed_log_entry {
	/* Type of log entry */
	enum {
		FILED_LOG_TYPE_MESSAGE,
		FILED_LOG_TYPE_TRANSFER
	} type;

	/* Linked list head/tail */
	struct filed_log_entry *_next;
	struct filed_log_entry *_prev;

	/* Thread from which this log entry eminates */
	pthread_t thread;

	/* Message buffer for type = MESSAGE */
	/* Path buffer for type = TRANSFER */
	char buffer[FILED_PATH_BUFFER_SIZE];

	/* Items for type = TRANSFER */
	int http_code;
	const char *reason;
	time_t starttime;
	time_t endtime;
	off_t req_offset;
	off_t req_length;
	off_t sent_length;
	off_t file_length;
	char ip[128];
	int port;
	int method;
};

/* Global variables */
/** Open File cache **/
struct filed_fileinfo *filed_fileinfo_fdcache = NULL;
unsigned int filed_fileinfo_fdcache_size = 0;

/** Logging **/
struct filed_log_entry *filed_log_msg_list;
pthread_mutex_t filed_log_msg_list_mutex;
pthread_cond_t filed_log_msg_list_ready;

/* Signal Handler */
static void filed_signal_handler(int signal_number) {
	struct filed_fileinfo *cache;
	unsigned int idx;

	switch (signal_number) {
		case SIGHUP:
			for (idx = 0; idx < filed_fileinfo_fdcache_size; idx++) {
				cache = &filed_fileinfo_fdcache[idx];

				pthread_mutex_lock(&cache->mutex);

				cache->path[0] = '\0';
				if (cache->fd >= 0) {
					close(cache->fd);

					cache->fd = -1;
				}

				cache->lastmod = "";
				cache->type = "";

				pthread_mutex_unlock(&cache->mutex);
			}
			break;
	}

	return;
}

/* Initialize cache */
static int filed_init_cache(unsigned int cache_size) {
	unsigned int idx;
	int mutex_init_ret;

	/* Cache may not be re-initialized */
	if (filed_fileinfo_fdcache_size != 0 || filed_fileinfo_fdcache != NULL) {
		return(1);
	}

	/* Cache does not need to be allocated if cache is not enabled */
	if (cache_size == 0) {
		return(0);
	}

	/* Allocate cache */
	filed_fileinfo_fdcache_size = cache_size;
	filed_fileinfo_fdcache = malloc(sizeof(*filed_fileinfo_fdcache) * filed_fileinfo_fdcache_size);
	if (filed_fileinfo_fdcache == NULL) {
		return(1);
	}

	/* Initialize cache entries */
	for (idx = 0; idx < filed_fileinfo_fdcache_size; idx++) {
		mutex_init_ret = pthread_mutex_init(&filed_fileinfo_fdcache[idx].mutex, NULL);
		if (mutex_init_ret != 0) {
			return(1);
		}

		filed_fileinfo_fdcache[idx].path[0] = '\0';
		filed_fileinfo_fdcache[idx].fd = -1;
		filed_fileinfo_fdcache[idx].lastmod = "";
		filed_fileinfo_fdcache[idx].type = "";
	}

	return(0);
}

/* Initialize process */
static int filed_init(unsigned int cache_size) {
	static int called = 0;
	struct sigaction signal_handler_info;
	sigset_t signal_handler_mask;
	ssize_t read_ret = 0;
	unsigned int random_value = 0;
	int cache_ret;
	int random_fd;

	if (called) {
		return(0);
	}

	called = 1;

	/* Attempt to lock all memory to physical RAM (but don't care if we can't) */
	mlockall(MCL_CURRENT | MCL_FUTURE);

	/* Establish signal handlers */
	/* SIGPIPE should interrupt system calls */
	sigfillset(&signal_handler_mask);
	signal_handler_info.sa_handler = filed_signal_handler;
	signal_handler_info.sa_mask = signal_handler_mask;
	signal_handler_info.sa_flags = SA_RESTART;
	sigaction(SIGPIPE, &signal_handler_info, NULL);

	/* Handle SIGHUP to release all caches */
	sigfillset(&signal_handler_mask);
	signal_handler_info.sa_handler = filed_signal_handler;
	signal_handler_info.sa_mask = signal_handler_mask;
	signal_handler_info.sa_flags = 0;
	sigaction(SIGHUP, &signal_handler_info, NULL);

	/* Initialize cache structure */
	cache_ret = filed_init_cache(cache_size);
	if (cache_ret != 0) {
		return(cache_ret);
	}

	/* Initialize random number generator */
	random_fd = open("/dev/urandom", O_RDONLY);
	if (random_fd >= 0) {
		read_ret = read(random_fd, &random_value, sizeof(random_value));

		close(random_fd);
	}

	random_value ^= getpid();
	random_value ^= getuid();
	random_value ^= time(NULL);

	srandom(random_value);

	return(0);
}

/* Listen on a particular address/port */
static int filed_listen(const char *address, unsigned int port) {
	struct sockaddr_in6 addr_v6;
	struct sockaddr_in addr_v4;
	struct sockaddr *addr;
	socklen_t addr_len;
	int pton_ret, bind_ret, listen_ret;
	int family;
	int fd;

	family = AF_INET6;
	pton_ret = inet_pton(family, address, &addr_v6.sin6_addr.s6_addr);
	if (pton_ret != 1) {
		family = AF_INET;
		pton_ret = inet_pton(family, address, &addr_v4.sin_addr.s_addr);
		if (pton_ret != 1) {
			return(-1);
		}

		addr_v4.sin_family = family;
		addr_v4.sin_port = htons(port);

		addr = (struct sockaddr *) &addr_v4;
		addr_len = sizeof(addr_v4);
	} else {
		addr_v6.sin6_family = AF_INET6;
		addr_v6.sin6_flowinfo = 0;
		addr_v6.sin6_scope_id = 0;
		addr_v6.sin6_port = htons(port);

		addr = (struct sockaddr *) &addr_v6;
		addr_len = sizeof(addr_v6);
	}

	fd = socket(family, SOCK_STREAM, 0);
	if (fd < 0) {
		return(fd);
	}

	bind_ret = bind(fd, addr, addr_len);
	if (bind_ret < 0) {
		close(fd);

		return(-1);
	}

	listen_ret = listen(fd, 128);
	if (listen_ret != 0) {
		close(fd);

		return(-1);
	}

	return(fd);
}

/* Log a message */
#ifdef FILED_DONT_LOG
#  define filed_logging_thread_init(x) 0
#  define filed_log_msg_debug(x, ...) /**/
#  define filed_log_msg(x, ...) /**/
#  define filed_log_entry(x) /**/
#  define filed_log_ip(x, ...) NULL
#  define filed_log_new(x) &local_dummy_log
#  define filed_log_free(x) /**/

/* Return logging handle */
static FILE *filed_log_open(const char *file) {
	return(stdout);
	file = file;
}
#else
#  define filed_log_free(x) free(x)
#  ifdef FILED_DEBUG
#    define filed_log_msg_debug(x, ...) { fprintf(stderr, x, __VA_ARGS__); fprintf(stderr, "\n"); fflush(stderr); }
#  else
#    define filed_log_msg_debug(x, ...) /**/
#  endif

/* Initialize logging thread */
static void *filed_logging_thread(void *arg_p) {
	struct filed_logging_thread_args *arg;
	struct filed_log_entry *curr, *prev;
	const char *method;
	time_t now;
	FILE *fp;

	arg = arg_p;

	fp = arg->fp;

	while (1) {
		pthread_mutex_lock(&filed_log_msg_list_mutex);
		pthread_cond_wait(&filed_log_msg_list_ready, &filed_log_msg_list_mutex);

		curr = filed_log_msg_list;
		filed_log_msg_list = NULL;

		pthread_mutex_unlock(&filed_log_msg_list_mutex);

		now = time(NULL);

		prev = NULL;
		for (; curr; curr = curr->_next) {
			curr->_prev = prev;

			prev = curr;
		}

		curr = prev;
		while (curr) {
			switch (curr->type) {
				case FILED_LOG_TYPE_MESSAGE:
					fprintf(fp, "%s", curr->buffer);

					break;
				case FILED_LOG_TYPE_TRANSFER:
					switch (curr->method) {
						case FILED_REQUEST_METHOD_GET:
							method="GET";
							break;
						case FILED_REQUEST_METHOD_HEAD:
							method="HEAD";
							break;
						default:
							method="<unknown>";
							break;
					}

					if (curr->endtime == ((time_t) -1)) {
						curr->endtime = now;
					}

					fprintf(fp, "TRANSFER METHOD=%s PATH=%s SRC=%s:%i TIME.START=%llu TIME.END=%llu CODE.VALUE=%u CODE.REASON=%s REQUEST.OFFSET=%llu REQUEST.LENGTH=%llu FILE.LENGTH=%llu TRANSFER.LENGTH=%llu",
						method,
						curr->buffer,
						curr->ip, curr->port,
						(unsigned long long) curr->starttime,
						(unsigned long long) curr->endtime,
						curr->http_code, curr->reason,
						(unsigned long long) curr->req_offset,
						(unsigned long long) curr->req_length,
						(unsigned long long) curr->file_length,
						(unsigned long long) curr->sent_length
					);

					break;
			}
			fprintf(fp, " THREAD=%llu TIME=%llu\n",
				(unsigned long long) ((intptr_t) curr->thread),
				(unsigned long long) now
			);
			fflush(fp);

			prev = curr;
			curr = curr->_prev;

			free(prev);
		}
	}

	return(NULL);
}

static void filed_log_entry(struct filed_log_entry *entry) {
	entry->thread = pthread_self();

	pthread_mutex_lock(&filed_log_msg_list_mutex);

	entry->_next = filed_log_msg_list;
	filed_log_msg_list = entry;

	pthread_mutex_unlock(&filed_log_msg_list_mutex);

	pthread_cond_signal(&filed_log_msg_list_ready);

	return;
}

static struct filed_log_entry *filed_log_new(int initialize) {
	struct filed_log_entry *retval;

	retval = malloc(sizeof(*retval));

	if (initialize) {
		retval->buffer[0] = '\0';
		retval->http_code = -1;
		retval->starttime = 0;
		retval->endtime = 0;
		retval->req_offset = 0;
		retval->req_length = 0;
		retval->sent_length = 0;
		retval->file_length = 0;
		retval->ip[0] = '\0';
		retval->port = -1;
		retval->method = -1;
	}

	return(retval);
}

static void filed_log_msg(const char *fmt, ...) {
	struct filed_log_entry *entry;
	va_list args;

	entry = filed_log_new(0);

	va_start(args, fmt);

	vsnprintf(entry->buffer, sizeof(entry->buffer), fmt, args);

	va_end(args);

	entry->type = FILED_LOG_TYPE_MESSAGE;

	filed_log_entry(entry);

	return;
}

static const char *filed_log_ip(struct sockaddr *addr, char *buffer, size_t bufferlen) {
	struct sockaddr_in *addr_v4;
	struct sockaddr_in6 *addr_v6;
	const char *retval = NULL;

	addr_v6 = (struct sockaddr_in6 *) addr;

	switch (addr_v6->sin6_family) {
		case AF_INET:
			addr_v4 = (struct sockaddr_in *) addr;
			retval = inet_ntop(AF_INET, &addr_v4->sin_addr, buffer, bufferlen);
			break;
		case AF_INET6:
			retval = inet_ntop(AF_INET6, &addr_v6->sin6_addr, buffer, bufferlen);
			break;
	}

	return(retval);
}

static FILE *filed_log_open(const char *file) {
	FILE *retval;

	if (strcmp(file, "-") == 0) {
		retval = stdout;
	} else if (file[0] == '|') {
		file++;
		retval = popen(file, "w");
	} else {
		retval = fopen(file, "a+");
	}

	return(retval);
}

static int filed_logging_thread_init(FILE *logfp) {
	struct filed_logging_thread_args *args;
	pthread_t thread_id;

	args = malloc(sizeof(*args));
	args->fp = logfp;

	filed_log_msg_list = NULL;

	pthread_mutex_init(&filed_log_msg_list_mutex, NULL);

	pthread_create(&thread_id, NULL, filed_logging_thread, args);

	filed_log_msg("START");

	return(0);
}
#endif

#ifdef FILED_DONT_TIMEOUT
#define filed_sockettimeout_thread_init() 0
#define filed_sockettimeout_init() 0
#define filed_sockettimeout_accept(x) /**/
#define filed_sockettimeout_processing_start(x) /**/
#define filed_sockettimeout_processing_end(x) /**/
#define filed_sockettimeout_close(x) /**/
#else
_Atomic time_t filed_sockettimeout_time;
struct {
	_Atomic time_t expiration_time;
	_Atomic pthread_t thread_id;
	bool valid;
}* filed_sockettimeout_sockstatus;
long filed_sockettimeout_sockstatus_length;
int filed_sockettimeout_devnull_fd;

static int filed_sockettimeout_sockfd_in_range(int sockfd) {
	if (sockfd < 3) {
		return(0);
	}

	if (sockfd > filed_sockettimeout_sockstatus_length) {
		return(0);
	}

	return(1);
}

static void filed_sockettimeout_expire(int sockfd, int length) {
	time_t now, expire;

	now = atomic_load(&filed_sockettimeout_time);

	expire = now + length;

	atomic_store(&filed_sockettimeout_sockstatus[sockfd].expiration_time, expire);

	return;
}

static void filed_sockettimeout_accept(int sockfd) {
	if (!filed_sockettimeout_sockfd_in_range(sockfd)) {
		return;
	}

	filed_sockettimeout_expire(sockfd, 60);

	atomic_store(&filed_sockettimeout_sockstatus[sockfd].thread_id, pthread_self());

	atomic_store(&filed_sockettimeout_sockstatus[sockfd].valid, true);

	return;
}

static void filed_sockettimeout_processing_start(int sockfd) {
	if (!filed_sockettimeout_sockfd_in_range(sockfd)) {
		return;
	}

	filed_sockettimeout_expire(sockfd, 86400);

	return;
}

static void filed_sockettimeout_processing_end(int sockfd) {
	if (!filed_sockettimeout_sockfd_in_range(sockfd)) {
		return;
	}

	filed_sockettimeout_expire(sockfd, 60);

	return;
}

static void filed_sockettimeout_close(int sockfd) {
	if (!filed_sockettimeout_sockfd_in_range(sockfd)) {
		return;
	}

	atomic_store(&filed_sockettimeout_sockstatus[sockfd].valid, false);

	return;
}

static void *filed_sockettimeout_thread(void *arg) {
	struct timespec sleep_time;
	time_t now, expiration_time;
	pthread_t thread_id;
	long idx;
	int count;
	bool valid;

	while (1) {
		for (count = 0; count < 10; count++) {
			sleep_time.tv_sec = 30;
			sleep_time.tv_nsec = 0;
			nanosleep(&sleep_time, NULL);

			now = time(NULL);

			atomic_store(&filed_sockettimeout_time, now);
		}

		for (idx = 0; idx < filed_sockettimeout_sockstatus_length; idx++) {
			valid = atomic_load(&filed_sockettimeout_sockstatus[idx].valid);

			if (!valid) {
				continue;
			}

			expiration_time = atomic_load(&filed_sockettimeout_sockstatus[idx].expiration_time);

			thread_id = atomic_load(&filed_sockettimeout_sockstatus[idx].thread_id);

			if (expiration_time > now) {
				continue;
			}

			filed_sockettimeout_close(idx);

			dup2(filed_sockettimeout_devnull_fd, idx);

			pthread_kill(thread_id, SIGPIPE);
		}
	}

	return(NULL);
}

static int filed_sockettimeout_thread_init(void) {
	pthread_t thread_id;

	pthread_create(&thread_id, NULL, filed_sockettimeout_thread, NULL);

	return(0);
}

static int filed_sockettimeout_init(void) {
	long maxfd, idx;

	maxfd = sysconf(_SC_OPEN_MAX);
	if (maxfd <= 0) {
		maxfd = 4096;
	}

	filed_sockettimeout_sockstatus = malloc(sizeof(*filed_sockettimeout_sockstatus) * maxfd);
	if (filed_sockettimeout_sockstatus == NULL) {
		return(-1);
	}

	for (idx = 0; idx < maxfd; idx++) {
		filed_sockettimeout_sockstatus[idx].valid = false;
	}

	filed_sockettimeout_sockstatus_length = maxfd;
	filed_sockettimeout_devnull_fd = open("/dev/null", O_RDWR);
	if (filed_sockettimeout_devnull_fd < 0) {
		return(-1);
	}

	return(0);
}
#endif

/* Format time per RFC2616 */
static char *filed_format_time(char *buffer, size_t buffer_len, const time_t timeinfo) {
	struct tm timeinfo_tm, *timeinfo_tm_p;

	timeinfo_tm_p = gmtime_r(&timeinfo, &timeinfo_tm);
	if (timeinfo_tm_p == NULL) {
		return("unknown");
	}

	buffer[buffer_len - 1] = '\0';
	buffer_len = strftime(buffer, buffer_len - 1, "%a, %d %b %Y %H:%M:%S GMT", timeinfo_tm_p);

	return(buffer);
}

/* hash */
static unsigned int filed_hash(const unsigned char *value, unsigned int modulus) {
	unsigned char curr, prev;
	int diff;
	unsigned int retval;

	retval = modulus - 1;
	prev = modulus % 255;

	while ((curr = *value)) {
		if (curr < 32) {
			curr = 255 - curr;
		} else {
			curr -= 32;
		}

		if (prev < curr) {
			diff = curr - prev;
		} else {
			diff = prev - curr;
		}

		prev = curr;

		retval <<= 3;
		retval &= 0xFFFFFFFFLU;
		retval ^= diff;

		value++;
	}

	retval = retval % modulus;

	return(retval);
}

/* Find a mime-type based on the filename */
static const char *filed_determine_mimetype(const char *path) {
	const char *p;

	p = strrchr(path, '.');
	if (p == NULL) {
		return(FILED_DEFAULT_TYPE);
	}

	p++;
	if (*p == '\0') {
		return(FILED_DEFAULT_TYPE);
	}

	filed_log_msg_debug("Looking up MIME type for %s (hash = %llu)", p, (unsigned long long) filed_hash((const unsigned char *) p, 16777259));

#include "filed-mime-types.h"

	return(FILED_DEFAULT_TYPE);
}

/* Generate a unique identifier */
static void filed_generate_etag(char *etag, size_t length) {
	snprintf(etag, length, "%llx-%llx%llx%llx%llx",
		(unsigned long long) time(NULL),
		(unsigned long long) random(),
		(unsigned long long) random(),
		(unsigned long long) random(),
		(unsigned long long) random()
	);
}

#ifdef FILED_FAKE_CHROOT
/* Translate a path into a fake chroot path */
static const char *filed_path_translate(const char *path, struct filed_options *options) {
	static __thread char pathBuffer[8192];
	int snprintf_ret;

	/* If no alternative root is specified, return the unadorned path */
	if (!options->fake_newroot) {
		return(path);
	}

	/* Verify that this request will not go outside of the specified root */
	if (strstr(path, "/../") != NULL || path[0] != '/') {
		filed_log_msg_debug("Unable to translate path \"%s\", contains invalid characters", path);

		return(options->fake_newroot);
	}

	/* Create the new path into our local (TLS) static buffer */
	snprintf_ret = snprintf(pathBuffer, sizeof(pathBuffer), "%s/%s", options->fake_newroot, path);
	if (snprintf_ret < 0 || ((unsigned int) snprintf_ret) >= sizeof(pathBuffer)) {
		filed_log_msg_debug("Unable to translate path \"%s\", will not fit into new buffer", path);

		return(options->fake_newroot);
	}

	filed_log_msg_debug("Translating path \"%s\" into \"%s\"", path, pathBuffer);

	/* Return the new path */
	return(pathBuffer);
}

static void filed_path_translate_set_root(const char *var, struct filed_options *options, const char *val) {
	options->fake_newroot = strdup(val);

	return;

	/* var is only used in the macro -- discard it here */
	var = var;
}
#else
#define filed_path_translate(path, options) path
#define filed_path_translate_set_root(var, options, val) var = strdup(val)
#endif

/* Open a file and return file information */
static struct filed_fileinfo *filed_open_file(const char *path, struct filed_fileinfo *buffer, struct filed_options *options) {
	struct filed_fileinfo *cache;
	unsigned int cache_idx;
	off_t len;
	int fd;

	if (filed_fileinfo_fdcache_size != 0) {
		cache_idx = filed_hash((const unsigned char *) path, filed_fileinfo_fdcache_size);

		cache = &filed_fileinfo_fdcache[cache_idx];

		filed_log_msg_debug("Locking mutex for idx: %lu", (unsigned long) cache_idx);

		pthread_mutex_lock(&cache->mutex);

		filed_log_msg_debug("Completed locking mutex for idx: %lu", (unsigned long) cache_idx);
	} else {
		cache_idx = 0;
		cache = buffer;
		cache->path[0] = '\0';
		cache->fd = -1;
	}

	if (strcmp(path, cache->path) != 0) {
		filed_log_msg_debug("Cache miss for idx: %lu: OLD \"%s\", NEW \"%s\"", (unsigned long) cache_idx, cache->path, path);

		fd = open(filed_path_translate(path, options), O_RDONLY | O_LARGEFILE);
		if (fd < 0) {
			if (filed_fileinfo_fdcache_size != 0) {
				pthread_mutex_unlock(&cache->mutex);
			}

			return(NULL);
		}

		if (cache->fd >= 0) {
			close(cache->fd);
		}

		len = lseek(fd, 0, SEEK_END);
		lseek(fd, 0, SEEK_SET);

		cache->fd = fd;
		cache->len = len;
		strcpy(cache->path, path);
		cache->type = filed_determine_mimetype(path);
		filed_generate_etag(cache->etag, sizeof(cache->etag));

		/* XXX:TODO: Determine */
		cache->lastmod = filed_format_time(cache->lastmod_b, sizeof(cache->lastmod_b), time(NULL) - 30);
	} else {
		filed_log_msg_debug("Cache hit for idx: %lu: PATH \"%s\"", (unsigned long) cache_idx, path);
	}

	if (filed_fileinfo_fdcache_size != 0) {
		/*
		 * We have to make a duplicate FD, because once we release the cache
		 * mutex, the file descriptor may be closed
		 */
		fd = dup(cache->fd);
		if (fd < 0) {
			pthread_mutex_unlock(&cache->mutex);

			return(NULL);
		}

		buffer->fd = fd;
		buffer->len = cache->len;
		buffer->type = cache->type;
		memcpy(buffer->lastmod_b, cache->lastmod_b, sizeof(buffer->lastmod_b));
		memcpy(buffer->etag, cache->etag, sizeof(buffer->etag));
		buffer->lastmod = buffer->lastmod_b + (cache->lastmod - cache->lastmod_b);

		pthread_mutex_unlock(&cache->mutex);
	}

	return(buffer);

	/* options is only used if fake chroot is enabled, confuse the compiler */
	options = options;
}

/* Process an HTTP request and return the path requested */
static struct filed_http_request *filed_get_http_request(FILE *fp, struct filed_http_request *buffer_st, struct filed_options *options) {
	char *method, *path;
	char *buffer, *workbuffer, *workbuffer_next;
	char *fgets_ret;
	size_t buffer_len, path_len;
	off_t range_start, range_end, range_length;
	int range_request;
	int snprintf_ret;
	int i;

	/* Set to default values */
	range_start = 0;
	range_end   = 0;
	range_request = 0;
	range_length = -1;
	buffer_st->headers.host.present = 0;
	buffer_st->headers.connection = FILED_CONNECTION_CLOSE;

	buffer = buffer_st->tmpbuf;
	buffer_len = sizeof(buffer_st->tmpbuf);

	fgets_ret = fgets(buffer, buffer_len, fp);
	if (fgets_ret == NULL) {
		return(NULL);
	}

	method = buffer;

	buffer = strchr(buffer, ' ');
	if (buffer == NULL) {
		return(NULL);
	}

	*buffer = '\0';
	buffer++;

	path = buffer;

	/* Terminate path component */
	buffer = strpbrk(path, "\r\n ");
	if (buffer != NULL) {
		*buffer = '\0';
		buffer++;
	}

	/* We only handle the "GET" and "HEAD' methods */
	if (strcasecmp(method, "head") != 0) {
		if (strcasecmp(method, "get") != 0) {
			return(NULL);
		}

		/* GET request */
		buffer_st->method = FILED_REQUEST_METHOD_GET;
	} else {
		/* HEAD request */
		buffer_st->method = FILED_REQUEST_METHOD_HEAD;
	}

	/* Note path */
	path_len = strlen(path);
	memcpy(buffer_st->path, path, path_len + 1);

	/* Determine type of request from path */
	if (path_len == 0) {
		buffer_st->type = FILED_REQUEST_TYPE_DIRECTORY;
	} else {
		if (path[path_len - 1] == '/') {
			buffer_st->type = FILED_REQUEST_TYPE_DIRECTORY;
		} else {
			buffer_st->type = FILED_REQUEST_TYPE_OTHER;
		}
	}

	/* Reset buffer for later use */
	buffer = buffer_st->tmpbuf;

	for (i = 0; i < 100; i++) {
		fgets_ret = fgets(buffer, buffer_len, fp);
		if (fgets_ret == NULL) {
			break;
		}

		if (strncasecmp(buffer, "Range: ", 7) == 0) {
			workbuffer = buffer + 7;

			if (strncasecmp(workbuffer, "bytes=", 6) == 0) {
				workbuffer += 6;

				range_request = 1;

				range_start = strtoull(workbuffer, &workbuffer_next, 10);

				workbuffer = workbuffer_next;

				if (*workbuffer == '-') {
					workbuffer++;

					if (*workbuffer != '\r' && *workbuffer != '\n') {
						range_end = strtoull(workbuffer, &workbuffer_next, 10);
					}
				}
			}
		} else if (strncasecmp(buffer, "Host: ", 5) == 0) {
			buffer_st->headers.host.present = 1;

			workbuffer = strpbrk(buffer + 5, "\r\n:");
			if (workbuffer != NULL) {
				*workbuffer = '\0';
			}

			workbuffer = buffer + 5;
			while (*workbuffer == ' ') {
				workbuffer++;
			}

			strcpy(buffer_st->headers.host.host, workbuffer);
		} else if (strncasecmp(buffer, "Connection: Keep-Alive", 22) == 0) {
			buffer_st->headers.connection = FILED_CONNECTION_KEEP_ALIVE;
		}

		if (memcmp(buffer, "\r\n", 2) == 0) {
			break;
		}
	}

	/* Determine range */
	if (range_end != 0) {
		if (range_end <= range_start) {
			return(NULL);
		}

		range_length = range_end - range_start;

		filed_log_msg_debug("Computing length parameter: %llu = %llu - %llu",
			(unsigned long long) range_length,
			(unsigned long long) range_end,
			(unsigned long long) range_start
		);
	}

	/* Fill up structure to return */
	buffer_st->headers.range.present = range_request;
	buffer_st->headers.range.offset  = range_start;
	buffer_st->headers.range.length  = range_length;

	/* If vhosts are enabled, compute new path */
	if (options->vhosts_enabled) {
		if (buffer_st->headers.host.present == 1) {
			buffer = buffer_st->tmpbuf;
			buffer_len = sizeof(buffer_st->tmpbuf);

			snprintf_ret = snprintf(buffer, buffer_len, "/%s%s%s",
				buffer_st->headers.host.host,
				buffer_st->path[0] == '/' ? "" : "/",
				buffer_st->path
			);
			if (snprintf_ret >= 0) {
				if (((unsigned int) snprintf_ret) < buffer_len) {
					strcpy(buffer_st->path, buffer);
				}
			}
		}
	}

	return(buffer_st);
}

/* Return an error page */
static void filed_error_page(FILE *fp, const char *date_current, int error_number, int method, const char *reason, struct filed_log_entry *log) {
	char *error_string = "<html><head><title>ERROR</title></head><body>Unable to process request</body></html>";

	fprintf(fp, "HTTP/1.1 %i Not OK\r\nDate: %s\r\nServer: filed\r\nLast-Modified: %s\r\nContent-Length: %llu\r\nContent-Type: %s\r\nConnection: close\r\n\r\n",
		error_number,
		date_current,
		date_current,
		(unsigned long long) strlen(error_string),
		"text/html"
	);

	/* silence error string for HEAD requests */
	if (method != FILED_REQUEST_METHOD_HEAD) {
		fprintf(fp, "%s", error_string);
	}

	/* Log error */
	/** reason must point to a globally allocated value **/
	log->reason = reason;
	log->http_code = error_number;

	filed_log_entry(log);

	/* Close connection */
	filed_sockettimeout_close(fileno(fp));

	fclose(fp);

	return;
}

/* Return a redirect to index.html */
#ifndef FILED_DONT_REDIRECT_DIRECTORIES
static void filed_redirect_index(FILE *fp, const char *date_current, const char *path, struct filed_log_entry *log) {
	int http_code = 302;
	fprintf(fp, "HTTP/1.1 %i OK\r\nDate: %s\r\nServer: filed\r\nLast-Modified: %s\r\nContent-Length: 0\r\nConnection: close\r\nLocation: %s\r\n\r\n",
		http_code,
		date_current,
		date_current,
		"index.html"
	);

	/* Log redirect */
	log->reason = "redirect";
	log->http_code = http_code;

	filed_log_entry(log);

	/* Close connection */
	filed_sockettimeout_close(fileno(fp));

	fclose(fp);

	return;

	/* Currently unused: path */
	path = path;
}
#endif

/* Convert an enum representing the "Connection" header value to a string */
static const char *filed_connection_str(int connection_value) {
	switch (connection_value) {
		case FILED_CONNECTION_CLOSE:
			return("close");
		case FILED_CONNECTION_KEEP_ALIVE:
			return("keep-alive");
	}

	return("close");
}

/* Handle a single request from a client */
static int filed_handle_client(int fd, struct filed_http_request *request, struct filed_log_entry *log, struct filed_options *options) {
	struct filed_fileinfo *fileinfo;
	ssize_t sendfile_ret;
	size_t sendfile_size;
	off_t sendfile_offset, sendfile_sent, sendfile_len;
	char *path;
	char *date_current, date_current_b[64];
	int http_code;
	FILE *fp;

	/* Determine current time */
	date_current = filed_format_time(date_current_b, sizeof(date_current_b), time(NULL));

	/* Open socket as ANSI I/O for ease of use */
	fp = fdopen(fd, "w+b");
	if (fp == NULL) {
		filed_sockettimeout_close(fd);

		close(fd);

		log->buffer[0] = '\0';
		log->http_code = -1;
		log->reason = "fdopen_failed";

		filed_log_entry(log);

		return(FILED_CONNECTION_CLOSE);
	}

	request = filed_get_http_request(fp, request, options);

	if (request == NULL) {
		log->buffer[0] = '\0';

		filed_error_page(fp, date_current, 500, FILED_REQUEST_METHOD_GET, "format", log);

		return(FILED_CONNECTION_CLOSE);
	}

	filed_sockettimeout_processing_start(fd);

	path = request->path;
	strcpy(log->buffer, path);
	log->method = request->method;

	/* If the requested path is a directory, redirect to index page */
	if (request->type == FILED_REQUEST_TYPE_DIRECTORY) {
#ifdef FILED_DONT_REDIRECT_DIRECTORIES
		char localpath[8192];
		int snprintf_ret;

		snprintf_ret = snprintf(localpath, sizeof(localpath), "%s/index.html", path);

		if (snprintf_ret <= 0 || snprintf_ret > (sizeof(localpath) - 1)) {
			filed_error_page(fp, date_current, 500, request->method, "path_format", log);

			return(FILED_CONNECTION_CLOSE);
		}

		path = localpath;
#else
		filed_redirect_index(fp, date_current, path, log);

		return(FILED_CONNECTION_CLOSE);
#endif
	}

	fileinfo = filed_open_file(path, &request->fileinfo, options);
	if (fileinfo == NULL) {
		filed_error_page(fp, date_current, 404, request->method, "open_failed", log);

		return(FILED_CONNECTION_CLOSE);
	}

	if (request->headers.range.present) {
		if (request->headers.range.offset != 0 || request->headers.range.length >= 0) {
			if (request->headers.range.offset >= fileinfo->len) {
				filed_error_page(fp, date_current, 416, request->method, "range_invalid", log);

				close(fileinfo->fd);

				return(FILED_CONNECTION_CLOSE);
			}

			if (request->headers.range.length == ((off_t) -1)) {
				filed_log_msg_debug("Computing length to fit in bounds: fileinfo->len = %llu, request->headers.range.offset = %llu",
					(unsigned long long) fileinfo->len,
					(unsigned long long) request->headers.range.offset
				);

				request->headers.range.length = fileinfo->len - request->headers.range.offset;
			}

			filed_log_msg_debug("Partial request, starting at: %llu and running for %lli bytes",
				(unsigned long long) request->headers.range.offset,
				(long long) request->headers.range.length
			);

		}

		http_code = 206;
	} else {
		http_code = 200;

		/* Compute fake range parameters that includes the entire file */
		request->headers.range.offset = 0;
		request->headers.range.length = fileinfo->len;
	}

	fprintf(fp, "HTTP/1.1 %i OK\r\nDate: %s\r\nServer: filed\r\nLast-Modified: %s\r\nContent-Length: %llu\r\nAccept-Ranges: bytes\r\nContent-Type: %s\r\nConnection: %s\r\nETag: \"%s\"\r\n",
		http_code,
		date_current,
		fileinfo->lastmod,
		(unsigned long long) request->headers.range.length,
		fileinfo->type,
		filed_connection_str(request->headers.connection),
		fileinfo->etag
	);

	if (http_code == 206) {
		fprintf(fp, "Content-Range: bytes %llu-%llu/%llu\r\n",
			(unsigned long long) request->headers.range.offset,
			(unsigned long long) (request->headers.range.offset + request->headers.range.length - 1),
			(unsigned long long) fileinfo->len
		);
	}
	fprintf(fp, "\r\n");
	fflush(fp);

	log->http_code = http_code;
	log->reason = "OK";
	log->starttime = time(NULL);
	log->req_offset = request->headers.range.offset;
	log->req_length = request->headers.range.length;
	log->file_length = fileinfo->len;

#ifdef FILED_NONBLOCK_HTTP
	int socket_flags;
	fd_set rfd, wfd;
	char sinkbuf[8192];
	ssize_t read_ret;

	FD_ZERO(&rfd);
	FD_ZERO(&wfd);
	FD_SET(fd, &rfd);
	FD_SET(fd, &wfd);

	socket_flags = fcntl(fd, F_GETFL);
	fcntl(fd, F_SETFL, socket_flags | O_NONBLOCK);
#endif
	sendfile_offset = request->headers.range.offset;
	sendfile_len = request->headers.range.length;
	sendfile_sent = 0;
	while (request->method == FILED_REQUEST_METHOD_GET) {
		if (sendfile_len > FILED_SENDFILE_MAX) {
			sendfile_size = FILED_SENDFILE_MAX;
		} else {
			sendfile_size = sendfile_len;
		}

		sendfile_ret = sendfile(fd, fileinfo->fd, &sendfile_offset, sendfile_size);
		if (sendfile_ret <= 0) {
#ifdef FILED_NONBLOCK_HTTP
			if (errno == EAGAIN) {
				sendfile_ret = 0;

				while (1) {
					select(fd + 1, &rfd, &wfd, NULL, NULL);
					if (FD_ISSET(fd, &rfd)) {
						read_ret = read(fd, sinkbuf, sizeof(sinkbuf));

						if (read_ret <= 0) {
							break;
						}
					}

					if (FD_ISSET(fd, &wfd)) {
						read_ret = 1;

						break;
					}
				}

				if (read_ret <= 0) {
					break;
				}
			} else {
				break;
			}
#else
			break;
#endif
		}

		sendfile_len -= sendfile_ret;
		sendfile_sent += sendfile_ret;
		if (sendfile_len == 0) {
			break;
		}
	}

	log->endtime = (time_t) -1;
	log->sent_length = sendfile_sent;

	filed_log_entry(log);

	close(fileinfo->fd);

	if (request->headers.connection != FILED_CONNECTION_KEEP_ALIVE) {
		filed_sockettimeout_close(fd);

		fclose(fp);

		return(FILED_CONNECTION_CLOSE);
	}

	filed_sockettimeout_processing_end(fd);

	return(FILED_CONNECTION_KEEP_ALIVE);
}

/* Handle incoming connections */
static void *filed_worker_thread(void *arg_v) {
	struct filed_worker_thread_args *arg;
	struct filed_http_request request;
	struct filed_log_entry *log, local_dummy_log;
	struct filed_options *options;
	struct sockaddr_in6 addr;
	socklen_t addrlen;
	int failure_count = 0, max_failure_count = FILED_MAX_FAILURE_COUNT;
	int connection_state = FILED_CONNECTION_CLOSE;
	int master_fd, fd = -1;

	/* Read arguments */
	arg = arg_v;

	master_fd = arg->fd;
	options = &arg->options;

	while (1) {
		/* Failure loop prevention */
		if (failure_count > max_failure_count) {
			break;
		}

		/* Allocate a new log buffer */
		log = filed_log_new(1);
		if (log == NULL) {
			filed_log_msg("ALLOCATE_LOG_MSG_FAILED");

			break;
		}

		log->type = FILED_LOG_TYPE_TRANSFER;

		/* If we closed the old connection, accept a new one */
		if (connection_state == FILED_CONNECTION_CLOSE) {
			/* Accept a new client */
			addrlen = sizeof(addr);

			fd = accept(master_fd, (struct sockaddr *) &addr, &addrlen);
		}

		/*
		 * If we fail, make a note of it so we don't go into a loop of
		 * accept() failing
		 */
		if (fd < 0) {
			/* Log the new connection */
			filed_log_msg("ACCEPT_FAILED");

			failure_count++;

			filed_log_free(log);

			continue;
		}

		filed_sockettimeout_accept(fd);

		/* Fill in log structure */
		if (filed_log_ip((struct sockaddr *) &addr, log->ip, sizeof(log->ip)) == NULL) {
			log->ip[0] = '\0';
			log->port = 0;
		} else {
			log->port = addr.sin6_port;
		}

		/* Reset failure count*/
		failure_count = 0;

		/* Handle socket */
		connection_state = filed_handle_client(fd, &request, log, options);
	}

	/* Report error */
	filed_log_msg("THREAD_DIED ABNORMAL");

	return(NULL);

	/* local_dummy_log is only used if FILED_DONT_LOG is enabled, otherwise it's not used, but the compiler hates that idea. */
	local_dummy_log.type = 0;
	local_dummy_log.type = local_dummy_log.type;
}

/* Create worker threads */
static int filed_worker_threads_init(int fd, int thread_count, struct filed_options *options) {
	struct filed_worker_thread_args *arg;
	pthread_t threadid;
	int pthread_ret;
	int i;

	for (i = 0; i < thread_count; i++) {
		arg = malloc(sizeof(*arg));

		arg->fd = fd;
		memcpy(&arg->options, options, sizeof(*options));

		pthread_ret = pthread_create(&threadid, NULL, filed_worker_thread, arg);
		if (pthread_ret != 0) {
			return(-1);
		}
	}

	return(0);
}

/* Display help */
static void filed_print_help(FILE *output, int long_help, const char *extra) {
	if (extra) {
		fprintf(output, "%s\n", extra);
	}

	fprintf(output, "Usage: filed [<options>]\n");
	fprintf(output, "  Options:\n");
	fprintf(output, "      -h, --help\n");
	fprintf(output, "      -d, --daemon\n");
	fprintf(output, "      -v, --version\n");
	fprintf(output, "      -V, --vhost\n");
	fprintf(output, "      -b <address>, --bind <address>\n");
	fprintf(output, "      -p <port>, --port <port>\n");
	fprintf(output, "      -t <count>, --threads <count>\n");
	fprintf(output, "      -c <entries>, --cache <entries>\n");
	fprintf(output, "      -l <file>, --log <file>\n");
	fprintf(output, "      -u <user>, --user <user>\n");
	fprintf(output, "      -r <directory>, --root <directory>\n");

	if (long_help) {
		fprintf(output, "\n");
		fprintf(output, "  Usage:\n");
		fprintf(output, "      -h (or --help) prints this usage information.\n");
		fprintf(output, "\n");
		fprintf(output, "      -d (or --daemon) instructs filed to become a daemon after initializing\n");
		fprintf(output, "                       the listening TCP socket and log files.\n");
		fprintf(output, "\n");
		fprintf(output, "      -v (or --version) instructs filed print out the version number and exit.\n");
		fprintf(output, "\n");
		fprintf(output, "      -V (or --vhost) instructs filed to prepend all requests with their HTTP\n");
		fprintf(output, "                      Host header.\n");
		fprintf(output, "\n");
		fprintf(output, "      -b (or --bind) specifies the address to listen for incoming HTTP\n");
		fprintf(output, "                     requests on.  The default value is \"%s\".\n", BIND_ADDR);
		fprintf(output, "\n");
		fprintf(output, "      -p (or --port) specifies the TCP port number to listen for incoming HTTP\n");
		fprintf(output, "                     requests on.  The default is %u.\n", (unsigned int) PORT);
		fprintf(output, "\n");
		fprintf(output, "      -t (or --threads) specifies the number of worker threads to create. Each\n");
		fprintf(output, "                        worker thread can service one concurrent HTTP session.\n");
		fprintf(output, "                        Thus the number of threads created will determine how\n");
		fprintf(output, "                        many simultaneous transfers will be possible. The\n");
		fprintf(output, "                        default is %lu.\n", (unsigned long) THREAD_COUNT);
		fprintf(output, "\n");
		fprintf(output, "      -c (or --cache) specifies the number of file information cache entries\n");
		fprintf(output, "                      to allocate.  Each cache entry holds file information as\n");
		fprintf(output, "                      well as an open file descriptor to the file, so resource\n");
		fprintf(output, "                      limits (i.e., ulimit) should be considered.  This should\n");
		fprintf(output, "                      be a prime number for ideal use with the lookup method.\n");
		fprintf(output, "                      The default is %lu.\n", (unsigned long) CACHE_SIZE);
		fprintf(output, "\n");
		fprintf(output, "      -l (or --log) specifies a filename to open for writing log entries.  Log\n");
		fprintf(output, "                    entries are made for various stages in transfering files.\n");
		fprintf(output, "                    The log file is opened before switching users (see \"-u\")\n");
		fprintf(output, "                    and root directories (see \"-r\").  The log file is never\n");
		fprintf(output, "                    closed so log rotation without stopping the daemon is will\n");
		fprintf(output, "                    not work.  The value of \"-\" indicates that standard output\n");
		fprintf(output, "                    should be used for logging.  If the filename begins with a\n");
		fprintf(output, "                    pipe (\"|\") then a process is started and used for logging\n");
		fprintf(output, "                    instead of a file.  The default is \"%s\".\n", LOG_FILE);
#ifdef FILED_DONT_LOG
		fprintf(output, "                    Note that logging is completely disabled so this option does\n");
		fprintf(output, "                    nothing in this build.\n");
#endif
		fprintf(output, "\n");
		fprintf(output, "      -u (or --user) specifies the user to switch user IDs to before servicing\n");
		fprintf(output, "                     requests.  The default is not change user IDs.\n");
		fprintf(output, "\n");
		fprintf(output, "      -r (or --root) specifies the directory to act as the root directory for\n");
		fprintf(output, "                     the file server.  If this option is specified, chroot(2)\n");
		fprintf(output, "                     is called.  The default is not change root directories,\n");
		fprintf(output, "                     that is, the \"/\" directory is shared out.  This will\n");
		fprintf(output, "                     likely be a security issue, so this option should always\n");
		fprintf(output, "                     be used.\n");
	}

	return;
}

/* Add a getopt option */
static void filed_getopt_long_setopt(struct option *opt, const char *name, int has_arg, int val) {
	opt->name     = name;
	opt->has_arg  = has_arg;
	opt->flag     = NULL;
	opt->val      = val;

	return;
}

/* Resolve a username to a UID */
static int filed_user_lookup(const char *user, uid_t *user_id) {
	char *next;
	uid_t user_id_check;
#ifndef FILED_NO_GETPWNAM
	struct passwd *ent;

	ent = getpwnam(user);
	if (ent != NULL) {
		*user_id = ent->pw_uid;

		return(0);
	}
#endif

	user_id_check = strtoull(user, &next, 10);
	if (next == NULL) {
		return(1);
	}

	if (next[0] != '\0') {
		return(1);
	}

	*user_id = user_id_check;

	return(0);
}

/* Daemonize */
static int filed_daemonize(void) {
	pid_t setsid_ret, fork_ret;
	int chdir_ret, dup2_ret;
	int fd_in, fd_out;

	chdir_ret = chdir("/");
	if (chdir_ret != 0) {
		return(1);
	}

	fork_ret = fork();
	if (fork_ret < 0) {
		return(1);
	}

	if (fork_ret > 0) {
		/* Parent */
		waitpid(fork_ret, NULL, 0);

		exit(EXIT_SUCCESS);
	}

	/* Child */
	if (fork() != 0) {
		/* Child */
		exit(EXIT_SUCCESS);
	}

	/* Grand child */
	setsid_ret = setsid();
	if (setsid_ret == ((pid_t) -1)) {
		return(1);
	}

	fd_in = open("/dev/null", O_RDONLY);
	fd_out = open("/dev/null", O_WRONLY);
	if (fd_in < 0 || fd_out < 0) {
		return(1);
	}

	dup2_ret = dup2(fd_in, STDIN_FILENO);
	if (dup2_ret != STDIN_FILENO) {
		return(1);
	}

	dup2_ret = dup2(fd_out, STDOUT_FILENO);
	if (dup2_ret != STDOUT_FILENO) {
		return(1);
	}

	dup2_ret = dup2(fd_out, STDERR_FILENO);
	if (dup2_ret != STDERR_FILENO) {
		return(1);
	}

	close(fd_in);
	close(fd_out);

	return(0);
}

/* Run process */
int main(int argc, char **argv) {
	struct option options[12];
	struct filed_options thread_options = {0};
	const char *bind_addr = BIND_ADDR, *newroot = NULL, *log_file = LOG_FILE;
	FILE *log_fp;
	uid_t user = 0;
	int port = PORT, thread_count = THREAD_COUNT;
	int cache_size = CACHE_SIZE;
	int init_ret, chroot_ret, setuid_ret, lookup_ret, chdir_ret;
	int setuid_enabled = 0, daemon_enabled = 0;
	int ch;
	int fd;

	/* Process arguments */
	filed_getopt_long_setopt(&options[0], "port", required_argument, 'p');
	filed_getopt_long_setopt(&options[1], "threads", required_argument, 't');
	filed_getopt_long_setopt(&options[2], "cache", required_argument, 'c');
	filed_getopt_long_setopt(&options[3], "bind", required_argument, 'b');
	filed_getopt_long_setopt(&options[4], "user", required_argument, 'u');
	filed_getopt_long_setopt(&options[5], "root", required_argument, 'r');
	filed_getopt_long_setopt(&options[6], "help", no_argument, 'h');
	filed_getopt_long_setopt(&options[7], "daemon", no_argument, 'd');
	filed_getopt_long_setopt(&options[8], "log", required_argument, 'l');
	filed_getopt_long_setopt(&options[9], "version", no_argument, 'v');
	filed_getopt_long_setopt(&options[10], "vhost", no_argument, 'V');
	filed_getopt_long_setopt(&options[11], NULL, 0, 0);
	while ((ch = getopt_long(argc, argv, "p:t:c:b:u:r:l:hdvV", options, NULL)) != -1) {
		switch(ch) {
			case 'p':
				port = atoi(optarg);
				break;
			case 't':
				thread_count = atoi(optarg);
				break;
			case 'c':
				cache_size = atoi(optarg);
				break;
			case 'b':
				bind_addr = strdup(optarg);
				break;
			case 'u':
				setuid_enabled = 1;
				lookup_ret = filed_user_lookup(optarg, &user);
				if (lookup_ret != 0) {
					filed_print_help(stderr, 0, "Invalid username specified");

					return(1);
				}
				break;
			case 'r':
				filed_path_translate_set_root(newroot, &thread_options, optarg);
				break;
			case 'l':
				log_file = strdup(optarg);
				break;
			case 'd':
				daemon_enabled = 1;
				break;
			case 'V':
				thread_options.vhosts_enabled = 1;

				break;
			case 'v':
				printf("filed version %s\n", FILED_VERSION);

				return(0);
			case '?':
			case ':':
				filed_print_help(stderr, 0, NULL);

				return(1);
			case 'h':
				filed_print_help(stdout, 1, NULL);

				return(0);
		}
	}

	/* Open log file */
	log_fp = filed_log_open(log_file);
	if (log_fp == NULL) {
		perror("filed_log_open");

		return(4);
	}

	/* Create listening socket */
	fd = filed_listen(bind_addr, port);
	if (fd < 0) {
		perror("filed_listen");

		return(1);
	}

	/* Initialize timeout structures */
	init_ret = filed_sockettimeout_init();
	if (init_ret != 0) {
		perror("filed_sockettimeout_init");

		return(8);
	}

	/* Become a daemon */
	if (daemon_enabled) {
		init_ret = filed_daemonize();
		if (init_ret != 0) {
			perror("filed_daemonize");

			return(6);
		}
	}

	/* Chroot, if appropriate */
	if (newroot) {
		chdir_ret = chdir(newroot);
		if (chdir_ret != 0) {
			perror("chdir");

			return(1);
		}

		chroot_ret = chroot(".");
		if (chroot_ret != 0) {
			perror("chroot");

			return(1);
		}
	}

	/* Drop privileges, if appropriate */
	if (setuid_enabled) {
		setuid_ret = setuid(user);
		if (setuid_ret != 0) {
			perror("setuid");

			return(1);
		}
	}

	/* Initialize */
	init_ret = filed_init(cache_size);
	if (init_ret != 0) {
		perror("filed_init");

		return(3);
	}

	/* Create logging thread */
	init_ret = filed_logging_thread_init(log_fp);
	if (init_ret != 0) {
		perror("filed_logging_thread_init");

		return(4);
	}

	/* Create socket termination thread */
	init_ret = filed_sockettimeout_thread_init();
	if (init_ret != 0) {
		perror("filed_sockettimeout_thread_init");

		return(7);
	}

	/* Create worker threads */
	init_ret = filed_worker_threads_init(fd, thread_count, &thread_options);
	if (init_ret != 0) {
		perror("filed_worker_threads_init");

		return(5);
	}

	/* Wait for threads to exit */
	/* XXX:TODO: Monitor thread usage */
	while (1) {
		sleep(86400);
	}

	/* Return in failure */
	return(2);
}