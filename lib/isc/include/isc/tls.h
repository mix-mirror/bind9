/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * SPDX-License-Identifier: MPL-2.0
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

#pragma once

#include <isc/log.h>
#include <isc/mem.h>
#include <isc/region.h>
#include <isc/result.h>
#include <isc/types.h>

typedef struct ssl_ctx_st isc_tlsctx_t;
typedef struct ssl_st	  isc_tls_t;

typedef struct x509_store_st isc_tls_cert_store_t;

void
isc_tlsctx_free(isc_tlsctx_t **ctpx);
/*%<
 * Free a TLS client or server context.
 *
 * Requires:
 *\li	'ctxp' != NULL and '*ctxp' != NULL.
 */

void
isc_tlsctx_attach(isc_tlsctx_t *src, isc_tlsctx_t **ptarget);
/*%<
 * Attach to the TLS context.
 *
 * Requires:
 *\li	'src' != NULL;
 *\li	'ptarget' != NULL;
 *\li	'*ptarget' == NULL.
 */

isc_result_t
isc_tlsctx_createserver(const char *keyfile, const char *certfile,
			isc_tlsctx_t **ctxp);
/*%<
 * Set up a TLS server context, using the key and certificate specified in
 * 'keyfile' and 'certfile', or a self-generated ephemeral key and
 * certificdate if both 'keyfile' and 'certfile' are NULL.
 *
 * Requires:
 *\li	'ctxp' != NULL and '*ctxp' == NULL.
 *\li	'keyfile' and 'certfile' are either both NULL or both non-NULL.
 */

isc_result_t
isc_tlsctx_createclient(isc_tlsctx_t **ctxp);
/*%<
 * Set up a TLS client context.
 *
 * Requires:
 *\li	'ctxp' != NULL and '*ctxp' == NULL.
 */

isc_result_t
isc_tlsctx_load_certificate(isc_tlsctx_t *ctx, const char *keyfile,
			    const char *certfile);
/*%<
 * Load a TLS certificate into a TLS context.
 *
 * Requires:
 *\li	'ctx' != NULL;
 *\li	'keyfile' and 'certfile' are both non-NULL.
 */

typedef enum isc_tls_protocol_version {
	/* these must be the powers of two */
	ISC_TLS_PROTO_VER_1_2 = 1 << 0,
	ISC_TLS_PROTO_VER_1_3 = 1 << 1,
	ISC_TLS_PROTO_VER_UNDEFINED,
} isc_tls_protocol_version_t;

void
isc_tlsctx_set_protocols(isc_tlsctx_t *ctx, const uint32_t tls_versions);
/*%<
 * Sets the supported TLS protocol versions via the 'tls_versions' bit
 * set argument (see `isc_tls_protocol_version_t` enum for the
 * expected values).
 *
 * Requires:
 *\li	'ctx' != NULL;
 *\li	'tls_versions' != 0.
 */

bool
isc_tls_protocol_supported(const isc_tls_protocol_version_t tls_ver);
/*%<
 * Check in runtime that the specified TLS protocol versions is supported.
 */

isc_tls_protocol_version_t
isc_tls_protocol_name_to_version(const char *name);
/*%<
 * Convert the protocol version string into the version of
 * 'isc_tls_protocol_version_t' type.
 * Requires:
 *\li	'name' != NULL.
 */

bool
isc_tlsctx_load_dhparams(isc_tlsctx_t *ctx, const char *dhparams_file);
/*%<
 * Load Diffie-Hellman parameters file and apply it to the given TLS context
 * 'ctx'.
 *
 * Requires:
 * \li	'ctx' != NULL;
 * \li	'dhaprams_file' a valid pointer to a non empty string.
 */

bool
isc_tls_cipherlist_valid(const char *cipherlist);
/*%<
 * Check if cipher list string is valid.
 *
 * Requires:
 * \li	'cipherlist' a valid pointer to a non empty string.
 */

void
isc_tlsctx_set_cipherlist(isc_tlsctx_t *ctx, const char *cipherlist);
/*%<
 * Set cipher list string for on the given TLS context 'ctx'. This affects only
 * TLSv1.2 (and older).
 *
 * Requires:
 * \li	'ctx' != NULL;
 * \li	'cipherlist' a valid pointer to a non empty string.
 */

bool
isc_tls_cipher_suites_valid(const char *cipher_suites);
/*%<
 * Check if cipher suites string is valid.
 *
 * Requires:
 * \li	'cipher_suites' a valid pointer to a non empty string.
 */

void
isc_tlsctx_set_cipher_suites(isc_tlsctx_t *ctx, const char *cipher_suites);
/*%<
 * Set cipher suites string for on the given TLS context 'ctx'. This affects
 * only TLSv1.3.
 *
 * Requires:
 * \li	'ctx' != NULL;
 * \li	'cipher_suites' a valid pointer to a non empty string.
 */

void
isc_tlsctx_prefer_server_ciphers(isc_tlsctx_t *ctx, const bool prefer);
/*%<
 * Make the given TLS context 'ctx' to prefer or to not prefer
 * server side ciphers during the ciphers negotiation.
 *
 * Requires:
 * \li	'ctx' != NULL.
 */

void
isc_tlsctx_session_tickets(isc_tlsctx_t *ctx, const bool use);
/*%<
 * Enable/Disable stateless session resumptions tickets on the given
 * TLS context 'ctx' (see RFC5077).
 *
 * Requires:
 * \li	'ctx' != NULL.
 */

isc_tls_t *
isc_tls_create(isc_tlsctx_t *ctx);
/*%<
 * Set up the structure to hold data for a new TLS connection.
 *
 * Requires:
 *\li	'ctx' != NULL.
 */

void
isc_tls_free(isc_tls_t **tlsp);
/*%<
 * Free a TLS structure.
 *
 * Requires:
 *\li	'tlsp' != NULL and '*tlsp' != NULL.
 */

const char *
isc_tls_verify_peer_result_string(isc_tls_t *tls);
/*%<
 * Return a user readable description of a remote peer's certificate
 * validation.
 *
 * Requires:
 *\li	'tls' != NULL.
 */

#if HAVE_LIBNGHTTP2
void
isc_tlsctx_enable_http2client_alpn(isc_tlsctx_t *ctx);
void
isc_tlsctx_enable_http2server_alpn(isc_tlsctx_t *ctx);
/*%<
 * Enable HTTP/2 Application Layer Protocol Negotation for 'ctx'.
 *
 * Requires:
 *\li	'ctx' is not NULL.
 */
#endif /* HAVE_LIBNGHTTP2 */

void
isc_tls_get_selected_alpn(isc_tls_t *tls, const unsigned char **alpn,
			  unsigned int *alpnlen);

#define ISC_TLS_DOT_PROTO_ALPN_ID     "dot"
#define ISC_TLS_DOT_PROTO_ALPN_ID_LEN 3

void
isc_tlsctx_enable_dot_client_alpn(isc_tlsctx_t *ctx);
void
isc_tlsctx_enable_dot_server_alpn(isc_tlsctx_t *ctx);
/*%<
 * Enable DoT Application Layer Protocol Negotation for 'ctx'.
 *
 * Requires:
 *\li	'ctx' is not NULL.
 */

isc_result_t
isc_tlsctx_enable_peer_verification(isc_tlsctx_t *ctx, const bool is_server,
				    isc_tls_cert_store_t *store,
				    const char		 *hostname,
				    bool hostname_ignore_subject);
/*%<
 * Enable peer certificate and, optionally, hostname (for client contexts)
 * verification.
 *
 * Requires:
 *\li	'ctx' is not NULL;
 *\li	'store' is not NULL.
 */

isc_result_t
isc_tlsctx_load_client_ca_names(isc_tlsctx_t *ctx, const char *ca_bundle_file);
/*%<
 * Load the list of CA-certificate names from a CA-bundle file to
 * send by the server to a client when requesting a peer certificate.
 * Usually used in conjunction with
 * isc_tlsctx_enable_peer_validation().
 *
 * Requires:
 *\li	'ctx' is not NULL;
 *\li	'ca_bundle_file' is not NULL.
 */

isc_result_t
isc_tls_cert_store_create(const char		*ca_bundle_filename,
			  isc_tls_cert_store_t **pstore);
/*%<
 * Create X509 certificate store. The 'ca_bundle_filename' might be
 * 'NULL' or an empty string, which means use the default system wide
 * bundle/directory.
 *
 * Requires:
 *\li	'pstore' is a valid pointer to a pointer containing 'NULL'.
 */

void
isc_tls_cert_store_free(isc_tls_cert_store_t **pstore);
/*%<
 * Free X509 certificate store.
 *
 * Requires:
 *\li	'pstore' is a valid pointer to a pointer containing a non-'NULL' value.
 */

typedef struct isc_tlsctx_client_session_cache isc_tlsctx_client_session_cache_t;
/*%<
 * TLS client session cache is an object which allows efficient
 * storing and retrieval of previously saved TLS sessions so that they
 * can be resumed. This object is supposed to be a foundation for
 * implementing TLS session resumption - a standard technique to
 * reduce the cost of re-establishing a connection to the remote
 * server endpoint.
 *
 * OpenSSL does server-side TLS session caching transparently by
 * default. However, on the client-side, a TLS session to resume must
 * be manually specified when establishing the TLS connection. The TLS
 * client session cache is precisely the foundation for that.
 *
 * The cache has been designed to have the following characteristics:
 *
 * - Fixed maximal number of entries to not keep too many obsolete
 * sessions within the cache;
 *
 * - The cache is indexed by character string keys. Each string is a
 * key representing a remote endpoint (unique remote endpoint name,
 * e.g. combination of the remote IP address and port);
 *
 * - Least Recently Used (LRU) cache replacement policy while allowing
 * easy removal of obsolete entries;
 *
 * - Ability to store multiple TLS sessions associated with the given
 * key (remote endpoint name). This characteristic is important if
 * multiple connections to the same remote server can be established;
 *
 * - Ability to efficiently retrieve the most recent TLS sessions
 * associated with the key (remote endpoint name).
 *
 * Because of these characteristics, the cache will end up having the
 * necessary amount of resumable TLS session parameters to the most
 * used remote endpoints ("hot entries") after a short period of
 * initial use ("warmup").
 *
 * Attempting to resume TLS sessions is an optimisation, which is not
 * guaranteed to succeed because it requires the same session to be
 * present in the server session caches. If it is not the case, the
 * usual handshake procedure takes place. However, when session
 * resumption is successful, it reduces the amount of the
 * computational resources required as well as the amount of data to
 * be transmitted when (re)establishing the connection. Also, it
 * reduces round trip time (by reducing the number of packets to
 * transmit).
 *
 * This optimisation is important in the context of DNS because the
 * amount of data within the full handshake messages might be
 * comparable to or surpass the size of a typical DNS message.
 */

void
isc_tlsctx_client_session_cache_create(
	isc_mem_t *mctx, isc_tlsctx_t *ctx, const size_t max_entries,
	isc_tlsctx_client_session_cache_t **cachep);
/*%<
 * Create a new TLS client session cache object.
 *
 * Requires:
 *\li	'mctx' is a valid memory context object;
 *\li	'ctx' is a valid TLS context object;
 *\li	'max_entries' is a positive number;
 *\li	'cachep' is a valid pointer to a pointer which must be equal to NULL.
 */

void
isc_tlsctx_client_session_cache_attach(
	isc_tlsctx_client_session_cache_t  *source,
	isc_tlsctx_client_session_cache_t **targetp);
/*%<
 * Create a reference to the TLS client session cache object.
 *
 * Requires:
 *\li	'source' is a valid TLS client session cache object;
 *\li	'targetp' is a valid pointer to a pointer which must equal NULL.
 */

void
isc_tlsctx_client_session_cache_detach(
	isc_tlsctx_client_session_cache_t **cachep);
/*%<
 * Remove a reference to the TLS client session cache object.
 *
 * Requires:
 *\li	'cachep' is a pointer to a pointer to a valid TLS client session cache
 *object.
 */

void
isc_tlsctx_client_session_cache_keep(isc_tlsctx_client_session_cache_t *cache,
				     char *remote_peer_name, isc_tls_t *tls);
/*%<
 * Add a resumable TLS client session within 'tls' to the TLS client
 * session cache object 'cache' and associate it with
 * 'remote_server_name' string. Also, the oldest entry from the cache
 * might get removed if the cache is full.
 *
 * Requires:
 *\li	'cache' is a pointer to a valid TLS client session cache object;
 *\li	'remote_peer_name' is a pointer to a non empty character string;
 *\li	'tls' is a valid, non-'NULL' pointer to a TLS connection state object.
 */

void
isc_tlsctx_client_session_cache_keep_sockaddr(
	isc_tlsctx_client_session_cache_t *cache, isc_sockaddr_t *remote_peer,
	isc_tls_t *tls);
/*%<
 * The same as 'isc_tlsctx_client_session_cache_keep()', but uses a
 * 'isc_sockaddr_t' as a key, instead of a character string.
 *
 * Requires:
 *\li	'remote_peer' is a valid, non-'NULL', pointer to an 'isc_sockaddr_t'
 *object.
 */

void
isc_tlsctx_client_session_cache_reuse(isc_tlsctx_client_session_cache_t *cache,
				      char *remote_server_name, isc_tls_t *tls);
/*%
 * Try to restore a previously stored TLS session denoted by a remote
 * server name as a key ('remote_server_name') into the given TLS
 * connection state object ('tls'). The successfully restored session
 * gets removed from the cache.
 *
 * Requires:
 *\li	'cache' is a pointer to a valid TLS client session cache object;
 *\li	'remote_peer_name' is a pointer to a non empty character string;
 *\li	'tls' is a valid, non-'NULL' pointer to a TLS connection state object.
 */

void
isc_tlsctx_client_session_cache_reuse_sockaddr(
	isc_tlsctx_client_session_cache_t *cache, isc_sockaddr_t *remote_peer,
	isc_tls_t *tls);
/*%<
 * The same as 'isc_tlsctx_client_session_cache_reuse()', but uses a
 * 'isc_sockaddr_t' as a key, instead of a character string.
 *
 * Requires:
 *\li	'remote_peer' is a valid, non-'NULL' pointer to an 'isc_sockaddr_t'
 *object.
 */

const isc_tlsctx_t *
isc_tlsctx_client_session_cache_getctx(isc_tlsctx_client_session_cache_t *cache);
/*%<
 * Returns a TLS context associated with the given TLS client
 * session cache object. The function is intended to be used to
 * implement the sanity checks ('INSIST()'s and 'REQUIRE()'s).
 *
 * Requires:
 *\li	'cache' is a pointer to a valid TLS client session cache object.
 */

#define ISC_TLSCTX_CLIENT_SESSION_CACHE_DEFAULT_SIZE (150)
/*%<
 * The default maximum size of a TLS client session cache. The value
 * should be large enough to hold enough sessions to successfully
 * re-establish connections to the most remote TLS servers, but not
 * too big to avoid keeping too much obsolete sessions.
 */

typedef struct isc_tlsctx_cache isc_tlsctx_cache_t;
/*%<
 * The TLS context cache is an object which allows retrieving a
 * previously created TLS context based on the following tuple:
 *
 * 1. The name of a TLS entry, as defined in the configuration file;
 * 2. A transport type. Currently, only TLS (DoT) and HTTPS (DoH) are
 *    supported;
 * 3. An IP address family (AF_INET or AF_INET6).
 *
 * There are multiple uses for this object:
 *
 * First, it allows reuse of client-side contexts during zone transfers.
 * That, in turn, allows use of session caches associated with these
 * contexts, which enables TLS session resumption, making establishment
 * of XoT connections faster and computationally cheaper.
 *
 * Second, it can be extended to be used as storage for TLS context related
 * data, as defined in 'tls' statements in the configuration file (for
 * example, CA-bundle intermediate certificate storage, client-side contexts
 * with pre-loaded certificates in a case of Mutual TLS, etc). This will
 * be used to implement Strict/Mutual TLS.
 *
 * Third, it avoids creating an excessive number of server-side TLS
 * contexts, which might help to reduce the number of contexts
 * created during server initialisation and reconfiguration.
 */

typedef enum {
	isc_tlsctx_cache_none = 0,
	isc_tlsctx_cache_tls,
	isc_tlsctx_cache_https,
	isc_tlsctx_cache_count
} isc_tlsctx_cache_transport_t;
/*%< TLS context cache transport type values. */

void
isc_tlsctx_cache_create(isc_mem_t *mctx, isc_tlsctx_cache_t **cachep);
/*%<
 * Create a new TLS context cache object.
 *
 * Requires:
 *\li	'mctx' is a valid memory context;
 *\li	'cachep' is a valid pointer to a pointer which must be equal to NULL.
 */

void
isc_tlsctx_cache_attach(isc_tlsctx_cache_t  *source,
			isc_tlsctx_cache_t **targetp);
/*%<
 * Create a reference to the TLS context cache object.
 *
 * Requires:
 *\li	'source' is a valid TLS context cache object;
 *\li	'targetp' is a valid pointer to a pointer which must equal NULL.
 */

void
isc_tlsctx_cache_detach(isc_tlsctx_cache_t **cachep);
/*%<
 * Remove a reference to the TLS context cache object.
 *
 * Requires:
 *\li	'cachep' is a pointer to a pointer to a valid TLS
 *	 context cache object.
 */

isc_result_t
isc_tlsctx_cache_add(
	isc_tlsctx_cache_t *cache, const char *name,
	const isc_tlsctx_cache_transport_t transport, const uint16_t family,
	isc_tlsctx_t *ctx, isc_tls_cert_store_t *store,
	isc_tlsctx_client_session_cache_t *client_sess_cache,
	isc_tlsctx_t **pfound, isc_tls_cert_store_t **pfound_store,
	isc_tlsctx_client_session_cache_t **pfound_client_sess_cache);
/*%<
 *
 * Add a new TLS context and its associated data to the TLS context
 * cache. 'pfound' is an optional pointer, which can be used to
 * retrieve an already existing TLS context object in a case it
 * exists.
 *
 * The passed certificates store object ('store') possession is
 * transferred to the cache object in a case of success. In some cases
 * it might be destroyed immediately upon the call completion.
 *
 * The possession of the passed TLS client session cache
 * ('client_sess_cache') is also transferred to the cache object in a
 * case of success.
 *
 * Requires:
 *\li	'cache' is a valid pointer to a TLS context cache object;
 *\li	'name' is a valid pointer to a non-empty string;
 *\li	'transport' is a valid transport identifier (currently only
 *       TLS/DoT and HTTPS/DoH are supported);
 *\li	'family' - either 'AF_INET' or 'AF_INET6';
 *\li   'ctx' - a valid pointer to a valid TLS context object;
 *\li   'store' - a valid pointer to a valid TLS certificates store object or
 *		'NULL';
 *\li   'client_sess_cache' - a valid pointer to a valid TLS client sessions
 *cache object or 'NULL.
 *
 * Returns:
 *\li	#ISC_R_EXISTS - node of the same key already exists;
 *\li	#ISC_R_SUCCESS - the new entry has been added successfully.
 */

isc_result_t
isc_tlsctx_cache_find(
	isc_tlsctx_cache_t *cache, const char *name,
	const isc_tlsctx_cache_transport_t transport, const uint16_t family,
	isc_tlsctx_t **pctx, isc_tls_cert_store_t **pstore,
	isc_tlsctx_client_session_cache_t **pfound_client_sess_cache);
/*%<
 * Look up a TLS context and its associated data in the TLS context cache.
 *
 * Requires:
 *\li	'cache' is a valid pointer to a TLS context cache object;
 *\li	'name' is a valid pointer to a non empty string;
 *\li	'transport' - a valid transport identifier (currently only
 *       TLS/DoT and HTTPS/DoH are supported;
 *\li	'family' - either 'AF_INET' or 'AF_INET6';
 *\li   'pctx' - a valid pointer to a non-NULL pointer;
 *\li   'pstore' - a valid pointer to a non-NULL pointer or 'NULL'.
 *\li   'pfound_client_sess_cache' - a valid pointer to a non-NULL pointer or
 *'NULL'.
 *
 * Returns:
 *\li	#ISC_R_SUCCESS - the context has been found;
 *\li	#ISC_R_NOTFOUND	- the context has not been found. In such a case,
 *		'pstore' still might get initialised as there is one to many
 *		relation between stores and contexts.
 */

void
isc_tlsctx_set_random_session_id_context(isc_tlsctx_t *ctx);
/*%<
 * Set context within which session can be reused to a randomly
 * generated value. This one is used for TLS session resumption using
 * session IDs. See OpenSSL documentation for
 * 'SSL_CTX_set_session_id_context()'.
 *
 * It might be worth noting that usually session ID contexts are kept
 * static for an application and particular certificate
 * combination. However, for the cases when exporting server side TLS
 * session cache to/loading from external memory is not required, we
 * might use random IDs just fine. See,
 * e.g. 'ngx_ssl_session_id_context()' in NGINX for an example of how
 * a session ID might be obtained.
 *
 * Requires:
 *\li   'ctx' - a valid non-NULL pointer;
 */

bool
isc_tls_valid_sni_hostname(const char *hostname);
/*%<
 * Checks if a 'hostname' is not a valid IPv4 or IPv6 address
 * string. Returns 'true' if the hostname is likely a domain name, and
 * 'false' if it represents an IP address.
 */

void
isc_tls_sslkeylogfile_append(const char *line);
/*%<
 * Appends the provided line to the dedicated SSL keys log file
 * provided via "SSLKEYLOGFILE" environmental variable (iff the variable is
 * set).
 */

/* QUIC related functionality (mostly see quic/tls_quic.c) */
#ifdef HAVE_LIBNGTCP2

typedef struct ssl_cipher_st isc_tls_cipher_t;
/*%<
 * See 'SSL_CIPHER'.
 */

typedef void (*isc_tls_keylog_cb_t)(const isc_tls_t *tls, const char *line);
/*%<
 * Keylog callback. See 'SSL_CTX_set_keylog_callback()'.
 */

typedef enum isc_quic_encryption_level {
	ISC_QUIC_ENCRYPTION_INITIAL = 0,
	ISC_QUIC_ENCRYPTION_EARLY_DATA,
	ISC_QUIC_ENCRYPTION_HANDSHAKE,
	ISC_QUIC_ENCRYPTION_APPLICATION
} isc_quic_encryption_level_t;
/*%<
 * QUIC TLS encryption level (similar to 'ssl_encryption_level_t').
 */

typedef struct isc_tls_quic_method {
	bool (*set_read_secret)(isc_tls_t			 *tls,
				const isc_quic_encryption_level_t level,
				const isc_tls_cipher_t		 *cipher,
				const uint8_t *secret, const size_t secret_len);

	bool (*set_write_secret)(isc_tls_t			  *tls,
				 const isc_quic_encryption_level_t level,
				 const isc_tls_cipher_t		  *cipher,
				 const uint8_t			  *secret,
				 const size_t			   secret_len);

	bool (*add_handshake_data)(isc_tls_t			    *tls,
				   const isc_quic_encryption_level_t level,
				   const uint8_t *data, const size_t len);

	/* The flush_flight() callback is used for optimisation means and
	 * cannot be implemented manually without access to the internals
	 * of the crypto libraries (TLS state machine). We need to skip
	 * it. */
	/*bool (*flush_flight)(isc_tls_t *tls);*/

	bool (*send_alert)(isc_tls_t			    *tls,
			   const isc_quic_encryption_level_t level,
			   const uint8_t		     alert);
} isc_tls_quic_method_t;
/*%<
 * As set of functions (hooks) for interaction between TLS and QUIC. Closely
 * resembles the LibreSSL/BoringSSL/QuicTLS's
 * 'SSL_QUIC_METHOD/ssl_quic_method_st' type.
 */

typedef struct isc_tls_quic_interface isc_tls_quic_interface_t;
/*%<
 * An implementation of QUIC and TLS interaction interface.
 */

const char *
isc_tls_quic_encryption_level_text(const isc_quic_encryption_level_t level);
/*%<
 * Get textual description of a given QUIC encryption level. The
 * function is intended for log messages.
 */

const isc_tls_quic_interface_t *
isc_tls_get_default_quic_interface(void);
/*%<
 * Returns a set of hooks to interact wit the default implementation
 * of QUIC integration API. It might be either a native QUIC
 * integration API or a compatibility layer depending on BIND
 * configuration.
 */

void
isc_tlsctx_quic_configure(isc_tlsctx_t			 *tlsctx,
			  const isc_tls_quic_interface_t *quic_interface);
/*%<
 * Configures the given TLS context object to be used for QUIC.
 * It is meant to be used as one of the last steps of a TLS
 * context configuration.
 *
 * Requires:
 *\li	'tlsctx' is a valid pointer to a TLS context object;
 *\li	'quic_interface' - a valid pointer to a QUIC interface object.
 */

isc_tls_t *
isc_tls_create_quic(isc_tlsctx_t *ctx);
/*%<
 * Create a new TLS structure to hold data for a new QUIC connection.
 *
 * Requires:
 *\li	'ctx' != NULL.
 */

void
isc_tls_quic_set_app_data(isc_tls_t *tls, void *app_data);
/*%<
 * Sets QUIC application data (user data) for the given TLS object
 * configured for QUIC. Works similar to 'SSL_set_app_data()' which
 * cannot be used for TLS objects configured for QUIC as this
 * functionality is used internally.
 *
 * Requires:
 *\li	'tls' is a valid pointer to a TLS object.
 */

void *
isc_tls_quic_get_app_data(isc_tls_t *tls);
/*%<
 * Returns QUIC application data (user data) for the given TLS
 * object configured for QUIC. Works similar to 'SSL_get_app_data()'
 * which cannot be used for TLS objects configured for QUIC as this
 * functionality is used internally.
 *
 * Requires:
 *\li	'tls' is a valid pointer to a TLS object.
 */

void
isc_tls_quic_set_keylog_callback(isc_tls_t *tls, isc_tls_keylog_cb_t cb);
/*%<
 * Sets QUIC keylog callback. See 'SSL_CTX_set_keylog_callback()' for more
 * details. NOTE: No-op on LibreSSL.
 *
 * Additional information:
 * https://datatracker.ietf.org/doc/draft-ietf-tls-keylogfile/
 *
 * Requires:
 *\li	'tls' is a valid pointer to a TLS object.
 */

isc_result_t
isc_tls_set_quic_method(isc_tls_t *tls, const isc_tls_quic_method_t *method);
/*%<
 * Configures the QUIC related hooks on a TLS object previously configured for
 * QUIC. The 'method' must remain valid for the lifetime of 'tls'.
 *
 * NOTE: See 'SSL_set_quic_method()'.
 *
 * Requires:
 *\li	'tls' is a valid pointer to a TLS object;
 *\li	'method' is a valid pointer to a QUIC method object.
 *
 * Returns:
 *\li	#ISC_R_SUCCESS - on success;
 *\li	#ISC_R_FAILURE - on failure.
 */

isc_result_t
isc_tls_provide_quic_data(isc_tls_t			   *tls,
			  const isc_quic_encryption_level_t level,
			  const uint8_t *data, const size_t len);
/*%<
 * Provides data from QUIC at a particular encryption level 'level' to a TLS
 * object previously configured for QUIC.
 *
 * NOTE: See 'SSL_provide_quic_data()'.
 *
 * Requires:
 *\li	'tls' is a valid pointer to a TLS object;
 *\li	'len' == 0 || 'data' != NULL;
 *
 * Returns:
 *\li	#ISC_R_SUCCESS - on success;
 *\li	#ISC_R_FAILURE - on failure.
 */

int
isc_tls_process_quic_post_handshake(isc_tls_t *tls);
/*%<
 * Processes any data that QUIC has provided that left after TLS handshake
 * completion in a TLS object previously configured for QUIC.
 *
 * NOTE: See 'SSL_process_quic_post_handshake()'. You can pass the
 * return value to 'SSL_get_error()' for better error processing.
 *
 * Requires:
 *\li	'tls' is a valid pointer to a TLS object.
 *
 * Returns:
 *\li	'1' - on success;
 *\li	'0' - on failure.
 */

int
isc_tls_do_quic_handshake(isc_tls_t *tls);
/*%<
 * Processes any handshake data that QUIC has provided.
 *
 * NOTE: See 'SSL_do_handshake()'. The function shares return values
 * with this function and can be considered a thin wrapper on top of
 * it. The intention behind the wrapper to hide some differences in
 * behaviour between native BoringSSL-style QUIC API and our OpenSSL
 * compatibility layer. You can pass the return value to
 * 'SSL_get_error()' for better error processing.
 *
 * Requires:
 *\li	'tls' is a valid pointer to a TLS object.
 */

isc_result_t
isc_tls_set_quic_transport_params(isc_tls_t *tls, const uint8_t *params,
				  const size_t params_len);
/*%<
 * Sets the 'quic_transport_parameters' extension value in either the
 *'ClientHello' or 'EncryptedExtensions' handshake message for a TLS object
 * previously configured for QUIC. The pointers need to be valid only for the
 * time of the call.
 *
 * NOTE: See 'SSL_set_quic_transport_params()'.
 *
 * Requires:
 *\li	'tls' is a valid pointer to a TLS object;
 *\li	'params' is a valid pointer;
 *\li	'params_len' is more than zero.
 *
 * Returns:
 *\li	#ISC_R_SUCCESS - on success;
 *\li	#ISC_R_FAILURE - on failure.
 */

void
isc_tls_get_peer_quic_transport_params(isc_tls_t      *tls,
				       const uint8_t **out_params,
				       size_t	      *out_params_len);
/*%<
 * Returns the 'quic_transport_parameters' extension value and its length for
 * either the 'ClientHello' or 'EncryptedExtensions' handshake message sent by
 * the peer for a TLS object previously configured for QUIC. The data buffer is
 * valid for the for until the call to 'isc_tls_quic_uninit()'.
 *
 * NOTE: See 'SSL_get_peer_quic_transport_params()'.
 *
 * Requires:
 *\li	'tls' is a valid pointer to a TLS object;
 *\li	'out_params' is a valid pointer to a nullified pointer;
 *\li	'out_params_len' is a valid pointer to a nullified variable.
 *
 * Returns:
 *\li	#ISC_R_SUCCESS - on success;
 *\li	#ISC_R_FAILURE - on failure.
 */

isc_quic_encryption_level_t
isc_tls_quic_read_level(const isc_tls_t *tls);
/*%<
 * Returns the current read encryption level. MUST NOT be called from a
 * 'isc_tls_quic_method_t' callback  (due to inconsistent behaviour in different
 * crypto libraries in this situation).
 *
 * NOTE: See 'SSL_quic_read_level()'.
 *
 * Requires:
 *\li	'tls' is a valid pointer to a TLS object.
 */

isc_quic_encryption_level_t
isc_tls_quic_write_level(const isc_tls_t *tls);
/*%<
 * Returns the current write encryption level. MUST NOT be called from a
 * 'isc_tls_quic_method_t' callback  (due to inconsistent behaviour in different
 * crypto libraries in this situation).
 *
 * NOTE: See 'SSL_quic_write_level()'.
 *
 * Requires:
 *\li	'tls' is a valid pointer to a TLS object.
 */

void
isc_tls_quic_crypto_initialize(void);
/*%<
 * Initiliazes the internal QUIC crypto library. It is supposed to
 * be used right after loading all required OpenSSL crypto providers.
 *
 * Internally it mostly pre-fetches the crypto algorithms according to
 * OpenSSL 3.X recommendations.
 *
 * https://docs.openssl.org/3.0/man7/crypto/#explicit-fetching
 */

void
isc_tls_quic_crypto_shutdown(void);
/*%<
 * Uninitiliazes the internal QUIC crypto library. It is supposed to
 * be used right before unloading the used OpenSSL crypto providers.
 */

void
isc__tls_quic_initialize(void);

void
isc__tls_quic_shutdown(void);

#endif /* HAVE_LIBNGTCP2 */

#define isc_tlserr2result(category, module, funcname, fallback)            \
	isc__tlserr2result(category, module, funcname, fallback, __FILE__, \
			   __LINE__)
isc_result_t
isc__tlserr2result(isc_logcategory_t category, isc_logmodule_t module,
		   const char *funcname, isc_result_t fallback,
		   const char *file, int line);
