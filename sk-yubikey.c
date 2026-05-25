/*
 * yubikey-sk - YubiKey FIDO2 SK provider for OpenSSH
 *
 * This shared library implements the OpenSSH SK (Security Key) middleware API,
 * bridging OpenSSH to YubiKey hardware tokens via libfido2.
 *
 * Usage: SSH_SK_PROVIDER=/path/to/libyubikey-sk.dylib ssh ...
 */

#include <stdlib.h>
#include <string.h>

#include <fido.h>
#include <fido/credman.h>
#include <fido/es256.h>
#include <fido/eddsa.h>

#include <openssl/bn.h>
#include <openssl/ecdsa.h>

#include "sk-api.h"

#define MAX_FIDO_DEVICES	64
#define SHA256_DIGEST_LEN	32
#define ES256_RAW_KEY_LEN	64	/* x || y affine coordinates */
#define ED25519_KEY_LEN		32
#define ED25519_SIG_LEN		64
#define SEC1_UNCOMPRESSED_LEN	(1 + ES256_RAW_KEY_LEN)	/* 0x04 || x || y */
#define SEC1_UNCOMPRESSED_TAG	0x04

/* Like strdup(), but for arbitrary memory */
static void *
memdup(const void *src, size_t len)
{
	void *dst;
	if (src == NULL || len == 0)
		return NULL;
	dst = malloc(len);
	if (dst != NULL)
		memcpy(dst, src, len);
	return dst;
}

/* Find the first FIDO device available (for enroll/resident keys) */
static fido_dev_t *
open_first_device(void)
{
	fido_dev_info_t *devlist = NULL;
	const fido_dev_info_t *di;
	fido_dev_t *dev = NULL;
	size_t ndevs = 0;
	int r;

	devlist = fido_dev_info_new(MAX_FIDO_DEVICES);
	if (devlist == NULL)
		goto out;
	r = fido_dev_info_manifest(devlist, MAX_FIDO_DEVICES, &ndevs);
	if (r != FIDO_OK)
		goto out;
	if (ndevs == 0)
		goto out;
	/* Use the first device */
	di = fido_dev_info_ptr(devlist, 0);
	if (di == NULL)
		goto out;
	dev = fido_dev_new();
	if (dev == NULL)
		goto out;
	r = fido_dev_open(dev, fido_dev_info_path(di));
	if (r != FIDO_OK) {
		fido_dev_free(&dev);
		dev = NULL;
		goto out;
	}
out:
	fido_dev_info_free(&devlist, MAX_FIDO_DEVICES);
	return dev;
}

/*
 * Test if a device holds the specified credential by attempting a
 * silent assertion (no user presence required).
 */
static int
try_device(fido_dev_t *dev, const uint8_t *message, size_t message_len,
    const char *application, const uint8_t *key_handle, size_t key_handle_len)
{
	fido_assert_t *assert = NULL;
	int r = FIDO_ERR_INTERNAL;

	assert = fido_assert_new();
	if (assert == NULL)
		goto out;
	r = fido_assert_set_clientdata_hash(assert, message, message_len);
	if (r != FIDO_OK)
		goto out;
	r = fido_assert_set_rp(assert, application);
	if (r != FIDO_OK)
		goto out;
	r = fido_assert_allow_cred(assert, key_handle, key_handle_len);
	if (r != FIDO_OK)
		goto out;
	r = fido_assert_set_up(assert, FIDO_OPT_FALSE);
	if (r != FIDO_OK)
		goto out;
	r = fido_dev_get_assert(dev, assert, NULL);
	if (r == FIDO_ERR_USER_PRESENCE_REQUIRED)
		r = FIDO_OK;
out:
	fido_assert_free(&assert);
	return r != FIDO_OK ? -1 : 0;
}

/*
 * Iterate over all FIDO devices looking for the one holding the
 * specified credential. Uses a dummy hash for the probe.
 */
static fido_dev_t *
find_device_for_cred(const uint8_t *message, size_t message_len,
    const char *application, const uint8_t *key_handle, size_t key_handle_len)
{
	fido_dev_info_t *devlist = NULL;
	fido_dev_t *dev = NULL;
	size_t ndevs = 0;
	int r;

	devlist = fido_dev_info_new(MAX_FIDO_DEVICES);
	if (devlist == NULL)
		goto out;
	r = fido_dev_info_manifest(devlist, MAX_FIDO_DEVICES, &ndevs);
	if (r != FIDO_OK)
		goto out;
	if (ndevs == 0)
		goto out;
	for (size_t i = 0; i < ndevs; i++) {
		const fido_dev_info_t *di = fido_dev_info_ptr(devlist, i);
		const char *path;
		if (di == NULL)
			continue;
		path = fido_dev_info_path(di);
		if (path == NULL)
			continue;
		dev = fido_dev_new();
		if (dev == NULL)
			continue;
		r = fido_dev_open(dev, path);
		if (r != FIDO_OK) {
			fido_dev_free(&dev);
			dev = NULL;
			continue;
		}
		if (try_device(dev, message, message_len,
		    application, key_handle, key_handle_len) == 0)
			break;
		fido_dev_close(dev);
		fido_dev_free(&dev);
		dev = NULL;
	}
out:
	fido_dev_info_free(&devlist, MAX_FIDO_DEVICES);
	return dev;
}

/* Check for unsupported required options */
static int
check_options(struct sk_option **options)
{
	if (options == NULL)
		return 0;
	for (size_t i = 0; options[i] != NULL; i++) {
		if (options[i]->required)
			return -1;
	}
	return 0;
}

/* Map SSH SK algorithm to COSE algorithm (-1 if unsupported) */
static int
ssh_to_cose_alg(uint32_t alg)
{
	switch (alg) {
	case SSH_SK_ECDSA:
		return COSE_ES256;
	case SSH_SK_ED25519:
		return COSE_EDDSA;
	default:
		return -1;
	}
}

/*
 * The key returned via fido_cred_pubkey_ptr() for ES256 is in affine
 * coordinates (x || y), but OpenSSH expects SEC1 uncompressed point
 * format (0x04 || x || y). Just prepend the format byte.
 */
static int
pack_public_key_ecdsa(const fido_cred_t *cred, struct sk_enroll_response *resp)
{
	const uint8_t *ptr;

	ptr = fido_cred_pubkey_ptr(cred);
	if (ptr == NULL)
		return -1;
	if (fido_cred_pubkey_len(cred) != ES256_RAW_KEY_LEN)
		return -1;
	resp->public_key = malloc(SEC1_UNCOMPRESSED_LEN);
	if (resp->public_key == NULL)
		return -1;
	resp->public_key[0] = SEC1_UNCOMPRESSED_TAG;
	memcpy(resp->public_key + 1, ptr, ES256_RAW_KEY_LEN);
	resp->public_key_len = SEC1_UNCOMPRESSED_LEN;
	return 0;
}

static int
pack_public_key_ed25519(const fido_cred_t *cred, struct sk_enroll_response *resp)
{
	const uint8_t *ptr;
	size_t len;

	len = fido_cred_pubkey_len(cred);
	if (len != ED25519_KEY_LEN)
		return -1;
	ptr = fido_cred_pubkey_ptr(cred);
	if (ptr == NULL)
		return -1;
	resp->public_key = memdup(ptr, len);
	if (resp->public_key == NULL)
		return -1;
	resp->public_key_len = len;
	return 0;
}

static int
pack_public_key(uint32_t alg, const fido_cred_t *cred,
    struct sk_enroll_response *resp)
{
	switch (alg) {
	case SSH_SK_ECDSA:
		return pack_public_key_ecdsa(cred, resp);
	case SSH_SK_ED25519:
		return pack_public_key_ed25519(cred, resp);
	default:
		return -1;
	}
}

/* --- Public API --- */

uint32_t
sk_api_version(void)
{
	return SSH_SK_VERSION_MAJOR;
}

int
sk_enroll(uint32_t alg, const uint8_t *challenge, size_t challenge_len,
		const char *application, uint8_t flags, const char *pin,
		struct sk_option **options, struct sk_enroll_response **enroll_response)
{
	fido_dev_t *dev = NULL;
	fido_cred_t *cred = NULL;
	struct sk_enroll_response *resp = NULL;
	const uint8_t *id, *authdata, *sig, *x509;
	size_t id_len, authdata_len, sig_len, x509_len;
	int cose_alg;
	int r, ret = SSH_SK_ERR_GENERAL;

	if (enroll_response == NULL)
		return SSH_SK_ERR_GENERAL;
	if (check_options(options) != 0)
		return SSH_SK_ERR_UNSUPPORTED;
	*enroll_response = NULL;
	cose_alg = ssh_to_cose_alg(alg);
	if (cose_alg == -1)
		return SSH_SK_ERR_UNSUPPORTED;
	dev = open_first_device();
	if (dev == NULL)
		return SSH_SK_ERR_DEVICE_NOT_FOUND;
	cred = fido_cred_new();
	if (cred == NULL)
		goto out;
	r = fido_cred_set_type(cred, cose_alg);
	if (r != FIDO_OK)
		goto out;
	/* Apple's OpenSSH passes raw challenge; upstream passes a hash */
	if (challenge_len == SHA256_DIGEST_LEN)
		r = fido_cred_set_clientdata_hash(cred, challenge, challenge_len);
	else
		r = fido_cred_set_clientdata(cred, challenge, challenge_len);
	if (r != FIDO_OK)
		goto out;
	r = fido_cred_set_rp(cred, application, NULL);
	if (r != FIDO_OK)
		goto out;
	/* Set user info for resident keys */
	r = fido_cred_set_user(cred,
		(const unsigned char *)"\0", 1,
		"openssh", NULL, NULL);
	if (r != FIDO_OK)
		goto out;
	/* Set options based on flags */
	if (flags & SSH_SK_RESIDENT_KEY) {
		r = fido_cred_set_rk(cred, FIDO_OPT_TRUE);
		if (r != FIDO_OK)
			goto out;
	}
	if (flags & SSH_SK_USER_VERIFICATION_REQD) {
		r = fido_cred_set_uv(cred, FIDO_OPT_TRUE);
		if (r != FIDO_OK)
			goto out;
	}
	/* Perform the enrollment */
	r = fido_dev_make_cred(dev, cred, pin);
	if (r != FIDO_OK) {
		if (r == FIDO_ERR_PIN_REQUIRED ||
				r == FIDO_ERR_UV_BLOCKED ||
				r == FIDO_ERR_PIN_INVALID)
			ret = SSH_SK_ERR_PIN_REQUIRED;
		goto out;
	}
	/* Verify the credential attestation */
	if (fido_cred_x5c_ptr(cred) != NULL) {
		r = fido_cred_verify(cred);
		if (r != FIDO_OK)
			goto out;
	} else {
		r = fido_cred_verify_self(cred);
		if (r != FIDO_OK)
			goto out;
	}
	/* Allocate response */
	resp = calloc(1, sizeof(*resp));
	if (resp == NULL)
		goto out;
	/* Extract public key */
	if (pack_public_key(alg, cred, resp) != 0)
		goto out;
	/* Extract key handle (credential ID) */
	id = fido_cred_id_ptr(cred);
	id_len = fido_cred_id_len(cred);
	if (id == NULL || id_len == 0)
		goto out;
	resp->key_handle = memdup(id, id_len);
	if (resp->key_handle == NULL)
		goto out;
	resp->key_handle_len = id_len;
	/* Extract signature */
	sig = fido_cred_sig_ptr(cred);
	sig_len = fido_cred_sig_len(cred);
	if (sig != NULL && sig_len > 0) {
		resp->signature = memdup(sig, sig_len);
		if (resp->signature == NULL)
			goto out;
		resp->signature_len = sig_len;
	}
	/* Extract attestation certificate */
	x509 = fido_cred_x5c_ptr(cred);
	x509_len = fido_cred_x5c_len(cred);
	if (x509 != NULL && x509_len > 0) {
		resp->attestation_cert = memdup(x509, x509_len);
		if (resp->attestation_cert == NULL)
			goto out;
		resp->attestation_cert_len = x509_len;
	}
	/* Extract authdata */
	authdata = fido_cred_authdata_ptr(cred);
	authdata_len = fido_cred_authdata_len(cred);
	if (authdata != NULL && authdata_len > 0) {
		resp->authdata = memdup(authdata, authdata_len);
		if (resp->authdata == NULL)
			goto out;
		resp->authdata_len = authdata_len;
	}
	resp->flags = flags;
	*enroll_response = resp;
	resp = NULL;
	ret = 0;
out:
	if (resp != NULL) {
		free(resp->public_key);
		free(resp->key_handle);
		free(resp->signature);
		free(resp->attestation_cert);
		free(resp->authdata);
		free(resp);
	}
	fido_cred_free(&cred);
	if (dev != NULL) {
		fido_dev_close(dev);
		fido_dev_free(&dev);
	}
	return ret;
}

int
sk_sign(uint32_t alg, const uint8_t *data, size_t data_len,
		const char *application, const uint8_t *key_handle, size_t key_handle_len,
		uint8_t flags, const char *pin, struct sk_option **options,
		struct sk_sign_response **sign_response)
{
	fido_dev_t *dev = NULL;
	fido_assert_t *assert = NULL;
	struct sk_sign_response *resp = NULL;
	const uint8_t *sig;
	size_t sig_len;
	int r, ret = SSH_SK_ERR_GENERAL;

	if (sign_response == NULL)
		return SSH_SK_ERR_GENERAL;
	if (check_options(options) != 0)
		return SSH_SK_ERR_UNSUPPORTED;
	*sign_response = NULL;
	if (ssh_to_cose_alg(alg) == -1)
		return SSH_SK_ERR_UNSUPPORTED;
	/*
	 * Find the device holding this credential by probing all devices.
	 * Use a dummy hash for the probe (actual signing uses real data).
	 */
	{
		uint8_t dummy_hash[SHA256_DIGEST_LEN] = {0};
		dev = find_device_for_cred(dummy_hash, sizeof(dummy_hash),
			application, key_handle, key_handle_len);
		if (dev == NULL)
			return SSH_SK_ERR_DEVICE_NOT_FOUND;
	}
	assert = fido_assert_new();
	if (assert == NULL)
		goto out;
	/* Apple's OpenSSH passes raw data; upstream passes a hash */
	if (data_len == SHA256_DIGEST_LEN)
		r = fido_assert_set_clientdata_hash(assert, data, data_len);
	else
		r = fido_assert_set_clientdata(assert, data, data_len);
	if (r != FIDO_OK)
		goto out;
	r = fido_assert_set_rp(assert, application);
	if (r != FIDO_OK)
		goto out;
	r = fido_assert_allow_cred(assert, key_handle, key_handle_len);
	if (r != FIDO_OK)
		goto out;
	/* Set UP (user presence) */
	r = fido_assert_set_up(assert, (flags & SSH_SK_USER_PRESENCE_REQD) ?
	    FIDO_OPT_TRUE : FIDO_OPT_FALSE);
	if (r != FIDO_OK)
		goto out;
	/* Set UV (user verification) */
	if (flags & SSH_SK_USER_VERIFICATION_REQD) {
		r = fido_assert_set_uv(assert, FIDO_OPT_TRUE);
		if (r != FIDO_OK)
			goto out;
	}
	/* Perform the assertion */
	r = fido_dev_get_assert(dev, assert, pin);
	if (r != FIDO_OK) {
		if (r == FIDO_ERR_PIN_REQUIRED ||
				r == FIDO_ERR_UV_BLOCKED ||
				r == FIDO_ERR_PIN_INVALID)
			ret = SSH_SK_ERR_PIN_REQUIRED;
		goto out;
	}
	if (fido_assert_count(assert) != 1)
		goto out;
	/* Allocate response */
	resp = calloc(1, sizeof(*resp));
	if (resp == NULL)
		goto out;
	resp->flags = fido_assert_flags(assert, 0);
	resp->counter = fido_assert_sigcount(assert, 0);
	/* Extract signature - format depends on algorithm */
	sig = fido_assert_sig_ptr(assert, 0);
	sig_len = fido_assert_sig_len(assert, 0);
	if (sig == NULL || sig_len == 0)
		goto out;
	if (alg == SSH_SK_ECDSA) {
		/*
		 * For ECDSA, the signature is DER-encoded. Use OpenSSL to
		 * parse it properly and extract r, s as big-endian integers.
		 */
		ECDSA_SIG *esig;
		const BIGNUM *sig_r, *sig_s;
		const unsigned char *cp = sig;

		esig = d2i_ECDSA_SIG(NULL, &cp, (long)sig_len);
		if (esig == NULL)
			goto out;
		ECDSA_SIG_get0(esig, &sig_r, &sig_s);
		resp->sig_r_len = BN_num_bytes(sig_r);
		resp->sig_s_len = BN_num_bytes(sig_s);
		resp->sig_r = calloc(1, resp->sig_r_len);
		resp->sig_s = calloc(1, resp->sig_s_len);
		if (resp->sig_r == NULL || resp->sig_s == NULL) {
			ECDSA_SIG_free(esig);
			goto out;
		}
		BN_bn2bin(sig_r, resp->sig_r);
		BN_bn2bin(sig_s, resp->sig_s);
		ECDSA_SIG_free(esig);
	} else if (alg == SSH_SK_ED25519) {
		/* ED25519 signature is raw, store in sig_r */
		if (sig_len != ED25519_SIG_LEN)
			goto out;
		resp->sig_r = calloc(1, sig_len);
		if (resp->sig_r == NULL)
			goto out;
		memcpy(resp->sig_r, sig, sig_len);
		resp->sig_r_len = sig_len;
		resp->sig_s = NULL;
		resp->sig_s_len = 0;
	}
	*sign_response = resp;
	resp = NULL;
	ret = 0;
out:
	if (resp != NULL) {
		free(resp->sig_r);
		free(resp->sig_s);
		free(resp);
	}
	fido_assert_free(&assert);
	if (dev != NULL) {
		fido_dev_close(dev);
		fido_dev_free(&dev);
	}
	return ret;
}

int
sk_load_resident_keys(const char *pin, struct sk_option **options,
		struct sk_resident_key ***rks, size_t *nrks)
{
	fido_dev_t *dev = NULL;
	fido_credman_metadata_t *metadata = NULL;
	fido_credman_rp_t *rp = NULL;
	fido_credman_rk_t *rk = NULL;
	struct sk_resident_key **keys = NULL;
	size_t nkeys = 0;
	int r, ret = SSH_SK_ERR_GENERAL;

	if (rks == NULL || nrks == NULL)
		return SSH_SK_ERR_GENERAL;
	if (check_options(options) != 0)
		return SSH_SK_ERR_UNSUPPORTED;
	*rks = NULL;
	*nrks = 0;
	dev = open_first_device();
	if (dev == NULL)
		return SSH_SK_ERR_DEVICE_NOT_FOUND;
	if (pin == NULL) {
		ret = SSH_SK_ERR_PIN_REQUIRED;
		goto out;
	}
	/* Get credential metadata */
	metadata = fido_credman_metadata_new();
	if (metadata == NULL)
		goto out;
	r = fido_credman_get_dev_metadata(dev, metadata, pin);
	if (r != FIDO_OK) {
		if (r == FIDO_ERR_PIN_REQUIRED || r == FIDO_ERR_PIN_INVALID)
			ret = SSH_SK_ERR_PIN_REQUIRED;
		goto out;
	}
	/* Enumerate RPs */
	rp = fido_credman_rp_new();
	if (rp == NULL)
		goto out;
	r = fido_credman_get_dev_rp(dev, rp, pin);
	if (r != FIDO_OK)
		goto out;
	/* Iterate over RPs and their credentials */
	for (size_t i = 0; i < fido_credman_rp_count(rp); i++) {
		const char *rp_id = fido_credman_rp_id(rp, i);
		if (rp_id == NULL)
			continue;
		/* Filter to ssh: prefixed RPs only */
		if (strncmp(rp_id, "ssh:", 4) != 0)
			continue;
		rk = fido_credman_rk_new();
		if (rk == NULL)
			goto out;
		r = fido_credman_get_dev_rk(dev, rp_id, rk, pin);
		if (r != FIDO_OK) {
			fido_credman_rk_free(&rk);
			continue;
		}
		for (size_t j = 0; j < fido_credman_rk_count(rk); j++) {
			const fido_cred_t *cred = fido_credman_rk(rk, j);
			if (cred == NULL)
				continue;
			int cred_type = fido_cred_type(cred);
			uint32_t ssh_alg;
			if (cred_type == COSE_ES256)
				ssh_alg = SSH_SK_ECDSA;
			else if (cred_type == COSE_EDDSA)
				ssh_alg = SSH_SK_ED25519;
			else
				continue;
			/* Grow keys array */
			struct sk_resident_key **tmp;
			tmp = realloc(keys, (nkeys + 1) * sizeof(*keys));
			if (tmp == NULL)
				goto out;
			keys = tmp;
			struct sk_resident_key *srk = calloc(1, sizeof(*srk));
			if (srk == NULL)
				goto out;
			srk->alg = ssh_alg;
			srk->slot = nkeys;
			srk->flags = 0;
			srk->application = strdup(rp_id);
			if (srk->application == NULL) {
				free(srk);
				goto out;
			}
			/* Pack public key in the format OpenSSH expects */
			if (pack_public_key(ssh_alg, cred, &srk->key) != 0) {
				free(srk->application);
				free(srk);
				continue;
			}
			/* Copy key handle (credential ID) */
			const uint8_t *id = fido_cred_id_ptr(cred);
			size_t id_len = fido_cred_id_len(cred);
			if (id != NULL && id_len > 0) {
				srk->key.key_handle = memdup(id, id_len);
				if (srk->key.key_handle == NULL) {
					free(srk->key.public_key);
					free(srk->application);
					free(srk);
					goto out;
				}
				srk->key.key_handle_len = id_len;
			}
			/* Copy user ID */
			const uint8_t *uid = fido_cred_user_id_ptr(cred);
			size_t uid_len = fido_cred_user_id_len(cred);
			if (uid != NULL && uid_len > 0) {
				srk->user_id = memdup(uid, uid_len);
				if (srk->user_id == NULL) {
					free(srk->key.key_handle);
					free(srk->key.public_key);
					free(srk->application);
					free(srk);
					goto out;
				}
				srk->user_id_len = uid_len;
			}
			keys[nkeys++] = srk;
		}
		fido_credman_rk_free(&rk);
		rk = NULL;
	}
	*rks = keys;
	*nrks = nkeys;
	keys = NULL;
	ret = 0;
out:
	if (keys != NULL) {
		for (size_t i = 0; i < nkeys; i++) {
			if (keys[i] != NULL) {
				free(keys[i]->application);
				free(keys[i]->key.public_key);
				free(keys[i]->key.key_handle);
				free(keys[i]->key.signature);
				free(keys[i]->key.attestation_cert);
				free(keys[i]->key.authdata);
				free(keys[i]->user_id);
				free(keys[i]);
			}
		}
		free(keys);
	}
	fido_credman_rk_free(&rk);
	fido_credman_rp_free(&rp);
	fido_credman_metadata_free(&metadata);
	if (dev != NULL) {
		fido_dev_close(dev);
		fido_dev_free(&dev);
	}
	return ret;
}
