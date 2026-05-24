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
#include <stdio.h>

#include <fido.h>
#include <fido/credman.h>
#include <fido/es256.h>
#include <fido/eddsa.h>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>

#include "sk-api.h"

/* Debug logging - set YUBIKEY_SK_DEBUG=1 to enable */
#ifdef DEBUG
#define skdebug(func, fmt, ...) \
	fprintf(stderr, "yubikey-sk %s: " fmt "\n", func, ##__VA_ARGS__)
#else
#define skdebug(func, fmt, ...) do { \
	if (getenv("YUBIKEY_SK_DEBUG") != NULL) \
		fprintf(stderr, "yubikey-sk %s: " fmt "\n", func, ##__VA_ARGS__); \
} while(0)
#endif

#define MAX_FIDO_DEVICES 64

/* Find the first FIDO device available (for enroll/resident keys) */
static fido_dev_t *
open_first_device(void)
{
	fido_dev_info_t *devlist = NULL;
	const fido_dev_info_t *di;
	fido_dev_t *dev = NULL;
	size_t ndevs = 0;
	int r;

	if ((devlist = fido_dev_info_new(MAX_FIDO_DEVICES)) == NULL) {
		skdebug(__func__, "fido_dev_info_new failed");
		goto out;
	}
	if ((r = fido_dev_info_manifest(devlist, MAX_FIDO_DEVICES, &ndevs)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_info_manifest: %s", fido_strerr(r));
		goto out;
	}
	if (ndevs == 0) {
		skdebug(__func__, "no FIDO devices found");
		goto out;
	}

	skdebug(__func__, "found %zu FIDO device(s)", ndevs);

	/* Use the first device */
	if ((di = fido_dev_info_ptr(devlist, 0)) == NULL) {
		skdebug(__func__, "fido_dev_info_ptr failed");
		goto out;
	}

	skdebug(__func__, "using device: %s", fido_dev_info_path(di));

	if ((dev = fido_dev_new()) == NULL) {
		skdebug(__func__, "fido_dev_new failed");
		goto out;
	}
	if ((r = fido_dev_open(dev, fido_dev_info_path(di))) != FIDO_OK) {
		skdebug(__func__, "fido_dev_open: %s", fido_strerr(r));
		fido_dev_free(&dev);
		dev = NULL;
		goto out;
	}

out:
	fido_dev_info_free(&devlist, ndevs);
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

	if ((assert = fido_assert_new()) == NULL) {
		skdebug(__func__, "fido_assert_new failed");
		goto out;
	}
	if ((r = fido_assert_set_clientdata_hash(assert, message,
	    message_len)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_clientdata_hash: %s",
		    fido_strerr(r));
		goto out;
	}
	if ((r = fido_assert_set_rp(assert, application)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_rp: %s", fido_strerr(r));
		goto out;
	}
	if ((r = fido_assert_allow_cred(assert, key_handle,
	    key_handle_len)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_allow_cred: %s",
		    fido_strerr(r));
		goto out;
	}
	if ((r = fido_assert_set_up(assert, FIDO_OPT_FALSE)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_up: %s", fido_strerr(r));
		goto out;
	}
	r = fido_dev_get_assert(dev, assert, NULL);
	skdebug(__func__, "fido_dev_get_assert: %s", fido_strerr(r));
	if (r == FIDO_ERR_USER_PRESENCE_REQUIRED) {
		/* U2F tokens may return this */
		r = FIDO_OK;
	}
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

	if ((devlist = fido_dev_info_new(MAX_FIDO_DEVICES)) == NULL) {
		skdebug(__func__, "fido_dev_info_new failed");
		goto out;
	}
	if ((r = fido_dev_info_manifest(devlist, MAX_FIDO_DEVICES, &ndevs)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_info_manifest: %s", fido_strerr(r));
		goto out;
	}
	if (ndevs == 0) {
		skdebug(__func__, "no FIDO devices found");
		goto out;
	}

	skdebug(__func__, "found %zu device(s)", ndevs);

	for (size_t i = 0; i < ndevs; i++) {
		const fido_dev_info_t *di = fido_dev_info_ptr(devlist, i);
		const char *path;

		if (di == NULL)
			continue;
		if ((path = fido_dev_info_path(di)) == NULL)
			continue;

		skdebug(__func__, "trying device %zu: %s", i, path);

		if ((dev = fido_dev_new()) == NULL) {
			skdebug(__func__, "fido_dev_new failed");
			continue;
		}
		if ((r = fido_dev_open(dev, path)) != FIDO_OK) {
			skdebug(__func__, "fido_dev_open: %s", fido_strerr(r));
			fido_dev_free(&dev);
			dev = NULL;
			continue;
		}
		if (try_device(dev, message, message_len,
		    application, key_handle, key_handle_len) == 0) {
			skdebug(__func__, "found key on device %s", path);
			break;
		}
		fido_dev_close(dev);
		fido_dev_free(&dev);
		dev = NULL;
	}

out:
	fido_dev_info_free(&devlist, ndevs);
	return dev;
}

/* Check for unsupported required options */
static int
check_options(struct sk_option **options)
{
	if (options == NULL)
		return 0;
	for (size_t i = 0; options[i] != NULL; i++) {
		if (options[i]->required) {
			skdebug(__func__, "unsupported required option: %s",
			    options[i]->name);
			return -1;
		}
	}
	return 0;
}

/* Check if a device supports the given algorithm */
static int
check_alg_support(uint32_t alg)
{
	switch (alg) {
	case SSH_SK_ECDSA:
	case SSH_SK_ED25519:
		return 0;
	default:
		return -1;
	}
}

/* Map SSH SK algorithm to COSE algorithm */
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
 * coordinates (64 bytes: x || y), but OpenSSH expects SEC1 uncompressed
 * point format (65 bytes: 0x04 || x || y).
 */
static int
pack_public_key_ecdsa(const fido_cred_t *cred, struct sk_enroll_response *resp)
{
	const uint8_t *ptr;
	BIGNUM *x = NULL, *y = NULL;
	EC_POINT *q = NULL;
	EC_GROUP *g = NULL;
	int ret = -1;

	resp->public_key = NULL;
	resp->public_key_len = 0;

	if ((ptr = fido_cred_pubkey_ptr(cred)) == NULL) {
		skdebug(__func__, "fido_cred_pubkey_ptr failed");
		goto out;
	}
	if (fido_cred_pubkey_len(cred) != 64) {
		skdebug(__func__, "bad fido_cred_pubkey_len %zu",
		    fido_cred_pubkey_len(cred));
		goto out;
	}

	if ((x = BN_new()) == NULL ||
	    (y = BN_new()) == NULL ||
	    (g = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1)) == NULL ||
	    (q = EC_POINT_new(g)) == NULL) {
		skdebug(__func__, "libcrypto setup failed");
		goto out;
	}
	if (BN_bin2bn(ptr, 32, x) == NULL ||
	    BN_bin2bn(ptr + 32, 32, y) == NULL) {
		skdebug(__func__, "BN_bin2bn failed");
		goto out;
	}
	if (EC_POINT_set_affine_coordinates(g, q, x, y, NULL) != 1) {
		skdebug(__func__, "EC_POINT_set_affine_coordinates failed");
		goto out;
	}
	resp->public_key_len = EC_POINT_point2oct(g, q,
	    POINT_CONVERSION_UNCOMPRESSED, NULL, 0, NULL);
	if (resp->public_key_len == 0 || resp->public_key_len > 2048) {
		skdebug(__func__, "bad pubkey length %zu", resp->public_key_len);
		goto out;
	}
	if ((resp->public_key = malloc(resp->public_key_len)) == NULL) {
		skdebug(__func__, "malloc pubkey failed");
		goto out;
	}
	if (EC_POINT_point2oct(g, q, POINT_CONVERSION_UNCOMPRESSED,
	    resp->public_key, resp->public_key_len, NULL) == 0) {
		skdebug(__func__, "EC_POINT_point2oct failed");
		goto out;
	}
	ret = 0;
out:
	if (ret != 0) {
		free(resp->public_key);
		resp->public_key = NULL;
		resp->public_key_len = 0;
	}
	EC_POINT_free(q);
	EC_GROUP_free(g);
	BN_clear_free(x);
	BN_clear_free(y);
	return ret;
}

static int
pack_public_key_ed25519(const fido_cred_t *cred, struct sk_enroll_response *resp)
{
	const uint8_t *ptr;
	size_t len;

	if ((len = fido_cred_pubkey_len(cred)) != 32) {
		skdebug(__func__, "bad fido_cred_pubkey_len %zu", len);
		return -1;
	}
	if ((ptr = fido_cred_pubkey_ptr(cred)) == NULL) {
		skdebug(__func__, "fido_cred_pubkey_ptr failed");
		return -1;
	}
	if ((resp->public_key = malloc(len)) == NULL) {
		skdebug(__func__, "malloc pubkey failed");
		return -1;
	}
	memcpy(resp->public_key, ptr, len);
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

	skdebug(__func__, "enroll alg=%u application=%s flags=0x%02x",
	    alg, application ? application : "(null)", flags);

	if (enroll_response == NULL) {
		skdebug(__func__, "enroll_response is NULL");
		return SSH_SK_ERR_GENERAL;
	}

	if (check_options(options) != 0)
		return SSH_SK_ERR_UNSUPPORTED;
	*enroll_response = NULL;

	if (check_alg_support(alg) != 0) {
		skdebug(__func__, "unsupported algorithm %u", alg);
		return SSH_SK_ERR_UNSUPPORTED;
	}

	if ((cose_alg = ssh_to_cose_alg(alg)) == -1) {
		skdebug(__func__, "failed to map algorithm");
		return SSH_SK_ERR_UNSUPPORTED;
	}

	if ((dev = open_first_device()) == NULL) {
		skdebug(__func__, "failed to open device");
		return SSH_SK_ERR_DEVICE_NOT_FOUND;
	}

	if ((cred = fido_cred_new()) == NULL) {
		skdebug(__func__, "fido_cred_new failed");
		goto out;
	}

	if ((r = fido_cred_set_type(cred, cose_alg)) != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_type: %s", fido_strerr(r));
		goto out;
	}
	/* Apple's OpenSSH passes raw challenge; upstream passes a 32-byte hash */
	if (challenge_len == 32) {
		r = fido_cred_set_clientdata_hash(cred, challenge, challenge_len);
	} else {
		skdebug(__func__, "hashing %zu bytes of challenge", challenge_len);
		r = fido_cred_set_clientdata(cred, challenge, challenge_len);
	}
	if (r != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_clientdata: %s", fido_strerr(r));
		goto out;
	}
	if ((r = fido_cred_set_rp(cred, application, NULL)) != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_rp: %s", fido_strerr(r));
		goto out;
	}

	/* Set user info for resident keys */
	if ((r = fido_cred_set_user(cred,
	    (const unsigned char *)"\0", 1, /* user id */
	    "openssh", /* user name */
	    NULL, /* display name */
	    NULL)) != FIDO_OK) { /* icon */
		skdebug(__func__, "fido_cred_set_user: %s", fido_strerr(r));
		goto out;
	}

	/* Set options based on flags */
	if (flags & SSH_SK_RESIDENT_KEY) {
		if ((r = fido_cred_set_rk(cred, FIDO_OPT_TRUE)) != FIDO_OK) {
			skdebug(__func__, "fido_cred_set_rk: %s", fido_strerr(r));
			goto out;
		}
	}
	if (flags & SSH_SK_USER_VERIFICATION_REQD) {
		if ((r = fido_cred_set_uv(cred, FIDO_OPT_TRUE)) != FIDO_OK) {
			skdebug(__func__, "fido_cred_set_uv: %s", fido_strerr(r));
			goto out;
		}
	}

	/* Perform the enrollment */
	if ((r = fido_dev_make_cred(dev, cred, pin)) != FIDO_OK) {
		if (r == FIDO_ERR_PIN_REQUIRED ||
		    r == FIDO_ERR_UV_BLOCKED ||
		    r == FIDO_ERR_PIN_INVALID) {
			skdebug(__func__, "PIN required: %s", fido_strerr(r));
			ret = SSH_SK_ERR_PIN_REQUIRED;
			goto out;
		}
		skdebug(__func__, "fido_dev_make_credential: %s", fido_strerr(r));
		goto out;
	}

	/* Verify the credential attestation */
	if (fido_cred_x5c_ptr(cred) != NULL) {
		if ((r = fido_cred_verify(cred)) != FIDO_OK) {
			skdebug(__func__, "fido_cred_verify: %s", fido_strerr(r));
			goto out;
		}
	} else {
		skdebug(__func__, "self-attested credential");
		if ((r = fido_cred_verify_self(cred)) != FIDO_OK) {
			skdebug(__func__, "fido_cred_verify_self: %s",
			    fido_strerr(r));
			goto out;
		}
	}

	/* Allocate response */
	if ((resp = calloc(1, sizeof(*resp))) == NULL) {
		skdebug(__func__, "calloc response failed");
		goto out;
	}

	/* Extract public key */
	if (pack_public_key(alg, cred, resp) != 0)
		goto out;

	/* Extract key handle (credential ID) */
	if ((id = fido_cred_id_ptr(cred)) == NULL ||
	    (id_len = fido_cred_id_len(cred)) == 0) {
		skdebug(__func__, "fido_cred_id failed");
		goto out;
	}
	if ((resp->key_handle = malloc(id_len)) == NULL) {
		skdebug(__func__, "malloc key_handle failed");
		goto out;
	}
	memcpy(resp->key_handle, id, id_len);
	resp->key_handle_len = id_len;

	/* Extract signature */
	if ((sig = fido_cred_sig_ptr(cred)) != NULL &&
	    (sig_len = fido_cred_sig_len(cred)) > 0) {
		if ((resp->signature = malloc(sig_len)) == NULL) {
			skdebug(__func__, "malloc signature failed");
			goto out;
		}
		memcpy(resp->signature, sig, sig_len);
		resp->signature_len = sig_len;
	}

	/* Extract attestation certificate */
	if ((x509 = fido_cred_x5c_ptr(cred)) != NULL &&
	    (x509_len = fido_cred_x5c_len(cred)) > 0) {
		if ((resp->attestation_cert = malloc(x509_len)) == NULL) {
			skdebug(__func__, "malloc attestation_cert failed");
			goto out;
		}
		memcpy(resp->attestation_cert, x509, x509_len);
		resp->attestation_cert_len = x509_len;
	}

	/* Extract authdata */
	if ((authdata = fido_cred_authdata_ptr(cred)) != NULL &&
	    (authdata_len = fido_cred_authdata_len(cred)) > 0) {
		if ((resp->authdata = malloc(authdata_len)) == NULL) {
			skdebug(__func__, "malloc authdata failed");
			goto out;
		}
		memcpy(resp->authdata, authdata, authdata_len);
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

	skdebug(__func__, "sign alg=%u application=%s flags=0x%02x",
	    alg, application ? application : "(null)", flags);
	skdebug(__func__, "data_len=%zu key_handle_len=%zu",
	    data_len, key_handle_len);

	if (sign_response == NULL) {
		skdebug(__func__, "sign_response is NULL");
		return SSH_SK_ERR_GENERAL;
	}

	if (check_options(options) != 0)
		return SSH_SK_ERR_UNSUPPORTED;
	*sign_response = NULL;

	if (check_alg_support(alg) != 0) {
		skdebug(__func__, "unsupported algorithm %u", alg);
		return SSH_SK_ERR_UNSUPPORTED;
	}

	/*
	 * Find the device holding this credential by probing all devices.
	 * Use a dummy 32-byte hash for the probe (actual signing uses real data).
	 */
	{
		uint8_t dummy_hash[32];
		memset(dummy_hash, 0, sizeof(dummy_hash));
		dev = find_device_for_cred(dummy_hash, sizeof(dummy_hash),
		    application, key_handle, key_handle_len);
	}
	if (dev == NULL) {
		skdebug(__func__, "failed to find device for credential");
		return SSH_SK_ERR_DEVICE_NOT_FOUND;
	}

	if ((assert = fido_assert_new()) == NULL) {
		skdebug(__func__, "fido_assert_new failed");
		goto out;
	}

	/* Apple's OpenSSH passes raw data; upstream passes a 32-byte hash */
	if (data_len == 32) {
		r = fido_assert_set_clientdata_hash(assert, data, data_len);
	} else {
		skdebug(__func__, "hashing %zu bytes of client data", data_len);
		r = fido_assert_set_clientdata(assert, data, data_len);
	}
	if (r != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_clientdata: %s", fido_strerr(r));
		goto out;
	}
	if ((r = fido_assert_set_rp(assert, application)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_rp: %s", fido_strerr(r));
		goto out;
	}
	if ((r = fido_assert_allow_cred(assert, key_handle, key_handle_len)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_allow_cred: %s", fido_strerr(r));
		goto out;
	}

	/* Set UP (user presence) */
	if (flags & SSH_SK_USER_PRESENCE_REQD) {
		if ((r = fido_assert_set_up(assert, FIDO_OPT_TRUE)) != FIDO_OK) {
			skdebug(__func__, "fido_assert_set_up: %s", fido_strerr(r));
			goto out;
		}
	} else {
		if ((r = fido_assert_set_up(assert, FIDO_OPT_FALSE)) != FIDO_OK) {
			skdebug(__func__, "fido_assert_set_up: %s", fido_strerr(r));
			goto out;
		}
	}

	/* Set UV (user verification) */
	if (flags & SSH_SK_USER_VERIFICATION_REQD) {
		if ((r = fido_assert_set_uv(assert, FIDO_OPT_TRUE)) != FIDO_OK) {
			skdebug(__func__, "fido_assert_set_uv: %s", fido_strerr(r));
			goto out;
		}
	}

	/* Perform the assertion */
	if ((r = fido_dev_get_assert(dev, assert, pin)) != FIDO_OK) {
		if (r == FIDO_ERR_PIN_REQUIRED ||
		    r == FIDO_ERR_UV_BLOCKED ||
		    r == FIDO_ERR_PIN_INVALID) {
			skdebug(__func__, "PIN required: %s", fido_strerr(r));
			ret = SSH_SK_ERR_PIN_REQUIRED;
			goto out;
		}
		skdebug(__func__, "fido_dev_get_assert: %s", fido_strerr(r));
		goto out;
	}

	if (fido_assert_count(assert) != 1) {
		skdebug(__func__, "expected 1 assertion, got %zu",
		    fido_assert_count(assert));
		goto out;
	}

	/* Allocate response */
	if ((resp = calloc(1, sizeof(*resp))) == NULL) {
		skdebug(__func__, "calloc response failed");
		goto out;
	}

	resp->flags = fido_assert_flags(assert, 0);
	resp->counter = fido_assert_sigcount(assert, 0);

	/* Extract signature - format depends on algorithm */
	if ((sig = fido_assert_sig_ptr(assert, 0)) == NULL ||
	    (sig_len = fido_assert_sig_len(assert, 0)) == 0) {
		skdebug(__func__, "fido_assert_sig failed");
		goto out;
	}

	if (alg == SSH_SK_ECDSA) {
		/*
		 * For ECDSA, the signature is DER-encoded. Use OpenSSL to
		 * parse it properly and extract r, s as big-endian integers.
		 */
		ECDSA_SIG *esig = NULL;
		const BIGNUM *sig_r, *sig_s;
		const unsigned char *cp = sig;

		if ((esig = d2i_ECDSA_SIG(NULL, &cp, (long)sig_len)) == NULL) {
			skdebug(__func__, "d2i_ECDSA_SIG failed");
			goto out;
		}
		ECDSA_SIG_get0(esig, &sig_r, &sig_s);
		resp->sig_r_len = BN_num_bytes(sig_r);
		resp->sig_s_len = BN_num_bytes(sig_s);
		if ((resp->sig_r = calloc(1, resp->sig_r_len)) == NULL ||
		    (resp->sig_s = calloc(1, resp->sig_s_len)) == NULL) {
			skdebug(__func__, "calloc signature failed");
			ECDSA_SIG_free(esig);
			goto out;
		}
		BN_bn2bin(sig_r, resp->sig_r);
		BN_bn2bin(sig_s, resp->sig_s);
		ECDSA_SIG_free(esig);
	} else if (alg == SSH_SK_ED25519) {
		/* ED25519 signature is raw 64 bytes, store in sig_r */
		if (sig_len != 64) {
			skdebug(__func__, "bad ed25519 sig len %zu", sig_len);
			goto out;
		}
		if ((resp->sig_r = calloc(1, sig_len)) == NULL) {
			skdebug(__func__, "calloc sig_r failed");
			goto out;
		}
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

	skdebug(__func__, "loading resident keys");

	if (rks == NULL || nrks == NULL) {
		skdebug(__func__, "rks or nrks is NULL");
		return SSH_SK_ERR_GENERAL;
	}

	if (check_options(options) != 0)
		return SSH_SK_ERR_UNSUPPORTED;
	*rks = NULL;
	*nrks = 0;

	if ((dev = open_first_device()) == NULL) {
		skdebug(__func__, "failed to open device");
		return SSH_SK_ERR_DEVICE_NOT_FOUND;
	}

	if (pin == NULL) {
		skdebug(__func__, "PIN required for resident keys");
		ret = SSH_SK_ERR_PIN_REQUIRED;
		goto out;
	}

	/* Get credential metadata */
	if ((metadata = fido_credman_metadata_new()) == NULL) {
		skdebug(__func__, "fido_credman_metadata_new failed");
		goto out;
	}
	if ((r = fido_credman_get_dev_metadata(dev, metadata, pin)) != FIDO_OK) {
		if (r == FIDO_ERR_PIN_REQUIRED || r == FIDO_ERR_PIN_INVALID) {
			skdebug(__func__, "PIN error: %s", fido_strerr(r));
			ret = SSH_SK_ERR_PIN_REQUIRED;
			goto out;
		}
		skdebug(__func__, "fido_credman_get_dev_metadata: %s", fido_strerr(r));
		goto out;
	}

	skdebug(__func__, "device has %zu existing credential(s), %zu remaining slot(s)",
	    (size_t)fido_credman_rk_existing(metadata),
	    (size_t)fido_credman_rk_remaining(metadata));

	/* Enumerate RPs */
	if ((rp = fido_credman_rp_new()) == NULL) {
		skdebug(__func__, "fido_credman_rp_new failed");
		goto out;
	}
	if ((r = fido_credman_get_dev_rp(dev, rp, pin)) != FIDO_OK) {
		skdebug(__func__, "fido_credman_get_dev_rp: %s", fido_strerr(r));
		goto out;
	}

	/* Iterate over RPs and their credentials */
	for (size_t i = 0; i < fido_credman_rp_count(rp); i++) {
		const char *rp_id = fido_credman_rp_id(rp, i);
		if (rp_id == NULL)
			continue;

		skdebug(__func__, "RP[%zu]: %s", i, rp_id);

		/* Filter to ssh: prefixed RPs only */
		if (strncmp(rp_id, "ssh:", 4) != 0)
			continue;

		if ((rk = fido_credman_rk_new()) == NULL) {
			skdebug(__func__, "fido_credman_rk_new failed");
			goto out;
		}

		if ((r = fido_credman_get_dev_rk(dev, rp_id, rk, pin)) != FIDO_OK) {
			skdebug(__func__, "fido_credman_get_dev_rk: %s", fido_strerr(r));
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
			else {
				skdebug(__func__, "unsupported cred type %d", cred_type);
				continue;
			}

			/* Grow keys array */
			struct sk_resident_key **tmp = realloc(keys, (nkeys + 1) * sizeof(*keys));
			if (tmp == NULL) {
				skdebug(__func__, "reallocarray failed");
				goto out;
			}
			keys = tmp;

			struct sk_resident_key *srk = calloc(1, sizeof(*srk));
			if (srk == NULL) {
				skdebug(__func__, "calloc srk failed");
				goto out;
			}

			srk->alg = ssh_alg;
			srk->slot = nkeys;
			srk->flags = 0;

			if ((srk->application = strdup(rp_id)) == NULL) {
				free(srk);
				goto out;
			}

			/* Copy public key */
			const uint8_t *pk = fido_cred_pubkey_ptr(cred);
			size_t pk_len = fido_cred_pubkey_len(cred);
			if (pk != NULL && pk_len > 0) {
				if ((srk->key.public_key = malloc(pk_len)) == NULL) {
					free(srk->application);
					free(srk);
					goto out;
				}
				memcpy(srk->key.public_key, pk, pk_len);
				srk->key.public_key_len = pk_len;
			}

			/* Copy key handle (credential ID) */
			const uint8_t *id = fido_cred_id_ptr(cred);
			size_t id_len = fido_cred_id_len(cred);
			if (id != NULL && id_len > 0) {
				if ((srk->key.key_handle = malloc(id_len)) == NULL) {
					free(srk->key.public_key);
					free(srk->application);
					free(srk);
					goto out;
				}
				memcpy(srk->key.key_handle, id, id_len);
				srk->key.key_handle_len = id_len;
			}

			/* Copy user ID */
			const uint8_t *uid = fido_cred_user_id_ptr(cred);
			size_t uid_len = fido_cred_user_id_len(cred);
			if (uid != NULL && uid_len > 0) {
				if ((srk->user_id = malloc(uid_len)) == NULL) {
					free(srk->key.key_handle);
					free(srk->key.public_key);
					free(srk->application);
					free(srk);
					goto out;
				}
				memcpy(srk->user_id, uid, uid_len);
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
