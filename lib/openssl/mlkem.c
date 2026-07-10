/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */
/*
 * Copyright 2026 Red Hat, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "misc.h"
#include "../hooks.h"
#include <jose/b64.h>

#include <openssl/opensslv.h>

#if OPENSSL_VERSION_NUMBER >= 0x30500000L

#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <openssl/core_names.h>

#include <string.h>

#define NAMES "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"

/* ML-KEM parameter-set maxima: the ciphertext is 768, 1088, or 1568
 * bytes and the public key 800, 1184, or 1568 bytes for
 * ML-KEM-512/768/1024, and the shared secret is 32 bytes and the
 * seed 64 bytes for every parameter set. */
#define MLKEM_CT_LEN_512  768
#define MLKEM_CT_LEN_768  1088
#define MLKEM_CT_LEN_1024 1568
#define MLKEM_MAX_CT_LEN  MLKEM_CT_LEN_1024
#define MLKEM_MAX_PUB_LEN 1568
#define MLKEM_SS_LEN 32
#define MLKEM_SEED_LEN 64

/* Exact ciphertext length for the known parameter sets; SIZE_MAX for
 * any other algorithm. */
static size_t
kem_ct_len(const char *name)
{
    switch (str2enum(name, NAMES, NULL)) {
    case 0: return MLKEM_CT_LEN_512;
    case 1: return MLKEM_CT_LEN_768;
    case 2: return MLKEM_CT_LEN_1024;
    default: return SIZE_MAX;
    }
}

static bool
mlkem_available(const char *name)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, name, NULL);

    if (!ctx)
        return false;

    EVP_PKEY_CTX_free(ctx);
    return true;
}

static bool
jwk_prep_handles(jose_cfg_t *cfg, const json_t *jwk)
{
    const char *alg = NULL;

    if (json_unpack((json_t *) jwk, "{s:s}", "alg", &alg) == -1)
        return false;

    return str2enum(alg, NAMES, NULL) != SIZE_MAX;
}

static bool
jwk_prep_execute(jose_cfg_t *cfg, json_t *jwk)
{
    const char *kty = NULL;

    if (json_unpack(jwk, "{s?s}", "kty", &kty) < 0)
        return false;

    /* Like every other prep hook, refuse to override an incompatible
     * key type. Silently rewriting it would leave members of the
     * declared type in the JWK, and a secret such as an oct "k" would
     * even survive jose_jwk_pub. */
    if (kty && strcmp(kty, "AKP") != 0)
        return false;

    if (json_object_set_new(jwk, "kty", json_string("AKP")) < 0)
        return false;

    return true;
}

static bool
jwk_make_handles(jose_cfg_t *cfg, const json_t *jwk)
{
    const char *kty = NULL;
    const char *alg = NULL;

    if (json_unpack((json_t *) jwk, "{s:s,s?s}", "kty", &kty, "alg", &alg) < 0)
        return false;

    if (strcmp(kty, "AKP") != 0)
        return false;

    return alg && str2enum(alg, NAMES, NULL) != SIZE_MAX;
}

/* jansson frees strings without zeroizing them, so secret-bearing
 * strings must be cleansed before their last reference is dropped. */
static void
cleanse_str(json_t *str)
{
    if (str)
        OPENSSL_cleanse((void *) json_string_value(str),
                        json_string_length(str));
}

static bool
jwk_make_execute(jose_cfg_t *cfg, json_t *jwk)
{
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;
    const char *alg = NULL;
    unsigned char *pub = NULL;
    unsigned char seed[MLKEM_SEED_LEN] = {};
    size_t seed_len = 0;
    size_t pub_len = 0;
    bool ret = false;

    if (json_unpack(jwk, "{s:s}", "alg", &alg) < 0) {
        jose_cfg_err(cfg, JOSE_CFG_ERR_JWK_INVALID, "Invalid KEM JWK");
        return false;
    }

    ctx = EVP_PKEY_CTX_new_from_name(NULL, alg, NULL);
    if (!ctx) {
        jose_cfg_err(cfg, JOSE_CFG_ERR_ALG_NOTSUP,
                     "KEM algorithm %s is unsupported", alg);
        return false;
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0)
        goto egress;

    if (EVP_PKEY_keygen(ctx, &pkey) <= 0)
        goto egress;

    /* The private JWK member is the seed, so read it back from the
     * generated key. Key generation fails when the provider does
     * not return it; there is no way to emit a conforming private
     * JWK without it. */
    if (EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_ML_KEM_SEED,
                                        seed, sizeof(seed), &seed_len) != 1
        || seed_len != sizeof(seed)) {
        jose_cfg_err(cfg, JOSE_CFG_ERR_JWK_INVALID,
                     "OpenSSL provider did not return the ML-KEM seed for %s",
                     alg);
        goto egress;
    }

    if (EVP_PKEY_get_raw_public_key(pkey, NULL, &pub_len) <= 0)
        goto egress;

    pub = jose_malloc(pub_len);
    if (!pub)
        goto egress;

    if (EVP_PKEY_get_raw_public_key(pkey, pub, &pub_len) <= 0)
        goto egress;

    /* Encode both members before mutating the JWK and commit them
     * through copy_val(), like the EC and RSA generators: a template
     * that already carries different key material must fail rather
     * than silently rotate the key. Conflicts are detected before
     * anything is written, so the make hook leaves the key members
     * as they were (the prep hook still sets kty, as it does for
     * every generator). The private member is then committed first,
     * so an interrupted commit can only leave a seed-only JWK,
     * which a retry refuses; any pub a caller later pairs with
     * that seed is checked against it at import. */
    {
        static const char *const members[] = { "priv", "pub", NULL };
        json_auto_t *pub_b64 = jose_b64_enc(pub, pub_len);
        json_auto_t *seed_b64 = jose_b64_enc(seed, sizeof(seed));
        json_auto_t *out = NULL;
        bool ok = false;

        if (pub_b64 && seed_b64)
            out = json_pack("{s:O,s:O}", "pub", pub_b64, "priv", seed_b64);

        /* Refuse before writing anything: copy_val() commits member
         * by member, so detecting a conflict only at the differing
         * member would leave the members before it behind. */
        ok = out != NULL;
        for (size_t i = 0; ok && members[i]; i++) {
            json_t *old = json_object_get(jwk, members[i]);
            json_t *val = json_object_get(out, members[i]);
            if (old && !json_equal(old, val))
                ok = false;
        }

        if (ok)
            ok = copy_val(out, jwk, "priv", "pub", NULL);

        if (!ok)
            jose_cfg_err(cfg, JOSE_CFG_ERR_JWK_INVALID,
                         "Refusing to replace existing key material "
                         "in the KEM JWK for %s", alg);

        /* copy_val() deep-copies into the JWK, so the encodings held
         * here are redundant once it has run; wipe the seed either
         * way before its last reference is dropped. */
        if (seed_b64)
            cleanse_str(seed_b64);

        if (!ok)
            goto egress;
    }

    ret = true;

egress:
    if (!ret)
        jose_cfg_err(cfg, JOSE_CFG_ERR_JWK_INVALID,
                     "KEM key generation failed for %s", alg);

    OPENSSL_cleanse(seed, sizeof(seed));
    jose_free(pub);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    return ret;
}

static EVP_PKEY *
jwk_to_pub_pkey(jose_cfg_t *cfg, const json_t *jwk)
{
    const char *alg = NULL;
    const char *kty = NULL;
    unsigned char *pub = NULL;
    EVP_PKEY *pkey = NULL;
    size_t pub_len = 0;

    if (json_unpack((json_t *) jwk, "{s:s,s:s}", "alg", &alg, "kty", &kty) < 0)
        return NULL;

    if (strcmp(kty, "AKP") != 0)
        return NULL;

    pub_len = jose_b64_dec(json_object_get(jwk, "pub"), NULL, 0);
    if (pub_len == SIZE_MAX) {
        jose_cfg_err(cfg, JOSE_CFG_ERR_JWK_INVALID,
                     "JWK 'pub' parameter contains invalid Base64");
        return NULL;
    }

    if (pub_len == 0) {
        jose_cfg_err(cfg, JOSE_CFG_ERR_JWK_INVALID,
                     "JWK 'pub' parameter is empty");
        return NULL;
    }

    pub = jose_malloc(pub_len);
    if (!pub)
        return NULL;

    if (jose_b64_dec(json_object_get(jwk, "pub"), pub, pub_len) != pub_len) {
        jose_cfg_err(cfg, JOSE_CFG_ERR_JWK_INVALID,
                     "JWK 'pub' parameter contains invalid Base64");
        jose_free(pub);
        return NULL;
    }

    pkey = EVP_PKEY_new_raw_public_key_ex(NULL, alg, NULL, pub, pub_len);
    if (!pkey)
        jose_cfg_err(cfg, JOSE_CFG_ERR_JWK_INVALID,
                     "Invalid public key for %s", alg);

    jose_free(pub);
    return pkey;
}

static EVP_PKEY *
jwk_to_priv_pkey(jose_cfg_t *cfg, const json_t *jwk)
{
    const char *alg = NULL;
    const char *kty = NULL;
    unsigned char priv[MLKEM_SEED_LEN] = {};
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ictx = NULL;
    size_t priv_len = 0;

    if (json_unpack((json_t *) jwk, "{s:s,s:s}", "alg", &alg, "kty", &kty) < 0)
        return NULL;

    if (strcmp(kty, "AKP") != 0)
        return NULL;

    priv_len = jose_b64_dec(json_object_get(jwk, "priv"), NULL, 0);
    if (priv_len == SIZE_MAX) {
        jose_cfg_err(cfg, JOSE_CFG_ERR_JWK_INVALID,
                     "JWK 'priv' parameter contains invalid Base64");
        return NULL;
    }

    /* The private member is the seed (d || z), never the expanded
     * private key. */
    if (priv_len != sizeof(priv)) {
        jose_cfg_err(cfg, JOSE_CFG_ERR_JWK_INVALID,
                     "JWK 'priv' parameter must be a 64-byte seed");
        return NULL;
    }

    if (jose_b64_dec(json_object_get(jwk, "priv"), priv, sizeof(priv)) != priv_len) {
        jose_cfg_err(cfg, JOSE_CFG_ERR_JWK_INVALID,
                     "JWK 'priv' parameter contains invalid Base64");
        goto egress;
    }

    ictx = EVP_PKEY_CTX_new_from_name(NULL, alg, NULL);
    if (!ictx)
        goto egress;

    {
        OSSL_PARAM import_params[] = {
            OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ML_KEM_SEED,
                                    priv, priv_len),
            OSSL_PARAM_END
        };
        if (EVP_PKEY_fromdata_init(ictx) <= 0 ||
            EVP_PKEY_fromdata(ictx, &pkey, EVP_PKEY_KEYPAIR,
                              import_params) <= 0) {
            jose_cfg_err(cfg, JOSE_CFG_ERR_JWK_INVALID,
                         "Invalid private key for %s", alg);
            EVP_PKEY_free(pkey);
            pkey = NULL;
        }
    }

    /* When the JWK carries a public member, it must match the key
     * derived from the seed. A mismatched pair would otherwise
     * decapsulate under the seed while every consumer uses the
     * advertised public key, and implicit rejection turns the
     * inconsistency into a silent wrong-key failure. */
    if (pkey && json_object_get(jwk, "pub")) {
        unsigned char pub[MLKEM_MAX_PUB_LEN];
        unsigned char raw[MLKEM_MAX_PUB_LEN];
        size_t pub_len = 0;
        size_t raw_len = sizeof(raw);

        pub_len = jose_b64_dec(json_object_get(jwk, "pub"), NULL, 0);
        if (pub_len == SIZE_MAX || pub_len > sizeof(pub) ||
            jose_b64_dec(json_object_get(jwk, "pub"), pub, sizeof(pub)) != pub_len ||
            EVP_PKEY_get_raw_public_key(pkey, raw, &raw_len) <= 0 ||
            raw_len != pub_len ||
            CRYPTO_memcmp(raw, pub, raw_len) != 0) {
            jose_cfg_err(cfg, JOSE_CFG_ERR_JWK_INVALID,
                         "JWK 'pub' does not match the private key for %s",
                         alg);
            EVP_PKEY_free(pkey);
            pkey = NULL;
        }
    }

egress:
    EVP_PKEY_CTX_free(ictx);
    OPENSSL_cleanse(priv, sizeof(priv));
    return pkey;
}

static json_t *
alg_kem_enc(const jose_hook_alg_t *alg, jose_cfg_t *cfg,
            const json_t *pub)
{
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    unsigned char ct[MLKEM_MAX_CT_LEN] = {};
    unsigned char ss[MLKEM_SS_LEN] = {};
    size_t ct_len = 0;
    size_t ss_len = 0;
    json_t *result = NULL;

    pkey = jwk_to_pub_pkey(cfg, pub);
    if (!pkey)
        return NULL;

    ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx)
        goto egress;

    if (EVP_PKEY_encapsulate_init(ctx, NULL) <= 0)
        goto egress;

    if (EVP_PKEY_encapsulate(ctx, NULL, &ct_len, NULL, &ss_len) <= 0)
        goto egress;

    /* The sizes are known per parameter set; the guard keeps a
     * future one from overrunning the buffers. */
    if (ct_len > sizeof(ct) || ss_len > sizeof(ss)) {
        jose_cfg_err(cfg, JOSE_CFG_ERR_JWK_INVALID,
                     "Reported KEM output lengths (%zu, %zu) exceed the "
                     "supported maximum for %s", ct_len, ss_len, alg->name);
        goto egress;
    }

    if (EVP_PKEY_encapsulate(ctx, ct, &ct_len, ss, &ss_len) <= 0)
        goto egress;

    {
        json_auto_t *ct_b64 = jose_b64_enc(ct, ct_len);
        json_auto_t *ss_b64 = jose_b64_enc(ss, ss_len);
        if (ct_b64 && ss_b64)
            result = json_pack("{s:O,s:{s:s,s:O}}",
                               "ct", ct_b64,
                               "ss", "kty", "oct", "k", ss_b64);

        /* On failure, ss_b64 is released without being zeroized. */
        if (!result && ss_b64)
            cleanse_str(ss_b64);
    }

egress:
    OPENSSL_cleanse(ss, sizeof(ss));
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return result;
}

static json_t *
alg_kem_dec(const jose_hook_alg_t *alg, jose_cfg_t *cfg,
            const json_t *prv, const json_t *ct)
{
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    unsigned char ct_buf[MLKEM_MAX_CT_LEN] = {};
    unsigned char ss[MLKEM_SS_LEN] = {};
    size_t ct_len = 0;
    size_t ss_len = 0;
    json_t *result = NULL;

    if (!json_is_string(ct)) {
        jose_cfg_err(cfg, JOSE_CFG_ERR_JWK_INVALID,
                     "Ciphertext must be a string");
        return NULL;
    }

    pkey = jwk_to_priv_pkey(cfg, prv);
    if (!pkey)
        return NULL;

    ct_len = jose_b64_dec(ct, NULL, 0);
    if (ct_len == SIZE_MAX) {
        jose_cfg_err(cfg, JOSE_CFG_ERR_JWK_INVALID,
                     "Ciphertext contains invalid Base64");
        goto egress;
    }

    if (ct_len == 0) {
        jose_cfg_err(cfg, JOSE_CFG_ERR_JWK_INVALID, "Ciphertext is empty");
        goto egress;
    }

    if (ct_len > sizeof(ct_buf)) {
        jose_cfg_err(cfg, JOSE_CFG_ERR_JWK_INVALID,
                     "Ciphertext has an invalid length for %s", alg->name);
        goto egress;
    }

    /* The exact length is known per parameter set. The provider's
     * sizing call accepts any ciphertext length, so checking it here
     * is what produces a clear diagnostic for a wrong one. */
    if (ct_len != kem_ct_len(alg->name)) {
        jose_cfg_err(cfg, JOSE_CFG_ERR_JWK_INVALID,
                     "Ciphertext has an invalid length for %s", alg->name);
        goto egress;
    }

    if (jose_b64_dec(ct, ct_buf, sizeof(ct_buf)) != ct_len) {
        jose_cfg_err(cfg, JOSE_CFG_ERR_JWK_INVALID,
                     "Ciphertext contains invalid Base64");
        goto egress;
    }

    ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx)
        goto egress;

    if (EVP_PKEY_decapsulate_init(ctx, NULL) <= 0)
        goto egress;

    if (EVP_PKEY_decapsulate(ctx, NULL, &ss_len, ct_buf, ct_len) <= 0) {
        jose_cfg_err(cfg, JOSE_CFG_ERR_JWK_INVALID,
                     "Decapsulation failed for %s", alg->name);
        goto egress;
    }

    /* The shared secret is 32 bytes for every parameter set; the
     * guard keeps a future one from overrunning the buffer. */
    if (ss_len > sizeof(ss)) {
        jose_cfg_err(cfg, JOSE_CFG_ERR_JWK_INVALID,
                     "Reported shared secret length %zu exceeds the "
                     "supported maximum for %s", ss_len, alg->name);
        goto egress;
    }

    if (EVP_PKEY_decapsulate(ctx, ss, &ss_len, ct_buf, ct_len) <= 0) {
        jose_cfg_err(cfg, JOSE_CFG_ERR_JWK_INVALID,
                     "Decapsulation failed for %s", alg->name);
        goto egress;
    }

    {
        json_auto_t *ss_b64 = jose_b64_enc(ss, ss_len);
        if (ss_b64)
            result = json_pack("{s:s,s:O}", "kty", "oct", "k", ss_b64);

        /* On failure, ss_b64 is released without being zeroized. */
        if (!result && ss_b64)
            cleanse_str(ss_b64);
    }

egress:
    OPENSSL_cleanse(ss, sizeof(ss));
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return result;
}

static void __attribute__((constructor))
constructor(void)
{
    static jose_hook_jwk_t jwks[] = {
        { .kind = JOSE_HOOK_JWK_KIND_PREP,
          .prep.handles = jwk_prep_handles,
          .prep.execute = jwk_prep_execute },
        { .kind = JOSE_HOOK_JWK_KIND_MAKE,
          .make.handles = jwk_make_handles,
          .make.execute = jwk_make_execute },
        {}
    };

    static jose_hook_alg_t algs[] = {
        { .kind = JOSE_HOOK_ALG_KIND_KEM,
          .name = "ML-KEM-512",
          .kem.prm = "deriveKey",
          .kem.enc = alg_kem_enc,
          .kem.dec = alg_kem_dec },
        { .kind = JOSE_HOOK_ALG_KIND_KEM,
          .name = "ML-KEM-768",
          .kem.prm = "deriveKey",
          .kem.enc = alg_kem_enc,
          .kem.dec = alg_kem_dec },
        { .kind = JOSE_HOOK_ALG_KIND_KEM,
          .name = "ML-KEM-1024",
          .kem.prm = "deriveKey",
          .kem.enc = alg_kem_enc,
          .kem.dec = alg_kem_dec },
        {}
    };

    bool found = false;

    for (size_t i = 0; algs[i].name; i++) {
        if (!mlkem_available(algs[i].name))
            continue;

        jose_hook_alg_push(&algs[i]);
        found = true;
    }

    if (!found)
        return;

    for (size_t i = 0; jwks[i].kind != JOSE_HOOK_JWK_KIND_NONE; i++)
        jose_hook_jwk_push(&jwks[i]);
}

#endif /* OPENSSL_VERSION_NUMBER >= 0x30500000L */
