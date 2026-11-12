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

#include "../lib/hooks.h"
#include <jose/jwk.h>
#include <jose/cfg.h>
#include <jose/b64.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>

static void
test_roundtrip(const jose_hook_alg_t *a)
{
    json_auto_t *jwk = json_pack("{s:s}", "alg", a->name);
    json_auto_t *pub = NULL;
    json_auto_t *enc = NULL;
    json_auto_t *dec = NULL;
    const char *ss1 = NULL;
    const char *ss2 = NULL;

    assert(jose_jwk_gen(NULL, jwk));

    pub = json_deep_copy(jwk);
    assert(jose_jwk_pub(NULL, pub));
    assert(!json_object_get(pub, "priv"));

    enc = jose_jwk_kem_enc(NULL, pub);
    assert(enc);
    assert(json_object_get(enc, "ct"));
    assert(json_object_get(enc, "ss"));

    ss1 = json_string_value(json_object_get(json_object_get(enc, "ss"), "k"));
    assert(ss1);

    dec = jose_jwk_kem_dec(NULL, jwk, json_object_get(enc, "ct"));
    assert(dec);

    ss2 = json_string_value(json_object_get(dec, "k"));
    assert(ss2);

    assert(strcmp(ss1, ss2) == 0);
}

static void
test_implicit_rejection(const jose_hook_alg_t *a)
{
    json_auto_t *jwk = json_pack("{s:s}", "alg", a->name);
    json_auto_t *enc = NULL;
    json_auto_t *dec = NULL;
    json_auto_t *corrupt_ct = NULL;
    const char *ss1 = NULL;
    const char *ss2 = NULL;
    uint8_t *ct_raw = NULL;
    size_t ct_len = 0;

    assert(jose_jwk_gen(NULL, jwk));

    json_auto_t *pub = json_deep_copy(jwk);
    assert(jose_jwk_pub(NULL, pub));

    enc = jose_jwk_kem_enc(NULL, pub);
    assert(enc);

    ss1 = json_string_value(json_object_get(json_object_get(enc, "ss"), "k"));
    assert(ss1);

    json_t *ct = json_object_get(enc, "ct");
    ct_len = jose_b64_dec(ct, NULL, 0);
    ct_raw = malloc(ct_len);
    assert(ct_raw);
    assert(jose_b64_dec(ct, ct_raw, ct_len) == ct_len);

    ct_raw[ct_len / 2] ^= 0x01;
    corrupt_ct = jose_b64_enc(ct_raw, ct_len);
    free(ct_raw);
    assert(corrupt_ct);

    dec = jose_jwk_kem_dec(NULL, jwk, corrupt_ct);
    assert(dec);

    ss2 = json_string_value(json_object_get(dec, "k"));
    assert(ss2);
    assert(strcmp(ss1, ss2) != 0);
}

static void
test_cross_key(const jose_hook_alg_t *a)
{
    json_auto_t *jwk1 = json_pack("{s:s}", "alg", a->name);
    json_auto_t *jwk2 = json_pack("{s:s}", "alg", a->name);
    json_auto_t *enc = NULL;
    json_auto_t *dec = NULL;
    const char *ss1 = NULL;
    const char *ss2 = NULL;

    assert(jose_jwk_gen(NULL, jwk1));
    assert(jose_jwk_gen(NULL, jwk2));

    json_auto_t *pub1 = json_deep_copy(jwk1);
    assert(jose_jwk_pub(NULL, pub1));

    enc = jose_jwk_kem_enc(NULL, pub1);
    assert(enc);

    ss1 = json_string_value(json_object_get(json_object_get(enc, "ss"), "k"));
    assert(ss1);

    dec = jose_jwk_kem_dec(NULL, jwk2, json_object_get(enc, "ct"));
    assert(dec);

    ss2 = json_string_value(json_object_get(dec, "k"));
    assert(ss2);
    assert(strcmp(ss1, ss2) != 0);
}

static void
test_pub_only_decap_fails(const jose_hook_alg_t *a)
{
    json_auto_t *jwk = json_pack("{s:s}", "alg", a->name);
    json_auto_t *pub = NULL;
    json_auto_t *enc = NULL;
    json_auto_t *dec = NULL;

    assert(jose_jwk_gen(NULL, jwk));

    pub = json_deep_copy(jwk);
    assert(jose_jwk_pub(NULL, pub));

    enc = jose_jwk_kem_enc(NULL, pub);
    assert(enc);

    dec = jose_jwk_kem_dec(NULL, pub, json_object_get(enc, "ct"));
    assert(!dec);
}

static void
test_key_ops(const jose_hook_alg_t *a)
{
    json_auto_t *jwk = json_pack("{s:s}", "alg", a->name);
    json_t *ops = NULL;
    const char *op = NULL;

    assert(jose_jwk_gen(NULL, jwk));

    ops = json_object_get(jwk, "key_ops");
    assert(json_is_array(ops));
    assert(json_array_size(ops) == 1);

    op = json_string_value(json_array_get(ops, 0));
    assert(op);
    assert(strcmp(op, "deriveKey") == 0);
}

/* An allocator that both injects failures and scrubs freed memory, so
 * that the error paths of the KEM operations can be exercised and any
 * use of released memory is caught: a dangling reference reads garbage
 * instead of the stale contents. Since jose and jansson share the
 * allocators, JSON strings are covered as well.
 *
 * A header carrying a magic value and the size is prepended to each
 * allocation so that test_free() can validate the pointer, catch
 * double frees of still-allocated chunks, and scrub the contents. */
#define TEST_ALLOC_HDR 16
#define TEST_ALLOC_MAGIC 0xC0FFEE42C0FFEE42

static size_t fail_no = 0;
static size_t alloc_no = 0;
static size_t live_allocs = 0;

static void *
test_alloc(size_t size)
{
    uint64_t magic = TEST_ALLOC_MAGIC;
    char *p = malloc(size + TEST_ALLOC_HDR);
    if (!p)
        return NULL;

    memcpy(p, &magic, sizeof(magic));
    memcpy(p + sizeof(magic), &size, sizeof(size));
    live_allocs++;
    return p + TEST_ALLOC_HDR;
}

static void *
test_malloc(size_t size)
{
    if (++alloc_no == fail_no)
        return NULL;
    return test_alloc(size);
}

static void *
test_realloc(void *ptr, size_t size)
{
    char *base = NULL;
    char *p = NULL;

    if (++alloc_no == fail_no)
        return NULL;

    if (!ptr)
        return test_alloc(size);

    base = (char *) ptr - TEST_ALLOC_HDR;
    p = realloc(base, size + TEST_ALLOC_HDR);
    if (!p)
        return NULL;

    memcpy(p + sizeof(uint64_t), &size, sizeof(size));
    return p + TEST_ALLOC_HDR;
}

static void *
test_calloc(size_t nmemb, size_t size)
{
    void *p = NULL;

    if (++alloc_no == fail_no)
        return NULL;

    if (size != 0 && nmemb > SIZE_MAX / size)
        return NULL;

    p = test_alloc(nmemb * size);
    if (p)
        memset(p, 0, nmemb * size);
    return p;
}

static void
test_free(void *ptr)
{
    char *base = NULL;
    uint64_t magic = 0;
    size_t size = 0;

    if (!ptr)
        return;

    base = (char *) ptr - TEST_ALLOC_HDR;
    memcpy(&magic, base, sizeof(magic));
    if (magic != TEST_ALLOC_MAGIC) {
        fprintf(stderr, "test_free: pointer %p was not allocated by "
                        "the test allocator\n", ptr);
        abort();
    }

    memcpy(&size, base + sizeof(magic), sizeof(size));
    memset(base, 0xAA, size + TEST_ALLOC_HDR);
    free(base);
    live_allocs--;
}

static void
test_alloc_failures(const jose_hook_alg_t *a)
{
    /* Prepare the decapsulation inputs with the default allocator,
     * so that they are released after the original allocators are
     * restored. The generation template must live under the test
     * allocator instead, since generations add JSON members to it
     * while the failures are being injected. */
    json_auto_t *jwk = json_pack("{s:s}", "alg", a->name);
    json_auto_t *pub = NULL;
    json_auto_t *enc = NULL;
    json_auto_t *gen = NULL;
    json_t *ct = NULL;
    size_t baseline = 0;

    assert(jwk);
    assert(jose_jwk_gen(NULL, jwk));

    pub = json_deep_copy(jwk);
    assert(pub);
    assert(jose_jwk_pub(NULL, pub));

    enc = jose_jwk_kem_enc(NULL, pub);
    assert(enc);
    ct = json_object_get(enc, "ct");
    assert(ct);

    assert(jose_set_alloc(test_malloc, test_realloc,
                          test_free, test_calloc) == 0);

    gen = json_pack("{s:s}", "alg", a->name);
    assert(gen);
    assert(jose_jwk_gen(NULL, gen));
    baseline = live_allocs;

    for (size_t i = 1; i <= 128; i++) {
        {
            json_auto_t *e = NULL;
            json_auto_t *d = NULL;

            fail_no = i;
            alloc_no = 0;

            /* Every operation must either succeed or fail cleanly,
             * releasing exactly what it allocated. A failed
             * regeneration must never leave a mixed keypair: a new
             * public key paired with a stale private seed
             * decapsulates without error (implicit rejection) and
             * yields a different shared secret. A failure after the
             * keypair was committed (for example, while building
             * key_ops) is fine, as long as the pair matches. */
            json_auto_t *pub_before = json_incref(json_object_get(gen, "pub"));
            json_auto_t *priv_before = json_incref(json_object_get(gen, "priv"));

            if (jose_jwk_gen(NULL, gen))
                assert(json_is_string(json_object_get(gen, "priv")));
            else if (pub_before && priv_before) {
                bool pub_changed =
                    !json_equal(pub_before, json_object_get(gen, "pub"));
                bool priv_changed =
                    !json_equal(priv_before, json_object_get(gen, "priv"));

                assert(pub_changed == priv_changed);

                if (pub_changed) {
                    json_auto_t *e2 = jose_jwk_kem_enc(NULL, gen);
                    json_auto_t *d2 = e2
                        ? jose_jwk_kem_dec(NULL, gen, json_object_get(e2, "ct"))
                        : NULL;
                    const char *ss1 = e2 ? json_string_value(
                        json_object_get(json_object_get(e2, "ss"), "k")) : NULL;
                    const char *ss2 = d2 ? json_string_value(
                        json_object_get(d2, "k")) : NULL;
                    assert(ss1 && ss2);
                    assert(strcmp(ss1, ss2) == 0);
                }
            }

            e = jose_jwk_kem_enc(NULL, pub);
            d = jose_jwk_kem_dec(NULL, jwk,
                                 e ? json_object_get(e, "ct") : ct);

            if (e && d) {
                const char *ss1 = json_string_value(
                    json_object_get(json_object_get(e, "ss"), "k"));
                const char *ss2 = json_string_value(json_object_get(d, "k"));
                assert(ss1 && ss2);
                assert(strcmp(ss1, ss2) == 0);
            }
        }

        assert(live_allocs == baseline);
    }

    json_decrefp(&gen);
    jose_reset_alloc();
    assert(live_allocs == 0);
    fail_no = 0;
}

static void
test_key_use_denial(const jose_hook_alg_t *a)
{
    /* Encapsulation and decapsulation must be denied when key_ops or
     * use restricts the JWK to other operations. */
    static const char *restrictions[] = {
        "{\"key_ops\":[\"sign\"]}",
        "{\"key_ops\":[]}",
        "{\"use\":\"sig\"}",
        "{\"use\":\"enc\"}",
    };

    for (size_t i = 0; i < sizeof(restrictions) / sizeof(restrictions[0]); i++) {
        json_auto_t *jwk = json_pack("{s:s}", "alg", a->name);
        json_auto_t *pub = NULL;
        json_auto_t *enc = NULL;
        json_t *ct = NULL;
        json_error_t error;
        json_auto_t *r = json_loads(restrictions[i], 0, &error);

        assert(r);
        assert(jose_jwk_gen(NULL, jwk));

        pub = json_deep_copy(jwk);
        assert(pub);
        assert(jose_jwk_pub(NULL, pub));

        enc = jose_jwk_kem_enc(NULL, pub);
        assert(enc);
        ct = json_object_get(enc, "ct");
        assert(ct);

        /* key_ops takes precedence over use (RFC 7517 Section 4.3),
         * so drop the generated key_ops before applying the
         * restriction. */
        json_object_del(jwk, "key_ops");
        json_object_del(pub, "key_ops");
        assert(json_object_update(jwk, r) == 0);
        assert(json_object_update(pub, r) == 0);

        assert(!jose_jwk_kem_enc(NULL, pub));
        assert(!jose_jwk_kem_dec(NULL, jwk, ct));
    }
}

static void
test_conflicting_kty(const jose_hook_alg_t *a)
{
    /* Generation must refuse to override an incompatible key type:
     * the JWK would keep members of the declared type, and a secret
     * such as an oct "k" would even survive jose_jwk_pub. */
    json_auto_t *jwk = json_pack("{s:s,s:s,s:s}",
                                 "kty", "oct", "alg", a->name,
                                 "k", "AAECAwQFBgcICQ");
    const char *kty = NULL;

    assert(jwk);
    assert(!jose_jwk_gen(NULL, jwk));

    assert(json_unpack(jwk, "{s:s}", "kty", &kty) == 0);
    assert(strcmp(kty, "oct") == 0);
    assert(!json_object_get(jwk, "pub"));
    assert(!json_object_get(jwk, "priv"));

    {
        json_auto_t *ec = json_pack("{s:s,s:s,s:s}",
                                    "kty", "EC", "alg", a->name,
                                    "crv", "P-256");
        assert(ec);
        assert(!jose_jwk_gen(NULL, ec));
        assert(!json_object_get(ec, "pub"));
        assert(!json_object_get(ec, "priv"));
    }
}

static void
test_thumbprint(const jose_hook_alg_t *a)
{
    json_auto_t *jwk = json_pack("{s:s}", "alg", a->name);
    json_auto_t *thp = NULL;

    assert(jose_jwk_gen(NULL, jwk));

    thp = jose_jwk_thp(NULL, jwk, "S256");
    assert(thp);
    assert(json_is_string(thp));
    assert(json_string_length(thp) > 0);
}

static void
test_seed_format(const jose_hook_alg_t *a)
{
    json_auto_t *jwk = json_pack("{s:s}", "alg", a->name);
    assert(jose_jwk_gen(NULL, jwk));

    size_t priv_len = jose_b64_dec(json_object_get(jwk, "priv"), NULL, 0);
    assert(priv_len == 64);
}

static void
test_seed_determinism(const jose_hook_alg_t *a)
{
    json_auto_t *jwk = json_pack("{s:s}", "alg", a->name);
    assert(jose_jwk_gen(NULL, jwk));

    const char *pub1 = json_string_value(json_object_get(jwk, "pub"));
    const char *priv_b64 = json_string_value(json_object_get(jwk, "priv"));
    assert(pub1 && priv_b64);

    json_auto_t *jwk2 = json_pack("{s:s,s:s,s:s}",
                                  "kty", "AKP",
                                  "alg", a->name,
                                  "priv", priv_b64);
    assert(jwk2);

    json_auto_t *pub_jwk = json_deep_copy(jwk);
    assert(jose_jwk_pub(NULL, pub_jwk));

    json_auto_t *enc = jose_jwk_kem_enc(NULL, pub_jwk);
    assert(enc);

    json_auto_t *dec = jose_jwk_kem_dec(NULL, jwk2, json_object_get(enc, "ct"));
    assert(dec);

    const char *ss1 = json_string_value(json_object_get(json_object_get(enc, "ss"), "k"));
    const char *ss2 = json_string_value(json_object_get(dec, "k"));
    assert(ss1 && ss2);
    assert(strcmp(ss1, ss2) == 0);
}

static void
test_wrong_priv_len(const jose_hook_alg_t *a)
{
    json_auto_t *jwk = json_pack("{s:s}", "alg", a->name);
    assert(jose_jwk_gen(NULL, jwk));

    json_auto_t *pub_jwk = json_deep_copy(jwk);
    assert(jose_jwk_pub(NULL, pub_jwk));

    json_auto_t *enc = jose_jwk_kem_enc(NULL, pub_jwk);
    assert(enc);

    unsigned char bad_priv[32];
    memset(bad_priv, 0x42, sizeof(bad_priv));
    json_auto_t *bad_jwk = json_pack("{s:s,s:s,s:O,s:o}",
                                     "kty", "AKP",
                                     "alg", a->name,
                                     "pub", json_object_get(jwk, "pub"),
                                     "priv", jose_b64_enc(bad_priv, sizeof(bad_priv)));
    assert(bad_jwk);

    json_auto_t *dec = jose_jwk_kem_dec(NULL, bad_jwk, json_object_get(enc, "ct"));
    assert(!dec);
}

/* Reference known-answer tests, count = 0 of
 * https://github.com/post-quantum-cryptography/KAT — generated by an
 * implementation independent of NIST, compliant with FIPS 203 final.
 *
 * priv is the 64-byte ML-KEM seed (d || z), pub is the encapsulation
 * key, ss is the shared secret for the valid ciphertext ct, and ss_rej
 * is the shared secret for the invalid ciphertext ct_rej, which the
 * decapsulator must produce through implicit rejection. thp is the
 * S256 thumbprint of the reference public key, pinning the canonical
 * member set (kty, alg, pub). */
struct kat {
    const char *alg;
    const char *priv;
    const char *pub;
    const char *ct;
    const char *ss;
    const char *ct_rej;
    const char *ss_rej;
    const char *thp;
};

static const struct kat kats[] = {
    {
        .alg = "ML-KEM-512",
        .thp = "LX-l-rWOii3uNJnIk9mQn5nipOkrPGHvjz7GCm50b1A",
        .priv = "bbvEN1E23zsH98cOY54iPhd-f9U7Fhs_TVd5F5TxJiT2lkhASOwh-"
             "Wz1ClbQdZxEjzd5dS8Dg9N0SWkGlM96aA",
        .pub = "gLcBAIMdfuFo9HOSSDEZ-Thj7LC8YFMS01coh2sA9fV69Mhe2pcoHVdDkL"
             "xyVhk2aNyYYlNUq1K5vOeBxXccwmCZ9vusvuF4TRlIh3MfCXyH4ILL6sV9"
             "MLe5opOHLIQUZvIkTMZf9LplPWdR36IgUdVTNplCwxwp-RMHr1cyktaXqM"
             "MWEuB7UzXPCDKf0ka_KjIgCoywxLA7nQnFuhw5GVOekinGlpJDSCgvaWsV"
             "JeVgOAa022GLPchjDLKG5DEXIbxQMfJXqpJb-AlgRFqo2OaXiOmdqVwdEM"
             "w76FhSjbDP6gA8dGk3gKZaNuYoQ7O-"
             "FUBlQ9Itg1B8h7J4Z5LID6VihFSjEDlN2kwqtZSThQJX1tO8EHGG2QYnB_"
             "NU6BoaEPy3Y9MaTsQJqiQ-"
             "0uWbsYmFXrFlYma7N1AHheoIzYjCIqjFOod3yrQsnCOKANWTaUJQJumdKu"
             "YECvZwkCnKh4nIl7Mp-"
             "6dI1pyKcUjJWrsMcXh8WPEvIfIhPjiSQqp_vTIMEqxCxhFgbLjB0bRiWIa"
             "hRaU1vWW9DZlrMwwWV9Yah-"
             "kEFwAyJXWYIKO77FBc2vERkyKarhc80SutIqejCnap-"
             "nY2w9WqSOF4QBKgEvFBaLeFPSoW-QygLMM7IAbAjybBX8opYSzHkuHPAuE"
             "yGnWoEIkZhmZ9QUivNuZeGlkliQKWF3NMMVwOObdRjIZgzcJl0MgT7yCgQ"
             "zF_rluOQFRu7PcdbAVPpmtJQBMJvvMP1RpVGXVdqRBGibJvCDkVTIR77yN"
             "llDwCSUg6rZpzZ8mAo9HORtIAihUnXKO8pINOb5owNsDNgLoijTS5eAJE1"
             "cDL6QfG-"
             "0OCSpwHRkcWOcuGGIxgw7JTIVzJFpK80Uk9akRNU2RG4CloE4ABzCh-DlG"
             "POqJdjDuVs8NcWfSBnUhJdgKa8FomPDUzayYfd7LNwpOJ8ITATLs3DEhWK"
             "1tQdxwPuBaQjhmN1tU_duSL8ELCsfgqOkC42vUfRtdvpLzJ08iU_4UMD6o"
             "y4KwzkBpMeROfXyBBfsGhkGBwRPGLuCTPNQx4qz3fPCyGylVD9xU",
        .ct = "kX5Z0eGCopZIphlVoVSzBKhC9FjrpZPzBl-310T7ok-joNU4hU4yhE2ySN"
             "SBAMOJxMSzymwjTy9hpnkyru6Ajb_pjYltHpZoggllxjQ7u0pN5kt6mftT"
             "tSZOMZnVh_-"
             "l4Eefa3OGsjy5wkP6b1RX_JfbyW3MA5vWxOfoWpC1xSMkFkNOqULMcRNLu"
             "aL0mR4FleNIf-q6xHnKuVENV7hiUO58lqZ6nyxhIffaoCxc-jsjsMcywrF"
             "WlOHMusgreHzyEY0IQly7oSGIIheUDIlMvkeq4lQfXG4L0bqrMf0rLss0u"
             "eaT9vwP3uqQZxbQiBj1HfDEaUAp6MMjS-"
             "C2JHGydp2axM65R2AjgPOkl7KgH_e4dGwceugZg-"
             "AWvWXHzRdiwZGFfkHCMhmB9seqjXr6qp-gtVfsHsEoX4tNbHiK_xWepYYu"
             "gU0IJciDS3ykXbfI7aP6amp7ikBRlSm_dLag-AxISRf0DBB9GCvOPjRP02"
             "0bN3qYL2vyNhuNZih1wWbcynMkC4bfXuD6QjGzVvDN1rMXD_iRE9sLG53S"
             "ZDNXgyIsvnvoRGQrCxmI0Ysmjab3jMlE9DuCcUPE3F7h8NZYuHucAIYvJj"
             "1vV5j8gui-B5oRCN791MeGPDFH6b3w-"
             "8hN66IV_fucpCN6hBmyb97_Y6f5XEQrzmeWbr5rX5rx_Sp8vtZI6nJ223Q"
             "trD5HD2zHQdgud-nA3QGbVFgXdVGXW1ljO-"
             "Z7NcDUMLclUk3q_eum02Q8XILrtSR5ZpxBG7VrOX-NN7j3-"
             "kztAxZUbKruQZwOfx2WoOxhTGycjgPgEAMXZRIfHrj9VJ_eBGpQRD66uf6"
             "i54op9JZEVZKNsfnngg5TPFcSmJs6NjfqAKHePkaagAxDHU3yQ8HcfWqJu"
             "nkA1St4vMEDR0-"
             "dLCEoAlwxk8TRoJ9QkFrS3n_o4J8Efg5y5tqw7ffjsI7RMWrPhXJUtsH79"
             "kzlgvKZDM7PlQX9foUXmYqvWDvhqmQem1TbuRyp0HAJE5Z_sDSSAbXWebM"
             "t",
        .ss = "K1xS7nKUYzGYO6BQvg9DUFXAVHkB4DVZs1ZReInqJ8U",
        .ct_rej = "lqxiQ8mxJyvne5daQEi_AP8sSPlKNIM2JEknOIDUXlS9oVcpaCv1kadDgq"
             "cIvreBGMqymtdKwvQFunIAdt-"
             "1cYjcFoSHzSAIH2v0EvJX3qA0BrI6anUuR4uk75x8D0gQkh-jJUW-ZNxdn"
             "xjU4TIO_GUIFUzaNauRLQWeApGhFQrgoQ2l49e9IhqFHFmN9NCxjaqSCXZ"
             "VYJnRwN5OIi1TBNRPqcub1P_hV2ndbEeT-oCfUmTPD-vKS1l1uih2OXg6o"
             "fS2Rf96ANRu57Gf7Bez6DvK9DYdU0njDOq2DDhraw0bkNizNu5qYnrSo4Z"
             "wy1ETsPtKwt3EJQCXSD_v0YJnDqQPD0XM6Que1Y2vrvZX1k4l_WaSppchm"
             "U59ALSUkgXr5MT5xG7loQGLIgom2Ari0rSGNy6XTXWyCgBbFhatHhPRYpF"
             "cwk8nRnDR5ei9NFh0p-"
             "fJdZyOQ_8zaJIAc5phM5X3rnjXPGp7kPZatRHw3zxdyoXQuUMLTpcJhxX_"
             "gjthcyF5muoKucciNHgDOex7VB1eb4wVURRsJKZUEYEbI2dMJhIzVs8jM1"
             "E4LDmUy6XcbCWgfhuprzPsoYu6PpeTXjq98H6foyzs8kHnyvxlkttO5If_"
             "K5ikpHgF3uF_2TRI3JhFe3U-"
             "1Jle5rG_qf8dOGyR85bKj0jKtbCaeC7DthaoemRIqWI2xGVUE691UyPTao"
             "2y4WUJRUSJ5uyDYpEwzSpUgXkYrzYsgxg0lLS1kNuvac85nT4tw-nAwSJP"
             "FI5l72goc0Grcq1Yrfxpso4n6R67-"
             "DD6xTuU92LwHMmxVhrjXxbtq_Uf8WTBMJ0f21LNK_7bWkkutly5_Ia48F7"
             "SbRMjP7Cj6zOp3OLPmOZRbO5C--HpfiCrbJll9Yo3fcc-"
             "UwZnq49F5qcLI9tQ8N9BFzLYrNq-UMUa24hsDlpSltSqGxOjNvDBeBL3n8"
             "aUGKfYkBxWj0EO_yr3S6rrgzb0bKF-"
             "FOBgzi1FzbN2KG7si4vvpauAJYAnIKHnOTr1edsT",
        .ss_rej = "blxSKm0ZuGxhvZg7VqC-81HFznFvAhtJvezXvf1e1Vo",
    },
    {
        .alg = "ML-KEM-768",
        .thp = "4_dvQ-bBcox9G42aVmXIMO6IxMZf-ezOgqsclOSAsj4",
        .priv = "bbvEN1E23zsH98cOY54iPhd-f9U7Fhs_TVd5F5TxJiT2lkhASOwh-"
             "Wz1ClbQdZxEjzd5dS8Dg9N0SWkGlM96aA",
        .pub = "AfYK8dyOY2CueLWdSlBC65FFomkEbWI2uDBPMFwtncsYn-"
             "WmLfibL1p7zju8dTweePcwqZhp-"
             "AmrqFa2drcHsmYB0dkJurMkUUlOt9CiFTpjULeXiamxFfg-oSA3JWVi8Go"
             "dWro3jadwOdO97Kyo5qIqSQUKdjAKAmfNs4t6x3kDxQylO5koPKxrlfumU"
             "bEaTRppLkByllBgWHZp8lOxuxguZhRGForGAiGJRmACDpu19bcSSgMD4lQ"
             "-o-ps6XokgrJVyjRvsnqEezO5Pzqy0zBkxuZjLRoj8RROkHska0efSlySi"
             "Smh4kFQ9SQSWKW2d2amb2ozhGSVkHgo6-"
             "ROzFtzEkBxukeQc5EEEKFtXVaWtIsZR1KXl5V3KpHDSPUCs3qmUJg-"
             "u4m_PAgf8nNUQSnJE3puGDTI8ufOFMeHDFPAW5uU7NOOZkWRGwkSM2hj7B"
             "aIMfgRiBB1zzilneS1xziqbvA9d5spVYjPtiSRzHs-CLSEczVPmsgGHBUq"
             "niBZl0mblwtpvOZv5CvKKSTM3wED0KTDkZPC3yURjXKxeqsmsMYNTNLDBs"
             "pGlsGF3gUDX0oJz5cK7MjMk0Nvg7Gur0UsQZKaLqvBUZOPdMk7hYVG3yJk"
             "7uq2AuBKhcUi-PsaUhSv2NTK5XpHtvOBojEmvZkXFzEor5F_HUg2kcRQ0R"
             "Uc_poUktRz7YYuJ9qSUAyGogAZ6fl15PVK0xm6LFYwxAFCGde6I1RW_lMB"
             "QBk9ZiRF5qlB0eI4Vnuo1NlascdEfWkIIYdtAXJwz7Fp8teS8DyAByBpe0"
             "EKtBxm8rJFhRJWVesQqhCH_8t3UMuIetRGc3dQCmp9OoKXa0FaVEaVd7QT"
             "jZGbA_TJpNM5C9y28XF6X6SrJaNPS6UDm7IsfzwjTqRCc0eqclFGTmMZBN"
             "fKxHhPeLSdX0oQSjAYCad59kZhMfnGK7ZxR_TNSXOmqhwprmqGR7Ymi-CJ"
             "_gSM6ZDNY4dD0oXIiacH9YG2OvQXMfAkawVLxLR6qwG2hConCdAugVirkP"
             "SLadE2CCs0ywZzt0qj9UUI7QKfuPUEXuBjnhUO47PIX2ijEOwEQZgBALQq"
             "vyutENSp4MeyvFu8r3PLzcSdwslJERk2d5sXiXSgOSlHdFpHGJvD-"
             "opnnICvlkqfmxtWV3J0oqZp0tpnBKpJavQH-"
             "hqpZMw9wxQPX5Wafql0vbG4PkipnAo-LXWwZptcEniWJUBgkWYmbaGIhvw"
             "jevMM79Vp2-OZ5mUuRfBqXfyadYpJhwiP-OOKPPNrnZiPDgcLaNC4j3vMQ"
             "TBggNiJeAx-I4iVzKpPNXciXMpMipMwzmE-"
             "cXeYyWcJJLJxrEArUVOLi1lnrEkNyrUwDmxU1qNjLzuXPkGG7hp-"
             "LoVkkYWyY3DDhyNcTfKKmTeknUB4v4g_TmNGyzJR2eE_G9oIeyha-"
             "qgOJiZBxVJ7ChhLi8hKYuV3MUZY4gKdhQBk96e4HyU-fMEkqcWwOdybF5q"
             "Awvau5uoIFRclNzMaV7UFuqdv9bTB8Np1S2GU9LOamxhzDTzauSXWke13q"
             "NuZJ-ojOsKhJ0T9wn5dIhuTaa2zJdg",
        .ct = "FqYf-EeH_UpfGcpZs2V9s6EGpzKeLWJ0ei74UUkWMQm-__a8sz32YjC49n"
             "Jc5xn1j3EZbolb78l1TZ8EJJRkjIim7UxM8T8vr59lHeedrgd3M8sjX53O"
             "RIl3_ULVSGt9_fbXvZFysUJHZV008QUk1GlHjZqWOfNNKs3m48BI1Sswi2"
             "YkX-mijN55g7nRTAOzdxX-OXDNNXNHca3XqptYz7Ct-"
             "MYT3q-ysx9uXINk1DNOk6-OSUP6lHzGdmdEfP_QNiNa-"
             "up_YDyy6id7l9rfgup0b2snOW3QjIXP-TBKLlzgVx_eLpJnFryfjk1HS06"
             "P00sNwoN2IE6jBtMOmm3YglC3mCPncxny7zp3cE9And6L622xvkqfJa4uF"
             "ZOd7fGxGlqlH8_wQGi0bUL7uv0kmCZMyk-"
             "3iw8qsWLH71aYdaExSLmksLnaF4fKCnAz4-"
             "yhNHHby74V408rUGW5lf4iHCt6wVAzTRTmjtxeBJZj3jYvro014kwgLF-t"
             "IVPNBE6pYqOI8DDNxd7Bw0Ixg7Fzwysi9YAK5F6OicjuRhfOJOYPJ4v9Hq"
             "D4-pJIa2-EkSfamb575MZh4romZp1qz2GaMwVoCWg-JKLynjO-f1-"
             "axmhpfllIjpuGhZVs2Ht8RxCdYDICwgFHLsgp6mSSLk0OrdSktaj7BuD0v"
             "yWlnO1UVXOI3NkbOHy2FIWX7fhKIllYAYUcpLnp4Jb9_JbyRErJ8SR6XmQ"
             "Hh_yiPj6yHsEFnEKmWANEHfASeQE8RI38Pu38M1Xu4fUQCGoRX4VMNtt5e"
             "oXt4ZpHOjPnmoD29_ZGfhsNhm_g5XqKvTeZNKampJL18yWU1D3i7C7qgUh"
             "5gbtjlL-"
             "m31SY10xtsiAqY0ijJfvJBrjoILsAZZou4SdAsUsuNvTF2rQRwM0JbF5ju"
             "k1Iqp6Ssx9E3JfA_vZhvPTbiV8XRhPZ1e2eg2ZXdF7J3ux68nPOyH7w6vg"
             "F2hvIQBYIgQuKhvlSxjJtCfyNHX_YO06GLgUFjod8BWzFRl7DGSsDpMM8x"
             "rFlWNJILV-EUYy7xSaq5uiEAxfvs6GYLD0XGe8V0Q-"
             "LB3xcaGgL5tPZLoaqpus3jPBVnUkyVxR7VXMPSaBCMlrwZrT5dBuf_11Hl"
             "y1ayvUra-pOnjVO-USLYvbSoTF2daki4U4xV41sq1oJpxqycNhlFRuKtMY"
             "Stf1dzJfkVBmhz7a4ua7GD2JgIJj5HwfCOBhmV5Qcehjk1-"
             "4iDwItX__SkYU7nAY-VhtxdveiNc5FvIbORxgIbflTbFpfCr8EwKhNgr32"
             "lVKt4xNUM8EKG6adaIlp5tnc5U07Oq46fyq5BOZX4_sFJB-sEQqgfmLMOZ"
             "HX0NYym1q51p1zNsDRSFiMnwkhMluF31_TDbgKVqNyQ3IVNkGWGqfgQr8m"
             "Rv9GAiwFnVeUw6S3-QxBDecaUjHdm4O70Oa9qxv55i8",
        .ss = "tAjV0RVxPwqTBH276oMuQ0B4dobVmpotEGvWYroKoDU",
        .ct_rej = "lqxiQ8mxJyvne5daQEi_AP8sSPlKNIM2JEknOIDUXlS9oVcpaCv1kadDgq"
             "cIvreBGMqymtdKwvQFunIAdt-"
             "1cYjcFoSHzSAIH2v0EvJX3qA0BrI6anUuR4uk75x8D0gQkh-jJUW-ZNxdn"
             "xjU4TIO_GUIFUzaNauRLQWeApGhFQrgoQ2l49e9IhqFHFmN9NCxjaqSCXZ"
             "VYJnRwN5OIi1TBNRPqcub1P_hV2ndbEeT-oCfUmTPD-vKS1l1uih2OXg6o"
             "fS2Rf96ANRu57Gf7Bez6DvK9DYdU0njDOq2DDhraw0bkNizNu5qYnrSo4Z"
             "wy1ETsPtKwt3EJQCXSD_v0YJnDqQPD0XM6Que1Y2vrvZX1k4l_WaSppchm"
             "U59ALSUkgXr5MT5xG7loQGLIgom2Ari0rSGNy6XTXWyCgBbFhatHhPRYpF"
             "cwk8nRnDR5ei9NFh0p-"
             "fJdZyOQ_8zaJIAc5phM5X3rnjXPGp7kPZatRHw3zxdyoXQuUMLTpcJhxX_"
             "gjthcyF5muoKucciNHgDOex7VB1eb4wVURRsJKZUEYEbI2dMJhIzVs8jM1"
             "E4LDmUy6XcbCWgfhuprzPsoYu6PpeTXjq98H6foyzs8kHnyvxlkttO5If_"
             "K5ikpHgF3uF_2TRI3JhFe3U-"
             "1Jle5rG_qf8dOGyR85bKj0jKtbCaeC7DthaoemRIqWI2xGVUE691UyPTao"
             "2y4WUJRUSJ5uyDYpEwzSpUgXkYrzYsgxg0lLS1kNuvac85nT4tw-nAwSJP"
             "FI5l72goc0Grcq1Yrfxpso4n6R67-"
             "DD6xTuU92LwHMmxVhrjXxbtq_Uf8WTBMJ0f21LNK_7bWkkutly5_Ia48F7"
             "SbRMjP7Cj6zOp3OLPmOZRbO5C--HpfiCrbJll9Yo3fcc-"
             "UwZnq49F5qcLI9tQ8N9BFzLYrNq-UMUa24hsDlpSltSqGxOjNvDBeBL3n8"
             "aUGKfYkBxWj0EO_yr3S6rrgzb0bKF-FOBgzi1FzbN2KG7si4vvpauAJYAn"
             "IKHnOTr1edsT6IZ9Q9cR5hsu45UHeYSkUKjiUTBABoqTF5a8PQBptW0fBi"
             "_D3WGxsZS24fHRwFltRT23t1kqb5-"
             "KxVdqhVkGUSIAI0xA_JvZ3pw9YpHDG15ret5HOjeHqrDJWLPfdhiKhuz54"
             "6sG-"
             "W0exRjBvzNmvvlEZdnhpp6ybbng8IVtJ75QpSuwo6FwddZggP4dO9QhItZ"
             "WzMOlVuBPkT-vlkEUOTGmQOcvq50AMDjJgsrIFC5WE9uqudQTkFd6_nOsY"
             "j98GSDL8f61yFzEMzAMHFV50CDVSR7dbFAxF7nE1ZhDiTiDHlw0HpyGzQD"
             "djUMgtlb5q6nw5VJyTjgo_C4AlGEhZjrTrZiiXn0wjaGgNHxNz8eY45UnC"
             "tB8_fD_jjJ42uIKsmZM3zCl0Ov-eh55nsRLUU4C8r6XONTigDa0d2vUBAg",
        .ss_rej = "57z4mf6122nRF0Gog47P7iU-gLdtajWvRuIg6B3EHa8",
    },
    {
        .alg = "ML-KEM-1024",
        .thp = "TrYEbznkj1wM8GzIYNovFSHgWQUSdlO4_fhzDTfaXuk",
        .priv = "bbvEN1E23zsH98cOY54iPhd-f9U7Fhs_TVd5F5TxJiT2lkhASOwh-"
             "Wz1ClbQdZxEjzd5dS8Dg9N0SWkGlM96aA",
        .pub = "qBIvN2s_XTVSY-ulIsQ5lQRL7KeLm6mSS4cDVJCueKlNUjx7pYijhutJv2"
             "Uv3xJxY3MYehygR8xhOGJ6rquPbOu_h6F2uGyffwk8j1sL3BRzmeg5rnNw"
             "ONC9AUI2n5ydRrJbmuVAuAAj1ddX52s_3TBk3StEzQa0Q2kncUe2FWVLMl"
             "BE4bxgb6YpBVouaksCsvGxqpimk5HJG9mPEFiqGNkBndu23OYKBwutS-"
             "w983oNTdqEECiIMOmuUJiAoCskjhu6jtscxSBRfBG2TWjMAMaUdaKi2cVq"
             "J3OgJCSyvvF937TEzFA9BciIlGV55AJ9v4qJNwx0-"
             "mbIoyXCNCljmUwgL6BReTUvkqGGMIIokhUae4sWPupoXCxPAmAV_ueC8cU"
             "8pXOAevxrx2a-AIeW-"
             "7kG6eGr0cyEX2BCPwl434mSSqEYorQcf0WDCOh7GQonACun93PLZeyHFlp"
             "lMKCXGnUgaaQq-"
             "9Jx4eI2_BVa7_dZ7HYlUeW83zpm1qmvkrTOFKKe1BDPcqgI6QyBpGB0YRB"
             "ZgCORAGxSxZlFGXGKhPRF6NnDxmFuAmiy4dWvSLCRxgU7dHd0D-"
             "o2GFM2TeZCpEuDNkI1tqhlA3h4B0s3QAyCWReUoJBV1bNKnxhuFXTMs4SP"
             "S2IAFtgHuUVIW8TJ4XZE_qZfU0XIYtg6oaTNG2dkCfpUXFcSYTwme4BEff"
             "CMh-UyvXdQDBSwjXrADcfC-lCxtcJtJ9ynStQfmwdhQmMhqbOpkqTD-hUQ"
             "IbwtF8iPqrcnTmXMI9KDq1WpUUlYckVbzOgGqegDwtm1Zqat3rt4EgupNh"
             "ypuLEDI_aCzFuRMdRPJiUB7YYchmyeMdCXifgdw8dzpEZMTMnEy4OLm9sW"
             "_yYiephxxXc0tcWcJ-"
             "d_Bhp7VpYylvSK5YqF40BjqvZE_uQXizqWRxkcTwIjVsxbF-JHZEqAm-DA"
             "TKV98du8rxwrFkUhemFbmKoEjKSK1yVPW4WSSQZqv2oz1ZUhsHzGhKGsIw"
             "iRAcgN-suCCURF0zWObrZGHPYUy8IiSCWe0Zqw1kmPPyDGYOmqWuh30pc2"
             "EaN3sUhg-TmECFda9RgZk2iD0IAhirCsr7tjmjAZo4h4pFoSZLMPcJxGo_"
             "peLVcfj1lNO6kMQygTt4AF4dILclUfh-"
             "l4_NhIe7WEpOl6ZqBYqadQ0VxHmRnIHtI1gDuKZXqOCIBPjBCfjdFgdBJN"
             "8isMSydtKshltVpTjXOCYiYha6IexzaPMMY44_IBKIojwoYcPIhZn5AnEg"
             "sN11daiFXFQRVU9pm0fsZno7KmL4KLJFiWUTASbym3UlIF7zNdR0ACCmHJ"
             "x0KqO-AEjqw6ppt9mhiEblSY5muO1VDNvZG74NBII0e_w5lk8_Y89JZ-qT"
             "IUGMN3uCYuYyJeF2If_qRmpjNegiBZ5GqKXrFv8yGzoENYjAu25dK086jB"
             "ALBb8nFVI0M9urUEkSFrnNwtUmquO9IYQEwzvrqVlxm0jMmuR1NRKxccdX"
             "Y7OPtN3KgnUKu1BbjD_FGedTZWDWOe8kdpU7e9eWbBO9CeivF6VCq0knFR"
             "rUpG6IQ8BVWR54yotOWVaCKBWjyY7_G5zEmuoGvNJPnHCUGj0_CBDeJa_B"
             "VN12Bp8sLDZ7tSosMJzPFwjVFNP4ccxOO6_pFUm0S79LJMVSWhm7ar1Qxp"
             "NAeFHhp2Mog_eDoI5Ug-"
             "fKeHbksoiUF9fsFH6GJOTIO4u1a97ymqR6VzUDS0i-uMNsYiPxhFAuyz-A"
             "ctYeQcyKIXhKJL48ZS8taXpaKK1gXL8MsfkooloTqZM3AEgfNBsqPCeQIe"
             "0tcBMDaZqrEt9IhjA9Oz4pSTQbV3-"
             "FrDJihKhfJJSXZ5DnYuxRwaiPqi9eA8D6tE45lzU3RQLwApz9t06eFRcmN"
             "lQmIyD_PBX_SAZ8cB34Q2UHNz_cekdfE9lhpFcYuhpLVvAtAJUDAZSlyzS"
             "Dhyg4ejOjEFYec9GMKvNBFjhIec_SxwquBADuwr1mfCpMWgUeZDx9iujRu"
             "rQ1K5vSez5kclm7HMyyME1yXLLnPGcYtavIiACUmywdA_FZ-"
             "_OWrcqFJvG0dvgP6RwTMI1kU",
        .ct = "cH0Yyrz4lnDIAAO0fSuGeK0NpKqteBozUegqw-RH5wGa9cuGAg-yrHJ-"
             "eWVBVYNbRd6bivXlx--gEpXaiYgTHcjW7bBkXD5BFqqwgMWlcedgQW_o4p"
             "nImBGWPPl3bgyCh1FwH5DiZDWJf4_fenr6rZhwCcDrEvuRTfqrH86SZPVe"
             "4MtNiUSThd0IGwLazpsXmlRRPSgVKbj9YcU-"
             "O8_J4sOucjOaYZcRn5fUSwXT82pavgo_fMvbuR0kslhWRipkm2wdRq5uBe"
             "mZJ02pI55nRSWlIvYUHLld6WuTs58PfQkNSxwFRu9vw_0I6Qsij2V68x65"
             "M8nPzmNK9r-CDV4YXzFX77ySaorkIPKTAFE7rzAjbMEUR-dK7U4mJ5nXel"
             "zyKwp9oSZCJfzWjPB2cLv1sE8xc9YULclCbZAG3e3F1ZRDoRyNIEU8KGfB"
             "BDSrawW08LRntnpCAwN8FupyCUXeR0EC4WjV951_Uw9h1reXPtZFfod_sr"
             "ReMh3tj_0wNoJZs-pgtM-dEcWgCH8n7UDVNlw9C4ui6M3qWa-jUUmXBIjO"
             "qeB8lDSSPpbmqZzzoL4RAWqG3J6qU5_svdxs_Vl6KK7K4nVyNDQBlPT6x-"
             "WiBIITgtWSjI4DWDPHytSbukME6CbVwCTHzKKs-Vxsu9aMOEhVSoVWlcJI"
             "rdUMh9rkpJ0Rzbx8dXqx4AuP0h54VKiX3CG0Dwh7PfsTF3PZ2HQB5dUBer"
             "H4ZDD4if9mzJ4EvoY-fjitUn52RMjOk9C8LiVc3Dvi03hO0MEmSfX-"
             "u6usDI5MkXyL7yl3X6PbHqI_7dxglTnCM1Tc5yKu5xxFQHs02gBvJEUuoF"
             "52bmtdysk373Q6qQint88vPtiTHGHN00Pf32xYjRsfQJm6W-U-dpEJlmCH"
             "dGPEMQo2dn7ifg29MTKs9oiEIeEBLt84PU7slkPooQtQ4QUnxaFHRFizXl"
             "S4QfwCWZ7QfBkBVFJcR7heabCeggjc829-"
             "ONnxCQuNrwoyTXy0is4I2sEb5GBYXbqQYavn73JDQ6S68cdAkOjXkYZI0N"
             "3EN0O8Ax7snjopEthw9Q7c224pJFbEAABu9l6ywk4DjKPd-XXiomEaixh-"
             "M-UqrdwRnvnmQDxhkkp88in2YZ75us7ufATyZ1mWF0yTgHj1DMr21lgPzt"
             "AVZHI9KXmzO3f2iZUbfHe2UOSKhAhTkyYSwID5tVv8eN5kHgkCxVA7L2zE"
             "UGZHcblNVZCVe2aeoIuW82jhHrkFQn4mUO0YXWADq3BOI4iTAM3ZIAYNOT"
             "S0QHR4PbOXFyg4yb4xi1-"
             "JIFjmfZ7JQBmHDXWCKeYwGM2F1EkuDrjAqQ06Zm52Ft2rMxYB7JYRVykp7"
             "nS86NO_uKcIhY_b9mG-ofCSf25RkqhhUf0DsAGTbILabYwUehry6RsipAL"
             "OdY_XQyJqhw8-"
             "NjUjGjkKIMau4XKBiXncxNtei9mAK8XAv_2jXCiNAny63n1hWZaHmgkpK7"
             "PKLJcg50HlGVnYGMnfaQO7cRqTume4RTl90dV4xrk3-"
             "MPu5GdQRvPDAEqxBKQ2xVE1LnDVF5xDzkjF7nEHRN5FlrPEzbEhgdDZasD"
             "saaoUURWfq88_uImYCa7MTU8Jfoa0tzUhXInROw2v513wAgsivvSXO0V_V"
             "ItKiZjf95Iy7ERpUap-vJIhK64aBveCvpklpTLhDdAqraiUh2bEJ-"
             "1aV5k2679ceiyXYv2_4UxwssARg3is1kQFb-yDx3S1SGfjiJwq8RdmEIaq"
             "Wr3BvRvkHA9mND4OxRenpZhJsrWjepkM5Eh7CY292ReLKIQR9Dc2VMhz7o"
             "7QGBVrs0ARU7CW-FOqFMNlssMhVBPrzo3AfEuv3QJhPhZZBWpNAQ6XCzjc"
             "fhAHJAPYyWIu6_QDC2q2QPcCLVwsk4wMohVrwWFksjIGY94fkEpcDZ9j1G"
             "60EwgcgJryy8JH0mu2y3TFgCLLybfWCxfQMlXnNgJLYUarnxwcbWSLn98l"
             "amArfEadoEv_trc1VyigUwi5M2pJoVItfn7grS_SRyu5z4gqSFH1ultDPe"
             "9mb7C_7UNYr99bYAUFHnTBYkT0V5KIoNqML0lZj3Q",
        .ss = "I_IRuEpu4gyMKfblMUyRtBTpQFE9OArdF71ySrOhOlI",
        .ct_rej = "lqxiQ8mxJyvne5daQEi_AP8sSPlKNIM2JEknOIDUXlS9oVcpaCv1kadDgq"
             "cIvreBGMqymtdKwvQFunIAdt-"
             "1cYjcFoSHzSAIH2v0EvJX3qA0BrI6anUuR4uk75x8D0gQkh-jJUW-ZNxdn"
             "xjU4TIO_GUIFUzaNauRLQWeApGhFQrgoQ2l49e9IhqFHFmN9NCxjaqSCXZ"
             "VYJnRwN5OIi1TBNRPqcub1P_hV2ndbEeT-oCfUmTPD-vKS1l1uih2OXg6o"
             "fS2Rf96ANRu57Gf7Bez6DvK9DYdU0njDOq2DDhraw0bkNizNu5qYnrSo4Z"
             "wy1ETsPtKwt3EJQCXSD_v0YJnDqQPD0XM6Que1Y2vrvZX1k4l_WaSppchm"
             "U59ALSUkgXr5MT5xG7loQGLIgom2Ari0rSGNy6XTXWyCgBbFhatHhPRYpF"
             "cwk8nRnDR5ei9NFh0p-"
             "fJdZyOQ_8zaJIAc5phM5X3rnjXPGp7kPZatRHw3zxdyoXQuUMLTpcJhxX_"
             "gjthcyF5muoKucciNHgDOex7VB1eb4wVURRsJKZUEYEbI2dMJhIzVs8jM1"
             "E4LDmUy6XcbCWgfhuprzPsoYu6PpeTXjq98H6foyzs8kHnyvxlkttO5If_"
             "K5ikpHgF3uF_2TRI3JhFe3U-"
             "1Jle5rG_qf8dOGyR85bKj0jKtbCaeC7DthaoemRIqWI2xGVUE691UyPTao"
             "2y4WUJRUSJ5uyDYpEwzSpUgXkYrzYsgxg0lLS1kNuvac85nT4tw-nAwSJP"
             "FI5l72goc0Grcq1Yrfxpso4n6R67-"
             "DD6xTuU92LwHMmxVhrjXxbtq_Uf8WTBMJ0f21LNK_7bWkkutly5_Ia48F7"
             "SbRMjP7Cj6zOp3OLPmOZRbO5C--HpfiCrbJll9Yo3fcc-"
             "UwZnq49F5qcLI9tQ8N9BFzLYrNq-UMUa24hsDlpSltSqGxOjNvDBeBL3n8"
             "aUGKfYkBxWj0EO_yr3S6rrgzb0bKF-FOBgzi1FzbN2KG7si4vvpauAJYAn"
             "IKHnOTr1edsT6IZ9Q9cR5hsu45UHeYSkUKjiUTBABoqTF5a8PQBptW0fBi"
             "_D3WGxsZS24fHRwFltRT23t1kqb5-"
             "KxVdqhVkGUSIAI0xA_JvZ3pw9YpHDG15ret5HOjeHqrDJWLPfdhiKhuz54"
             "6sG-"
             "W0exRjBvzNmvvlEZdnhpp6ybbng8IVtJ75QpSuwo6FwddZggP4dO9QhItZ"
             "WzMOlVuBPkT-vlkEUOTGmQOcvq50AMDjJgsrIFC5WE9uqudQTkFd6_nOsY"
             "j98GSDL8f61yFzEMzAMHFV50CDVSR7dbFAxF7nE1ZhDiTiDHlw0HpyGzQD"
             "djUMgtlb5q6nw5VJyTjgo_C4AlGEhZjrTrZiiXn0wjaGgNHxNz8eY45UnC"
             "tB8_fD_jjJ42uIKsmZM3zCl0Ov-"
             "eh55nsRLUU4C8r6XONTigDa0d2vUBAhs_HhdMvh6QVViJkSxMRhdFw-gbv"
             "9C1rW1oQMMlAmTLOiStiJbx7OQGloxeFpHqf2iII1NjvGfFtoKbp5xKa0I"
             "78hhxj4s4hI4SPM_NeWYtLq3MFHSRWjr9DWhT3lf38A24aYH5Xb7IVtPrz"
             "NwwZvRjFiE91ARYeEltBOOC9I6aOO_D4iwGmpocsSGYWn-"
             "0ObRbHVCVHEMA2xlRbJTauYXw_uG_KbekOOX3XwIRFIrAiRTZdYl_w7Ca4"
             "S_WDQmmpDi0iviuA7pqK979Lykvm8Y-Z9txp7cyF9XAZhwXk0P9NIy4c-"
             "w5yX8rNF5qqzhb_ZIHtIG1W5vjFgy3gqBFAFLvwW2muVqMaSeqwlzIHLUa"
             "sIfcQPIAI1pfIrWzfRxl4XPmdaYlad2dWNdekctSlu8qiTcSbIVNRvtNxi"
             "y1NuvxUwHfsW1a9Nru30d_ZaNGH9-"
             "oYpBPXu6HbYBIlZcNC7itMO6ZJr0LtBdCxBwNZogpW4gEShUhdoDnge2ne"
             "R6OSyjq-d5KC-w4DId8Kpw3I2le791c36lSSx98XQzqaYOMFSfQOw-FGYg"
             "MPvJaD8vkSuZL_NFZmKwRKxNSD_Qoq8Bj2Txq6_CAI64AFVK2nD8VaeerY"
             "ioL8L_Aaotx37XFd8",
        .ss_rej = "JH0_7Yys2wa95jfHSf7miaLMChQl6cW47JAZLvS9oYA",
    },
};

static void
test_kat(const jose_hook_alg_t *a)
{
    const struct kat *k = NULL;

    for (size_t i = 0; i < sizeof(kats) / sizeof(kats[0]); i++) {
        if (strcmp(kats[i].alg, a->name) == 0) {
            k = &kats[i];
            break;
        }
    }

    /* Every KEM algorithm must be covered by a reference KAT. */
    assert(k);

    json_auto_t *prv = json_pack("{s:s,s:s,s:s}",
                                 "kty", "AKP", "alg", a->name, "priv", k->priv);
    json_auto_t *pub = json_pack("{s:s,s:s,s:s}",
                                 "kty", "AKP", "alg", a->name, "pub", k->pub);
    json_auto_t *ct = json_string(k->ct);
    json_auto_t *ct_rej = json_string(k->ct_rej);
    assert(prv && pub && ct && ct_rej);

    /* Decapsulating the reference ciphertext must produce the exact
     * reference shared secret. */
    json_auto_t *ss = jose_jwk_kem_dec(NULL, prv, ct);
    assert(ss);
    const char *ss1 = json_string_value(json_object_get(ss, "k"));
    assert(ss1);
    assert(strcmp(ss1, k->ss) == 0);

    /* An invalid ciphertext must produce the reference implicit
     * rejection shared secret. */
    json_auto_t *ss_rej = jose_jwk_kem_dec(NULL, prv, ct_rej);
    assert(ss_rej);
    const char *ss2 = json_string_value(json_object_get(ss_rej, "k"));
    assert(ss2);
    assert(strcmp(ss2, k->ss_rej) == 0);

    /* Encapsulation against the reference public key must agree with
     * decapsulation by the seed, which only holds if the keypair
     * derived from the seed matches the reference public key. */
    json_auto_t *enc = jose_jwk_kem_enc(NULL, pub);
    assert(enc);
    json_auto_t *ss_enc = jose_jwk_kem_dec(NULL, prv, json_object_get(enc, "ct"));
    assert(ss_enc);
    const char *ss3 = json_string_value(json_object_get(json_object_get(enc, "ss"), "k"));
    const char *ss4 = json_string_value(json_object_get(ss_enc, "k"));
    assert(ss3 && ss4);
    assert(strcmp(ss3, ss4) == 0);

    /* The thumbprint must match the pinned reference value, and must
     * not depend on the presence of private material. */
    {
        json_auto_t *thp = jose_jwk_thp(NULL, pub, "S256");
        json_auto_t *both = json_pack("{s:s,s:s,s:s,s:s}",
                                      "kty", "AKP", "alg", a->name,
                                      "pub", k->pub, "priv", k->priv);
        json_auto_t *thp2 = both ? jose_jwk_thp(NULL, both, "S256") : NULL;
        const char *t1 = thp ? json_string_value(thp) : NULL;
        const char *t2 = thp2 ? json_string_value(thp2) : NULL;
        assert(t1 && t2);
        assert(strcmp(t1, k->thp) == 0);
        assert(strcmp(t1, t2) == 0);
    }
}

static void
test_invalid_pub_key(void)
{
    /* Use a wrong-length buffer: ML-KEM-768 expects 1184 bytes */
    unsigned char bad_pub[100];
    memset(bad_pub, 0x42, sizeof(bad_pub));

    json_auto_t *pub_b64 = jose_b64_enc(bad_pub, sizeof(bad_pub));
    assert(pub_b64);

    json_auto_t *jwk = json_pack("{s:s,s:s,s:O}",
                                 "kty", "AKP",
                                 "alg", "ML-KEM-768",
                                 "pub", pub_b64);
    assert(jwk);

    json_auto_t *result = jose_jwk_kem_enc(NULL, jwk);
    assert(!result);
}

int
main(int argc, char *argv[])
{
    bool found = false;

    for (const jose_hook_alg_t *a = jose_hook_alg_list(); a; a = a->next) {
        if (a->kind != JOSE_HOOK_ALG_KIND_KEM)
            continue;

        found = true;
        fprintf(stderr, "alg: %s\n", a->name);

        test_roundtrip(a);
        fprintf(stderr, "  roundtrip: OK\n");

        test_implicit_rejection(a);
        fprintf(stderr, "  implicit rejection: OK\n");

        test_cross_key(a);
        fprintf(stderr, "  cross-key rejection: OK\n");

        test_pub_only_decap_fails(a);
        fprintf(stderr, "  pub-only decap rejected: OK\n");

        test_key_ops(a);
        fprintf(stderr, "  key_ops: OK\n");

        test_alloc_failures(a);
        fprintf(stderr, "  allocation failure injection: OK\n");

        test_key_use_denial(a);
        fprintf(stderr, "  key_ops/use denial: OK\n");

        test_conflicting_kty(a);
        fprintf(stderr, "  conflicting kty rejected: OK\n");

        test_thumbprint(a);
        fprintf(stderr, "  thumbprint: OK\n");

        test_seed_format(a);
        fprintf(stderr, "  seed format (64 bytes): OK\n");

        test_seed_determinism(a);
        fprintf(stderr, "  seed determinism: OK\n");

        test_wrong_priv_len(a);
        fprintf(stderr, "  wrong priv length rejected: OK\n");

        test_kat(a);
        fprintf(stderr, "  reference KAT: OK\n");
    }

    if (!found) {
        fprintf(stderr, "No KEM algorithms available (OpenSSL < 3.5?)\n");
        return 77;
    }

    test_invalid_pub_key();
    fprintf(stderr, "  invalid pub key rejected: OK\n");

    return EXIT_SUCCESS;
}
