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
    }

    if (!found) {
        fprintf(stderr, "No KEM algorithms available (OpenSSL < 3.5?)\n");
        return 77;
    }

    return EXIT_SUCCESS;
}
