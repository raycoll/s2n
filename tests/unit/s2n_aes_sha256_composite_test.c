/*
 * Copyright 2017 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

#include "s2n_test.h"

#include <s2n.h>
#include <string.h>
#include <openssl/evp.h>

#include "testlib/s2n_testlib.h"

#include "tls/s2n_record.h"
#include "tls/s2n_cipher_suites.h"

#include "stuffer/s2n_stuffer.h"

#include "utils/s2n_random.h"
#include "utils/s2n_safety.h"

#include "crypto/s2n_cipher.h"
#include "crypto/s2n_hmac.h"
#include "crypto/s2n_hash.h"

/* Prepare connection for another round of encryption/decryption */
static int test_connection_reset(struct s2n_connection *conn, uint8_t proto_vers, const struct s2n_record_algorithm *record_alg, struct s2n_blob *enc_key, struct s2n_blob *mac_key, struct s2n_blob *in)
{
    GUARD(s2n_connection_wipe(conn));
    conn->actual_protocol_version = proto_vers;
    conn->initial.cipher_suite->record_alg = record_alg;
    GUARD(conn->initial.cipher_suite->record_alg->cipher->set_encryption_key(&conn->initial.server_key, enc_key));
    GUARD(conn->initial.cipher_suite->record_alg->cipher->set_decryption_key(&conn->initial.client_key, enc_key));
    GUARD(conn->initial.cipher_suite->record_alg->cipher->io.comp.set_mac_write_key(&conn->initial.server_key, mac_key->data, mac_key->size));
    GUARD(conn->initial.cipher_suite->record_alg->cipher->io.comp.set_mac_write_key(&conn->initial.client_key, mac_key->data, mac_key->size));

    return 0;
}

/* Move encrypted output stuffers to input for decrypt tests */
static int copy_output_to_input(struct s2n_connection *conn)
{
    GUARD(s2n_stuffer_wipe(&conn->in));
    GUARD(s2n_stuffer_wipe(&conn->header_in));
    GUARD(s2n_stuffer_copy(&conn->out, &conn->header_in, 5));
    GUARD(s2n_stuffer_copy(&conn->out, &conn->in, s2n_stuffer_data_available(&conn->out)));

    return 0;
}

int main(int argc, char **argv)
{
    struct s2n_connection *conn;
    uint8_t random_data[S2N_DEFAULT_FRAGMENT_LENGTH + 1];
    uint8_t mac_key_sha256[SHA256_DIGEST_LENGTH] = "server key sha256server key sha";
    uint8_t aes128_key[] = "123456789012345";
    uint8_t aes256_key[] = "1234567890123456789012345678901";
    struct s2n_blob aes128 = {.data = aes128_key,.size = sizeof(aes128_key) };
    struct s2n_blob aes256 = {.data = aes256_key,.size = sizeof(aes256_key) };
    struct s2n_blob mac_key = {.data = mac_key_sha256,.size = sizeof(mac_key_sha256) };
    struct s2n_blob r = {.data = random_data, .size = sizeof(random_data)};

    BEGIN_TEST();

    /* Skip test if we can't use the ciphers */
    if (!s2n_aes128_sha256.is_available() || !s2n_aes256_sha256.is_available()) {
        END_TEST();
    }

    EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
    EXPECT_SUCCESS(s2n_get_urandom_data(&r));

    /* Peer and we are in sync */
    conn->server = &conn->initial;
    conn->client = &conn->initial;

    int max_aligned_fragment = S2N_DEFAULT_FRAGMENT_LENGTH - (S2N_DEFAULT_FRAGMENT_LENGTH % 16);
    uint8_t proto_versions[] = { S2N_TLS10, S2N_TLS11, S2N_TLS12 };

    /* test the composite AES128_SHA256 cipher  */
    conn->initial.cipher_suite->record_alg = &s2n_record_alg_aes128_sha256_composite;

    /* It's important to verify all TLS versions for the composite implementation.
     * There are a few gotchas with respect to explicit IV length and payload length
     */
    for (int j = 0; j < 3; j++ ) {
        for (int i = 0; i < max_aligned_fragment; i++) {
            struct s2n_blob in = {.data = random_data,.size = i };
            int bytes_written;

            EXPECT_SUCCESS(s2n_connection_wipe(conn));
            test_connection_reset(conn, proto_versions[j], &s2n_record_alg_aes128_sha256_composite, &aes128, &mac_key, &in);
            EXPECT_SUCCESS(bytes_written = s2n_record_write(conn, TLS_APPLICATION_DATA, &in));

            const uint16_t block_size = 16;
            const uint16_t mac_size = SHA256_DIGEST_LENGTH;
            /* explicit IV is added to CBC records in TLS1.1 and TLS1.2 */
            const uint16_t explicit_iv_length = (proto_versions[j] > S2N_TLS10) ? block_size : 0;
            const uint16_t prepadded_length = bytes_written + 1 + mac_size + explicit_iv_length;
            const uint16_t padding_length = (prepadded_length % block_size) ? (block_size - (prepadded_length % block_size)) : 0;
            const uint16_t predicted_length = prepadded_length + padding_length;

            if (i < max_aligned_fragment - mac_size - explicit_iv_length - 1) {
                EXPECT_EQUAL(bytes_written, i);
            } else {
                EXPECT_EQUAL(bytes_written, max_aligned_fragment - mac_size - explicit_iv_length - 1);
            }

            EXPECT_EQUAL(conn->out.blob.data[0], TLS_APPLICATION_DATA);
            uint8_t record_version = conn->out.blob.data[1] * 10 + conn->out.blob.data[2];
            EXPECT_EQUAL(record_version, conn->actual_protocol_version);
            EXPECT_EQUAL(conn->out.blob.data[3], (predicted_length >> 8) & 0xff);
            EXPECT_EQUAL(conn->out.blob.data[4], predicted_length & 0xff);

            /* The data should be encrypted */
            if (bytes_written > 10) {
                EXPECT_NOT_EQUAL(memcmp(conn->out.blob.data + 5, random_data, bytes_written), 0);
            }

            /* Copy the encrypted out data to the in data */
            EXPECT_SUCCESS(copy_output_to_input(conn));

            /* Let's decrypt it */
            uint8_t content_type;
            uint16_t fragment_length;
            EXPECT_SUCCESS(s2n_record_header_parse(conn, &content_type, &fragment_length));
            EXPECT_SUCCESS(s2n_record_parse(conn));
            EXPECT_EQUAL(content_type, TLS_APPLICATION_DATA);
            EXPECT_EQUAL(fragment_length, predicted_length);

            EXPECT_SUCCESS(s2n_stuffer_wipe(&conn->header_in));
            EXPECT_SUCCESS(s2n_stuffer_wipe(&conn->in));

            /* Tamper the protocol version in the header and ensure decryption fails. We supply this data as part of
             * the composite AAD. */
            EXPECT_SUCCESS(test_connection_reset(conn, proto_versions[j], &s2n_record_alg_aes128_sha256_composite, &aes128, &mac_key, &in));
            GUARD(s2n_record_write(conn, TLS_APPLICATION_DATA, &in));
            EXPECT_SUCCESS(copy_output_to_input(conn));
            conn->in.blob.data[2] = 0xFF;
            EXPECT_SUCCESS(s2n_record_header_parse(conn, &content_type, &fragment_length));
            EXPECT_FAILURE(s2n_record_parse(conn));
            EXPECT_EQUAL(content_type, TLS_APPLICATION_DATA);

            /* Tamper with the explicit IV and ensure decryption fails */
            if (proto_versions[i] > S2N_TLS10) {
                EXPECT_SUCCESS(test_connection_reset(conn, proto_versions[j], &s2n_record_alg_aes128_sha256_composite, &aes128, &mac_key, &in));
                GUARD(s2n_record_write(conn, TLS_APPLICATION_DATA, &in));
                EXPECT_SUCCESS(copy_output_to_input(conn));
                conn->in.blob.data[5 + (explicit_iv_length - j - 1)]++;
                EXPECT_FAILURE(s2n_record_parse(conn));
            }

            /* Tamper with ciphertext and make sure decryption fails */
            EXPECT_SUCCESS(test_connection_reset(conn, proto_versions[j], &s2n_record_alg_aes128_sha256_composite, &aes128, &mac_key, &in));
            EXPECT_SUCCESS(s2n_record_write(conn, TLS_APPLICATION_DATA, &in));
            EXPECT_SUCCESS(copy_output_to_input(conn));
            conn->in.blob.data[5 + explicit_iv_length + j]++;
            EXPECT_SUCCESS(s2n_record_header_parse(conn, &content_type, &fragment_length));
            EXPECT_EQUAL(content_type, TLS_APPLICATION_DATA);
            EXPECT_FAILURE(s2n_record_parse(conn));

            /* Tamper with the MAC and ensure decryption fails */
            EXPECT_SUCCESS(test_connection_reset(conn, proto_versions[j], &s2n_record_alg_aes128_sha256_composite, &aes128, &mac_key, &in));
            EXPECT_SUCCESS(s2n_record_write(conn, TLS_APPLICATION_DATA, &in));
            EXPECT_SUCCESS(copy_output_to_input(conn));
            conn->in.blob.data[prepadded_length - j - 1]++;
            EXPECT_SUCCESS(s2n_record_header_parse(conn, &content_type, &fragment_length));
            EXPECT_FAILURE(s2n_record_parse(conn));
            EXPECT_EQUAL(content_type, TLS_APPLICATION_DATA);

            /* Tamper with the padding and ensure decryption fails */
            EXPECT_SUCCESS(test_connection_reset(conn, proto_versions[j], &s2n_record_alg_aes128_sha256_composite, &aes128, &mac_key, &in));
            EXPECT_SUCCESS(s2n_record_write(conn, TLS_APPLICATION_DATA, &in));
            EXPECT_SUCCESS(copy_output_to_input(conn));
            conn->in.blob.data[predicted_length - j - 1]++;
            EXPECT_SUCCESS(s2n_record_header_parse(conn, &content_type, &fragment_length));
            EXPECT_FAILURE(s2n_record_parse(conn));
            EXPECT_EQUAL(content_type, TLS_APPLICATION_DATA);
        }
    }

    /* test the composite AES256_SHA256 cipher  */
    conn->initial.cipher_suite->record_alg = &s2n_record_alg_aes256_sha256_composite;
    for (int j = 0; j < 3; j++ ) {
        for (int i = 0; i < max_aligned_fragment; i++) {
            struct s2n_blob in = {.data = random_data,.size = i };
            int bytes_written;

            EXPECT_SUCCESS(s2n_connection_wipe(conn));
            test_connection_reset(conn, proto_versions[j], &s2n_record_alg_aes256_sha256_composite, &aes256, &mac_key, &in);
            EXPECT_SUCCESS(bytes_written = s2n_record_write(conn, TLS_APPLICATION_DATA, &in));

            const uint16_t block_size = 16;
            const uint16_t mac_size = SHA256_DIGEST_LENGTH;
            /* explicit IV is added to CBC records in TLS1.1 and TLS1.2 */
            const uint16_t explicit_iv_length = (proto_versions[j] > S2N_TLS10) ? block_size : 0;
            const uint16_t prepadded_length = bytes_written + 1 + mac_size + explicit_iv_length;
            const uint16_t padding_length = (prepadded_length % block_size) ? (block_size - (prepadded_length % block_size)) : 0;
            const uint16_t predicted_length = prepadded_length + padding_length;

            if (i < max_aligned_fragment - mac_size - explicit_iv_length - 1) {
                EXPECT_EQUAL(bytes_written, i);
            } else {
                EXPECT_EQUAL(bytes_written, max_aligned_fragment - mac_size - explicit_iv_length - 1);
            }

            EXPECT_EQUAL(conn->out.blob.data[0], TLS_APPLICATION_DATA);
            uint8_t record_version = conn->out.blob.data[1] * 10 + conn->out.blob.data[2];
            EXPECT_EQUAL(record_version, conn->actual_protocol_version);
            EXPECT_EQUAL(conn->out.blob.data[3], (predicted_length >> 8) & 0xff);
            EXPECT_EQUAL(conn->out.blob.data[4], predicted_length & 0xff);

            /* The data should be encrypted */
            if (bytes_written > 10) {
                EXPECT_NOT_EQUAL(memcmp(conn->out.blob.data + 5, random_data, bytes_written), 0);
            }

            /* Copy the encrypted out data to the in data */
            EXPECT_SUCCESS(copy_output_to_input(conn));

            /* Let's decrypt it */
            uint8_t content_type;
            uint16_t fragment_length;
            EXPECT_SUCCESS(s2n_record_header_parse(conn, &content_type, &fragment_length));
            EXPECT_SUCCESS(s2n_record_parse(conn));
            EXPECT_EQUAL(content_type, TLS_APPLICATION_DATA);
            EXPECT_EQUAL(fragment_length, predicted_length);

            EXPECT_SUCCESS(s2n_stuffer_wipe(&conn->header_in));
            EXPECT_SUCCESS(s2n_stuffer_wipe(&conn->in));

            /* Start over */
            EXPECT_SUCCESS(test_connection_reset(conn, proto_versions[j], &s2n_record_alg_aes256_sha256_composite, &aes256, &mac_key, &in));
            GUARD(s2n_record_write(conn, TLS_APPLICATION_DATA, &in));
            EXPECT_SUCCESS(copy_output_to_input(conn));
            /* Tamper the protocol version in the header and ensure decryption fails. We supply this data as part of
             * the composite AAD. */
            conn->in.blob.data[2] = 0xFF;
            EXPECT_SUCCESS(s2n_record_header_parse(conn, &content_type, &fragment_length));
            EXPECT_FAILURE(s2n_record_parse(conn));
            EXPECT_EQUAL(content_type, TLS_APPLICATION_DATA);

            /* Tamper with the explicit IV and ensure decryption fails */
            if (proto_versions[i] > S2N_TLS10) {
                EXPECT_SUCCESS(test_connection_reset(conn, proto_versions[j], &s2n_record_alg_aes256_sha256_composite, &aes256, &mac_key, &in));
                GUARD(s2n_record_write(conn, TLS_APPLICATION_DATA, &in));
                EXPECT_SUCCESS(copy_output_to_input(conn));
                conn->in.blob.data[5 + (explicit_iv_length - j - 1)]++;
                EXPECT_FAILURE(s2n_record_parse(conn));
            }

            /* Tamper with ciphertext and make sure decryption fails */
            EXPECT_SUCCESS(test_connection_reset(conn, proto_versions[j], &s2n_record_alg_aes256_sha256_composite, &aes256, &mac_key, &in));
            EXPECT_SUCCESS(s2n_record_write(conn, TLS_APPLICATION_DATA, &in));
            EXPECT_SUCCESS(copy_output_to_input(conn));
            conn->in.blob.data[5 + explicit_iv_length + j]++;
            EXPECT_SUCCESS(s2n_record_header_parse(conn, &content_type, &fragment_length));
            EXPECT_EQUAL(content_type, TLS_APPLICATION_DATA);
            EXPECT_FAILURE(s2n_record_parse(conn));

            /* Tamper with the MAC and ensure decryption fails */
            EXPECT_SUCCESS(test_connection_reset(conn, proto_versions[j], &s2n_record_alg_aes256_sha256_composite, &aes256, &mac_key, &in));
            EXPECT_SUCCESS(s2n_record_write(conn, TLS_APPLICATION_DATA, &in));
            EXPECT_SUCCESS(copy_output_to_input(conn));
            conn->in.blob.data[prepadded_length - j - 1]++;
            EXPECT_SUCCESS(s2n_record_header_parse(conn, &content_type, &fragment_length));
            EXPECT_FAILURE(s2n_record_parse(conn));
            EXPECT_EQUAL(content_type, TLS_APPLICATION_DATA);

            /* Tamper with the padding and ensure decryption fails */
            EXPECT_SUCCESS(test_connection_reset(conn, proto_versions[j], &s2n_record_alg_aes256_sha256_composite, &aes256, &mac_key, &in));
            EXPECT_SUCCESS(s2n_record_write(conn, TLS_APPLICATION_DATA, &in));
            EXPECT_SUCCESS(copy_output_to_input(conn));
            conn->in.blob.data[predicted_length - j - 1]++;
            EXPECT_SUCCESS(s2n_record_header_parse(conn, &content_type, &fragment_length));
            EXPECT_FAILURE(s2n_record_parse(conn));
            EXPECT_EQUAL(content_type, TLS_APPLICATION_DATA);
        }
    }

    END_TEST();
}
