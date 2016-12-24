/*
 * Copyright 2014 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include <stdint.h>
#include <sys/param.h>

#include "error/s2n_errno.h"

#include "tls/s2n_cipher_suites.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_record.h"
#include "tls/s2n_crypto.h"

#include "stuffer/s2n_stuffer.h"

#include "crypto/s2n_sequence.h"
#include "crypto/s2n_cipher.h"

#include "utils/s2n_safety.h"
#include "utils/s2n_random.h"
#include "utils/s2n_blob.h"

int s2n_composite_record_parse(struct s2n_connection *conn)
{
    struct s2n_blob iv;
    struct s2n_blob en;
    uint8_t content_type;
    uint16_t fragment_length;
    uint8_t ivpad[S2N_TLS_MAX_IV_LEN];

    uint8_t *sequence_number = conn->client->client_sequence_number;
    struct s2n_session_key *session_key = &conn->client->client_key;
    struct s2n_cipher_suite *cipher_suite = conn->client->cipher_suite;
    uint8_t *implicit_iv = conn->client->client_implicit_iv;

    if (conn->mode == S2N_CLIENT) {
        sequence_number = conn->server->server_sequence_number;
        session_key = &conn->server->server_key;
        cipher_suite = conn->server->cipher_suite;
        implicit_iv = conn->server->server_implicit_iv;
    }

    GUARD(s2n_record_header_parse(conn, &content_type, &fragment_length));

    /* Add the header to the HMAC */
    uint8_t *header = s2n_stuffer_raw_read(&conn->header_in, S2N_TLS_RECORD_HEADER_LENGTH);
    notnull_check(header);

    uint16_t encrypted_length = fragment_length;
    /* Don't reduce encrypted length for explicit IV, composite decrypt expects it */
    iv.data = implicit_iv;
    iv.size = cipher_suite->record_alg->cipher->io.comp.record_iv_size;

    en.size = encrypted_length;
    en.data = s2n_stuffer_raw_read(&conn->in, en.size);
    notnull_check(en.data);

    uint16_t payload_length = encrypted_length;

    /* Compute non-payload parts of the MAC(seq num, type, proto vers, fragment length) for composite ciphers.
     * Composite "decrypt" will MAC the actual payload data.
     * In the decrypt case, this outputs the MAC digest length:
     * https://github.com/openssl/openssl/blob/master/crypto/evp/e_aes_cbc_hmac_sha1.c#L842
     */
    int mac_size;
    GUARD(cipher_suite->record_alg->cipher->io.comp.initial_hmac(session_key, sequence_number, content_type, conn->actual_protocol_version,
                                                     payload_length, &mac_size));

    payload_length -= mac_size;

    /* Adjust payload_length for explicit IV */
    if (conn->actual_protocol_version > S2N_TLS10) {
        payload_length -= cipher_suite->record_alg->cipher->io.comp.record_iv_size;
    }

    /* Decrypt stuff! */
    ne_check(en.size, 0);
    eq_check(en.size % iv.size,  0);

    /* Copy the last encrypted block to be the next IV */
    memcpy_check(ivpad, en.data + en.size - iv.size, iv.size);

    /* This will: Skip the explicit IV(if applicable), decrypt the payload, verify the MAC and padding. */
    GUARD((cipher_suite->record_alg->cipher->io.comp.decrypt(session_key, &iv, &en, &en)));

    memcpy_check(implicit_iv, ivpad, iv.size);

    /* Subtract the padding length */
    gt_check(en.size, 0);
    payload_length -= (en.data[en.size - 1] + 1);

    struct s2n_blob seq = {.data = sequence_number,.size = S2N_TLS_SEQUENCE_NUM_LEN };
    GUARD(s2n_increment_sequence_number(&seq));

    /* O.k., we've successfully read and decrypted the record, now we need to align the stuffer
     * for reading the plaintext data.
     */
    GUARD(s2n_stuffer_reread(&conn->in));
    GUARD(s2n_stuffer_reread(&conn->header_in));

    /* Skip the IV, if any */
    if (conn->actual_protocol_version > S2N_TLS10) {
        GUARD(s2n_stuffer_skip_read(&conn->in, cipher_suite->record_alg->cipher->io.comp.record_iv_size));
    }

    /* Truncate and wipe the MAC and any padding */
    GUARD(s2n_stuffer_wipe_n(&conn->in, s2n_stuffer_data_available(&conn->in) - payload_length));
    conn->in_status = PLAINTEXT;

    return 0;
}

int s2n_composite_record_write(struct s2n_connection *conn, uint8_t content_type, struct s2n_blob *in)
{
    struct s2n_blob out, iv;
    uint8_t padding = 0;
    uint16_t block_size = 0;
    uint8_t protocol_version[S2N_TLS_PROTOCOL_VERSION_LEN];

    uint8_t *sequence_number = conn->server->server_sequence_number;
    struct s2n_session_key *session_key = &conn->server->server_key;
    struct s2n_cipher_suite *cipher_suite = conn->server->cipher_suite;
    uint8_t *implicit_iv = conn->server->server_implicit_iv;

    if (conn->mode == S2N_CLIENT) {
        sequence_number = conn->client->client_sequence_number;
        session_key = &conn->client->client_key;
        cipher_suite = conn->client->cipher_suite;
        implicit_iv = conn->client->client_implicit_iv;
    }

    if (s2n_stuffer_data_available(&conn->out)) {
        S2N_ERROR(S2N_ERR_BAD_MESSAGE);
    }

    /* Before we do anything, we need to figure out what the length of the
     * fragment is going to be.
     */
    uint16_t data_bytes_to_take = MIN(in->size, s2n_record_max_write_payload_size(conn));

    uint16_t extra = overhead(conn);

    block_size = cipher_suite->record_alg->cipher->io.comp.block_size;

    /* Now that we know the length, start writing the record */
    protocol_version[0] = conn->actual_protocol_version / 10;
    protocol_version[1] = conn->actual_protocol_version % 10;
    GUARD(s2n_stuffer_write_uint8(&conn->out, content_type));
    GUARD(s2n_stuffer_write_bytes(&conn->out, protocol_version, S2N_TLS_PROTOCOL_VERSION_LEN));

    /* First write a header that has the payload length, this is for the MAC */
    GUARD(s2n_stuffer_write_uint16(&conn->out, data_bytes_to_take));

    /* Compute non-payload parts of the MAC(seq num, type, proto vers, fragment length) for composite ciphers.
     * Composite "encrypt" will MAC the payload data and filling in padding.
     * Only fragment length is needed for MAC, but the EVP ctrl function needs fragment length + eiv len.
     */
    uint16_t payload_and_eiv_len = data_bytes_to_take;
    if (conn->actual_protocol_version > S2N_TLS10) {
        payload_and_eiv_len += block_size;
    }

    /* Outputs number of extra bytes required for MAC and padding */
    int pad_and_mac_len;
    GUARD(cipher_suite->record_alg->cipher->io.comp.initial_hmac(session_key, sequence_number, content_type, conn->actual_protocol_version,
                                                     payload_and_eiv_len, &pad_and_mac_len));
    extra += pad_and_mac_len;


    /* Rewrite the length to be the actual fragment length */
    uint16_t actual_fragment_length = data_bytes_to_take + padding + extra;
    GUARD(s2n_stuffer_wipe_n(&conn->out, 2));
    GUARD(s2n_stuffer_write_uint16(&conn->out, actual_fragment_length));

    iv.size = block_size;
    iv.data = implicit_iv;

    /* For TLS1.1/1.2; write the IV with random data */
    if (conn->actual_protocol_version > S2N_TLS10) {
        GUARD(s2n_get_public_random_data(&iv));
        GUARD(s2n_stuffer_write(&conn->out, &iv));
    }

    /* We are done with this sequence number, so we can increment it */
    struct s2n_blob seq = {.data = sequence_number,.size = S2N_TLS_SEQUENCE_NUM_LEN };
    GUARD(s2n_increment_sequence_number(&seq));

    /* Write the plaintext data */
    out.data = in->data;
    out.size = data_bytes_to_take;
    GUARD(s2n_stuffer_write(&conn->out, &out));

    /* Rewind to rewrite/encrypt the packet */
    GUARD(s2n_stuffer_rewrite(&conn->out));

    /* Skip the header */
    GUARD(s2n_stuffer_skip_write(&conn->out, S2N_TLS_RECORD_HEADER_LENGTH));

    uint16_t encrypted_length = data_bytes_to_take;

    /* Composite CBC expects a pointer starting at explicit IV: [Explicit IV | fragment | MAC | padding | padding len ]
     * extra will account for the explicit IV len(if applicable), MAC digest len, padding len + padding byte.
     */
    encrypted_length += extra;

    /* Do the encryption */
    struct s2n_blob en;
    en.size = encrypted_length;
    en.data = s2n_stuffer_raw_write(&conn->out, en.size);
    notnull_check(en.data);

    /* This will: compute mac, append padding, append padding length, and encrypt */
    GUARD(cipher_suite->record_alg->cipher->io.comp.encrypt(session_key, &iv, &en, &en));

    /* Copy the last encrypted block to be the next IV */
    gte_check(en.size, block_size);
    memcpy_check(implicit_iv, en.data + en.size - block_size, block_size);

    conn->wire_bytes_out += actual_fragment_length + S2N_TLS_RECORD_HEADER_LENGTH;
    return data_bytes_to_take;
}

