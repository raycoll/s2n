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

int s2n_aead_record_parse(struct s2n_connection *conn)
{
    struct s2n_blob en, iv;
    struct s2n_blob aad;
    uint8_t content_type;
    uint16_t fragment_length;
    uint8_t aad_gen[S2N_TLS_MAX_AAD_LEN] = { 0 };
    uint8_t aad_iv[S2N_TLS_MAX_IV_LEN] = { 0 };

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

    uint16_t encrypted_length = fragment_length;

    en.size = encrypted_length;
    en.data = s2n_stuffer_raw_read(&conn->in, en.size);
    notnull_check(en.data);

    uint16_t payload_length = encrypted_length;

    /* In AEAD mode, the explicit IV is in the record */
    gte_check(en.size, cipher_suite->record_alg->cipher->io.aead.record_iv_size);

    struct s2n_stuffer iv_stuffer;
    iv.data = aad_iv;
    iv.size = sizeof(aad_iv);

    GUARD(s2n_stuffer_init(&iv_stuffer, &iv));
    GUARD(s2n_stuffer_write_bytes(&iv_stuffer, implicit_iv, cipher_suite->record_alg->cipher->io.aead.fixed_iv_size));
    GUARD(s2n_stuffer_write_bytes(&iv_stuffer, en.data, cipher_suite->record_alg->cipher->io.aead.record_iv_size));

    /* Set the IV size to the amount of data written */
    iv.size = s2n_stuffer_data_available(&iv_stuffer);

    aad.data = aad_gen;
    aad.size = sizeof(aad_gen);

    /* remove the AEAD overhead from the record size */
    gte_check(payload_length, cipher_suite->record_alg->cipher->io.aead.record_iv_size + cipher_suite->record_alg->cipher->io.aead.tag_size);
    payload_length -= cipher_suite->record_alg->cipher->io.aead.record_iv_size;
    payload_length -= cipher_suite->record_alg->cipher->io.aead.tag_size;

    struct s2n_stuffer ad_stuffer;
    GUARD(s2n_stuffer_init(&ad_stuffer, &aad));
    GUARD(s2n_aead_aad_init(conn, sequence_number, content_type, payload_length, &ad_stuffer));


    /* Skip explicit IV for decryption */
    en.size -= cipher_suite->record_alg->cipher->io.aead.record_iv_size;
    en.data += cipher_suite->record_alg->cipher->io.aead.record_iv_size;

    /* Check that we have some data to decrypt */
    ne_check(en.size, 0);

    /* Decrypt stuff! */
    GUARD(cipher_suite->record_alg->cipher->io.aead.decrypt(session_key, &iv, &aad, &en, &en));

    struct s2n_blob seq = {.data = sequence_number,.size = S2N_TLS_SEQUENCE_NUM_LEN };
    GUARD(s2n_increment_sequence_number(&seq));

    /* O.k., we've successfully read and decrypted the record, now we need to align the stuffer
     * for reading the plaintext data.
     */
    GUARD(s2n_stuffer_reread(&conn->in));
    GUARD(s2n_stuffer_reread(&conn->header_in));

    /* Skip the IV, if any */
    if (conn->actual_protocol_version >= S2N_TLS12) {
        GUARD(s2n_stuffer_skip_read(&conn->in, cipher_suite->record_alg->cipher->io.aead.record_iv_size));
    }

    /* Truncate and wipe the MAC and any padding */
    GUARD(s2n_stuffer_wipe_n(&conn->in, s2n_stuffer_data_available(&conn->in) - payload_length));
    conn->in_status = PLAINTEXT;

    return 0;
}

int s2n_aead_record_write(struct s2n_connection *conn, uint8_t content_type, struct s2n_blob *in)
{
    struct s2n_blob out, aad, iv;
    uint8_t protocol_version[S2N_TLS_PROTOCOL_VERSION_LEN];
    uint8_t aad_gen[S2N_TLS_MAX_AAD_LEN] = { 0 };
    uint8_t aad_iv[S2N_TLS_MAX_IV_LEN] = { 0 };

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
    uint16_t extra = s2n_record_overhead(conn);

    /* Now that we know the length, start writing the record */
    protocol_version[0] = conn->actual_protocol_version / 10;
    protocol_version[1] = conn->actual_protocol_version % 10;
    GUARD(s2n_stuffer_write_uint8(&conn->out, content_type));
    GUARD(s2n_stuffer_write_bytes(&conn->out, protocol_version, S2N_TLS_PROTOCOL_VERSION_LEN));

    GUARD(s2n_stuffer_write_uint16(&conn->out, data_bytes_to_take + extra));

    /* Write the sequence number as an IV, and generate the AAD */
    GUARD(s2n_stuffer_write_bytes(&conn->out, sequence_number, S2N_TLS_SEQUENCE_NUM_LEN));

    struct s2n_stuffer iv_stuffer;
    iv.data = aad_iv;
    iv.size = sizeof(aad_iv);

    GUARD(s2n_stuffer_init(&iv_stuffer, &iv));
    GUARD(s2n_stuffer_write_bytes(&iv_stuffer, implicit_iv, cipher_suite->record_alg->cipher->io.aead.fixed_iv_size));
    GUARD(s2n_stuffer_write_bytes(&iv_stuffer, sequence_number, S2N_TLS_SEQUENCE_NUM_LEN));

    /* Set the IV size to the amount of data written */
    iv.size = s2n_stuffer_data_available(&iv_stuffer);

    aad.data = aad_gen;
    aad.size = sizeof(aad_gen);

    struct s2n_stuffer ad_stuffer;
    GUARD(s2n_stuffer_init(&ad_stuffer, &aad));
    GUARD(s2n_aead_aad_init(conn, sequence_number, content_type, data_bytes_to_take, &ad_stuffer));

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

    GUARD(s2n_stuffer_skip_write(&conn->out, cipher_suite->record_alg->cipher->io.aead.record_iv_size));
    encrypted_length += cipher_suite->record_alg->cipher->io.aead.tag_size;

    /* Do the encryption */
    struct s2n_blob en;
    en.size = encrypted_length;
    en.data = s2n_stuffer_raw_write(&conn->out, en.size);
    notnull_check(en.data);
    GUARD(cipher_suite->record_alg->cipher->io.aead.encrypt(session_key, &iv, &aad, &en, &en));

    conn->wire_bytes_out += data_bytes_to_take + S2N_TLS_RECORD_HEADER_LENGTH;
    return data_bytes_to_take;
}
