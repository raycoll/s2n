/*
 * Copyright 2016 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include <isa-l_crypto.h> // should probably use a subdir here

#include "crypto/s2n_cipher.h"

#include "tls/s2n_crypto.h"

#include "utils/s2n_safety.h"
#include "utils/s2n_blob.h"

static uint32_t gcm_iv_trailer = 0x00000001U;

static int s2n_aead_cipher_aes128_gcm_encrypt(struct s2n_session_key *key, struct s2n_blob *iv, struct s2n_blob *aad, struct s2n_blob *in, struct s2n_blob *out)
{
    gte_check(in->size, S2N_TLS_GCM_TAG_LEN);
    gte_check(out->size, in->size);
    eq_check(iv->size, S2N_TLS_GCM_IV_LEN);

    /* Initialize the IV */
    if (EVP_EncryptInit_ex(key->evp_cipher_ctx, NULL, NULL, NULL, iv->data) != 1) {
        S2N_ERROR(S2N_ERR_KEY_INIT);
    }

    /* Adjust our buffer pointers to account for the explicit IV and TAG lengths */
    int in_len = in->size - S2N_TLS_GCM_TAG_LEN;
    uint8_t *tag_data = out->data + out->size - S2N_TLS_GCM_TAG_LEN;

    /* requires a 16 byte IV with 0x1 at the end*/
    uint8_t gcm_iv[16];
    memcpy(gcm_iv, iv->data, S2N_TLS_GCM_IV_LEN);
    memcpy(gcm_iv, &gcm_iv_trailer, 4);

    aesni_gcm128_enc(&key->gcm_data,
           out->data,   //!< Ciphertext output. Encrypt in-place is allowed.
           in->data,   //!< Plaintext input
           in_len,  //!< Length of data in Bytes for encryption.
           gcm_iv,    //!< Pre-counter block j0: 4 byte salt (from Security Association) concatenated with 8 byte Initialization Vector (from IPSec ESP Payload) concatenated with 0x00000001. 16-byte pointer.
           aad->data,  //!< Additional Authentication Data (AAD).
           aad->size,    //!< Length of AAD.
           tag_data,  //!< Authenticated Tag output.
           S2N_TLS_GCM_TAG_LEN   //!< Authenticated Tag Length in bytes (must be a multiple of 4 bytes). Valid values are 16 (most likely), 12 or 8.
    );

    return 0;
}

static int s2n_aead_cipher_aes256_gcm_encrypt(struct s2n_session_key *key, struct s2n_blob *iv, struct s2n_blob *aad, struct s2n_blob *in, struct s2n_blob *out)
{
    gte_check(in->size, S2N_TLS_GCM_TAG_LEN);
    gte_check(out->size, in->size);
    eq_check(iv->size, S2N_TLS_GCM_IV_LEN);

    /* Initialize the IV */
    if (EVP_EncryptInit_ex(key->evp_cipher_ctx, NULL, NULL, NULL, iv->data) != 1) {
        S2N_ERROR(S2N_ERR_KEY_INIT);
    }

    /* Adjust our buffer pointers to account for the explicit IV and TAG lengths */
    int in_len = in->size - S2N_TLS_GCM_TAG_LEN;
    uint8_t *tag_data = out->data + out->size - S2N_TLS_GCM_TAG_LEN;

    /* requires a 16 byte IV with 0x1 at the end*/
    uint8_t gcm_iv[16];
    memcpy(gcm_iv, iv->data, S2N_TLS_GCM_IV_LEN);
    memcpy(gcm_iv, &gcm_iv_trailer, 4);

    aesni_gcm256_enc(&key->gcm_data,
           out->data,   //!< Ciphertext output. Encrypt in-place is allowed.
           in->data,   //!< Plaintext input
           in_len,  //!< Length of data in Bytes for encryption.
           gcm_iv,    //!< Pre-counter block j0: 4 byte salt (from Security Association) concatenated with 8 byte Initialization Vector (from IPSec ESP Payload) concatenated with 0x00000001. 16-byte pointer.
           aad->data,  //!< Additional Authentication Data (AAD).
           aad->size,    //!< Length of AAD.
           tag_data,  //!< Authenticated Tag output.
           S2N_TLS_GCM_TAG_LEN   //!< Authenticated Tag Length in bytes (must be a multiple of 4 bytes). Valid values are 16 (most likely), 12 or 8.
    );

    return 0;
}

static int s2n_aead_cipher_aes128_gcm_decrypt(struct s2n_session_key *key, struct s2n_blob *iv, struct s2n_blob *aad, struct s2n_blob *in, struct s2n_blob *out)
{
    gte_check(in->size, S2N_TLS_GCM_TAG_LEN);
    gte_check(out->size, in->size);
    eq_check(iv->size, S2N_TLS_GCM_IV_LEN);

    /* Adjust our buffer pointers to account for the explicit IV and TAG lengths */
    int in_len = in->size - S2N_TLS_GCM_TAG_LEN;
    uint8_t *tag_data = in->data + in->size - S2N_TLS_GCM_TAG_LEN;

    /* requires a 16 byte IV with 0x1 at the end*/
    uint8_t gcm_iv[16];
    memcpy(gcm_iv, iv->data, S2N_TLS_GCM_IV_LEN);
    memcpy(gcm_iv, &gcm_iv_trailer, 4);

    // no return value, fingers crossed
    aesni_gcm128_dec(&key->gcm_data,
           out->data,   //!< Plaintext output. Decrypt in-place is allowed.
           in->data,   //!< Ciphertext input
           in_len,  //!< Length of data in Bytes for encryption.
           gcm_iv,    //!< Pre-counter block j0: 4 byte salt (from Security Association) concatenated with 8 byte Initialisation Vector (from IPSec ESP Payload) concatenated with 0x00000001. 16-byte pointer.
           aad->data,  //!< Additional Authentication Data (AAD).
           aad->size,    //!< Length of AAD.
           tag_data,  //!< Authenticated Tag output.
           S2N_TLS_GCM_TAG_LEN   //!< Authenticated Tag Length in bytes (must be a multiple of 4 bytes). Valid values are 16 (most likely), 12 or 8.
    );

    /* How do we verify ? */

    return 0;
}

static int s2n_aead_cipher_aes256_gcm_decrypt(struct s2n_session_key *key, struct s2n_blob *iv, struct s2n_blob *aad, struct s2n_blob *in, struct s2n_blob *out)
{
    gte_check(in->size, S2N_TLS_GCM_TAG_LEN);
    gte_check(out->size, in->size);
    eq_check(iv->size, S2N_TLS_GCM_IV_LEN);

    /* Adjust our buffer pointers to account for the explicit IV and TAG lengths */
    int in_len = in->size - S2N_TLS_GCM_TAG_LEN;
    uint8_t *tag_data = in->data + in->size - S2N_TLS_GCM_TAG_LEN;

    /* requires a 16 byte IV with 0x1 at the end*/
    uint8_t gcm_iv[16];
    memcpy(gcm_iv, iv->data, S2N_TLS_GCM_IV_LEN);
    memcpy(gcm_iv, &gcm_iv_trailer, 4);

    // no return value, fingers crossed
    aesni_gcm256_dec(&key->gcm_data,
           out->data,   //!< Plaintext output. Decrypt in-place is allowed.
           in->data,   //!< Ciphertext input
           in_len,  //!< Length of data in Bytes for encryption.
           gcm_iv,    //!< Pre-counter block j0: 4 byte salt (from Security Association) concatenated with 8 byte Initialisation Vector (from IPSec ESP Payload) concatenated with 0x00000001. 16-byte pointer.
           aad->data,  //!< Additional Authentication Data (AAD).
           aad->size,    //!< Length of AAD.
           tag_data,  //!< Authenticated Tag output.
           S2N_TLS_GCM_TAG_LEN   //!< Authenticated Tag Length in bytes (must be a multiple of 4 bytes). Valid values are 16 (most likely), 12 or 8.
    );

    /* How do we verify ? */

    return 0;
}

static int s2n_aead_cipher_aes128_gcm_set_encryption_key(struct s2n_session_key *key, struct s2n_blob *in)
{
    eq_check(in->size, 16);
    aesni_gcm128_pre(in->data, &key->gcm_data);

    return 0;
}

static int s2n_aead_cipher_aes256_gcm_set_encryption_key(struct s2n_session_key *key, struct s2n_blob *in)
{
    eq_check(in->size, 32);
    aesni_gcm256_pre(in->data, &key->gcm_data);

    return 0;
}

static int s2n_aead_cipher_aes128_gcm_set_decryption_key(struct s2n_session_key *key, struct s2n_blob *in)
{
    eq_check(in->size, 16);
    aesni_gcm128_pre(in->data, &key->gcm_data);

    return 0;
}

static int s2n_aead_cipher_aes256_gcm_set_decryption_key(struct s2n_session_key *key, struct s2n_blob *in)
{
    eq_check(in->size, 32);
    aesni_gcm256_pre(in->data, &key->gcm_data);

    return 0;
}

static int s2n_aead_cipher_aes_gcm_init(struct s2n_session_key *key)
{
    // Don't seem a "cleanup" method in the isa_l include, assume a memset will do
    memset(&key->gcm_data, 0, sizeof(struct gcm_data));

    return 0;
}

static int s2n_aead_cipher_aes_gcm_destroy_key(struct s2n_session_key *key)
{
    // Don't seem a "cleanup" method in the isa_l include, assume a memset will do
    memset(&key->gcm_data, 0, sizeof(struct gcm_data));

    return 0;
}

struct s2n_cipher s2n_aes128_gcm = {
    .key_material_size = 16,
    .type = S2N_AEAD,
    .io.aead = {
                .record_iv_size = S2N_TLS_GCM_EXPLICIT_IV_LEN,
                .fixed_iv_size = S2N_TLS_GCM_FIXED_IV_LEN,
                .tag_size = S2N_TLS_GCM_TAG_LEN,
                .decrypt = s2n_aead_cipher_aes128_gcm_decrypt,
                .encrypt = s2n_aead_cipher_aes128_gcm_encrypt},
    .init = s2n_aead_cipher_aes_gcm_init,
    .set_encryption_key = s2n_aead_cipher_aes128_gcm_set_encryption_key,
    .set_decryption_key = s2n_aead_cipher_aes128_gcm_set_decryption_key,
    .destroy_key = s2n_aead_cipher_aes_gcm_destroy_key,
};

struct s2n_cipher s2n_aes256_gcm = {
    .key_material_size = 32,
    .type = S2N_AEAD,
    .io.aead = {
                .record_iv_size = S2N_TLS_GCM_EXPLICIT_IV_LEN,
                .fixed_iv_size = S2N_TLS_GCM_FIXED_IV_LEN,
                .tag_size = S2N_TLS_GCM_TAG_LEN,
                .decrypt = s2n_aead_cipher_aes256_gcm_decrypt,
                .encrypt = s2n_aead_cipher_aes256_gcm_encrypt},
    .init = s2n_aead_cipher_aes_gcm_init,
    .set_encryption_key = s2n_aead_cipher_aes256_gcm_set_encryption_key,
    .set_decryption_key = s2n_aead_cipher_aes256_gcm_set_decryption_key,
    .destroy_key = s2n_aead_cipher_aes_gcm_destroy_key,
};
