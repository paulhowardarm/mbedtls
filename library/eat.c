/*
 *  eat_example_psa.c
 *
 * Copyright 2019-2020, Laurence Lundblade
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */
#include "ctoken_encode.h"
#include "ctoken_decode.h"

#include "mbedtls/eat.h"

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/mbedtls_config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include "t_cose/t_cose_common.h"
#include "t_cose/t_cose_sign1_sign.h"
#include "t_cose/q_useful_buf.h"
#include "mbedtls/error.h"
#include "mbedtls/pk.h"
#include "mbedtls/error.h"
#include "psa/crypto.h"
#include "common.h"

#include "mbedtls/x509_crt.h"

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#include <stdlib.h>
#define mbedtls_printf          printf
#define mbedtls_exit            exit
#define MBEDTLS_EXIT_SUCCESS    EXIT_SUCCESS
#define MBEDTLS_EXIT_FAILURE    EXIT_FAILURE
#endif /* MBEDTLS_PLATFORM_C */


/* Function signatures */

enum t_cose_err_t make_psa_ecdsa_key_pair(int32_t cose_algorithm_id, struct t_cose_key *key_pair);

int32_t create_cwt( uint8_t *ptr, size_t *len, const uint8_t *nonce, size_t nonce_len, uint8_t *crt, size_t crt_len, struct t_cose_key *key_pair, uint8_t *eat, size_t eat_len);

int32_t create_eat( uint8_t *ptr, size_t *len, const uint8_t *nonce, size_t nonce_len, struct t_cose_key *key_pair );

int32_t verify_eat( uint8_t *ptr, size_t len, const uint8_t *nonce, size_t nonce_len, struct t_cose_key *key_pair );

int32_t verify_cwt( uint8_t *ptr, size_t len, const uint8_t *nonce, size_t nonce_len, struct t_cose_key *key_pair, uint8_t *crt, size_t *crt_len);

void free_psa_ecdsa_key_pair(struct t_cose_key key_pair);


/**
 * \file t_cose_basic_example_psa.c
 *
 * \brief Example code for signing and verifying a COSE_Sign1 message using PSA
 *
 * This file has simple code to sign a payload and verify it.
 *
 * This works with PSA / MBed Crypto. It assumes t_cose has been wired
 * up to PSA / MBed Crypto and has code specific to this library to
 * make a key pair that will be passed through t_cose. See t_cose
 * README for more details on how integration with crypto libraries
 * works.
 */

/* Here's the auto-detect and manual override logic for managing PSA
 * Crypto API compatibility. It is needed here for key generation.
 *
 * PSA_GENERATOR_UNBRIDLED_CAPACITY happens to be defined in MBed
 * Crypto 1.1 and not in MBed Crypto 2.0 so it is what auto-detect
 * hinges off of.
 *
 * T_COSE_USE_PSA_CRYPTO_FROM_MBED_CRYPTO20 can be defined to force
 * setting to MBed Crypto 2.0
 *
 * T_COSE_USE_PSA_CRYPTO_FROM_MBED_CRYPTO11 can be defined to force
 * setting to MBed Crypt 1.1. It is also what the code below hinges
 * on.
 */
#if defined(PSA_GENERATOR_UNBRIDLED_CAPACITY) && !defined(T_COSE_USE_PSA_CRYPTO_FROM_MBED_CRYPTO20)
#define T_COSE_USE_PSA_CRYPTO_FROM_MBED_CRYPTO11
#endif

psa_status_t parsec_attest_key(psa_key_id_t attested_key,
                               parsec_attest_mechanism_t mech,
                               const uint8_t *challenge,
                               size_t challenge_length,
                               uint8_t *attestation_token,
                               size_t attestation_token_size,
                               size_t *attestation_token_length)
{
    enum t_cose_err_t return_value;
    unsigned char eat_scratch[500]={0};
    unsigned char *eat = eat_scratch;
    struct t_cose_key key_pair;
    psa_status_t status;
    uint8_t pk[PSA_EXPORT_PUBLIC_KEY_MAX_SIZE] = { 0 };
    size_t pk_len;
    size_t n;

    switch( mech )
    {
    case 0: /* EAT-based approach */
        break;
    default: /* Nothing else is supported */
        return( PSA_ERROR_NOT_SUPPORTED );
    }

    /* Fetch private key used to sign the EAT and the CWT */
    return_value = make_psa_ecdsa_key_pair(T_COSE_ALGORITHM_ES256, &key_pair);

    if ( return_value != T_COSE_SUCCESS )
    {
        return( PSA_ERROR_GENERIC_ERROR );
    }

    /* TBD: APIs for getting an EAT and a key attestation */
    if ( create_eat( eat, &n, challenge, challenge_length, &key_pair ) != 0 )
    {
        free_psa_ecdsa_key_pair(key_pair);
        return( PSA_ERROR_GENERIC_ERROR );
    }

    /* Put the EAT and the RPK inside the CWT */
     status = psa_export_public_key( attested_key,
                                     pk,
                                     sizeof(pk),
                                     &pk_len
                                   );

    if( status != PSA_SUCCESS )
    {
        free_psa_ecdsa_key_pair(key_pair);
        return( PSA_ERROR_GENERIC_ERROR );
    }

    if ( create_cwt( attestation_token, attestation_token_length,
                     challenge, challenge_length,
                     pk, pk_len,
                     &key_pair,
                     eat,
                     n
                   ) != 0 )
    {
        free_psa_ecdsa_key_pair(key_pair);
        return( PSA_ERROR_GENERIC_ERROR );
    }

    free_psa_ecdsa_key_pair(key_pair);
    return( PSA_SUCCESS );
}


psa_status_t parsec_create_key(int32_t             algorithm_id,
                               psa_key_handle_t   *key_handle)
{
    psa_key_type_t      key_type;
    psa_status_t        crypto_result;
    psa_algorithm_t     key_alg;
    const uint8_t      *private_key;
    size_t              private_key_len;

    static const uint8_t private_key_256[] = {PRIVATE_KEY_prime256r1};
    static const uint8_t private_key_384[] = {PRIVATE_KEY_secp384r1};
    static const uint8_t private_key_521[] = {PRIVATE_KEY_secp521r1};

    /* There is not a 1:1 mapping from alg to key type, but
     * there is usually an obvious curve for an algorithm. That
     * is what this does.
     */

#ifdef T_COSE_USE_PSA_CRYPTO_FROM_MBED_CRYPTO11
#define PSA_KEY_TYPE_ECC_KEY_PAIR PSA_KEY_TYPE_ECC_KEYPAIR
#endif /* T_COSE_USE_PSA_CRYPTO_FROM_MBED_CRYPTO11 */

    switch(algorithm_id) {
        case T_COSE_ALGORITHM_ES256:
            private_key     = private_key_256;
            private_key_len = sizeof(private_key_256);
            key_type        = PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1);
            key_alg         = PSA_ALG_ECDSA(PSA_ALG_SHA_256);
            break;

        case T_COSE_ALGORITHM_ES384:
            private_key     = private_key_384;
            private_key_len = sizeof(private_key_384);
            key_type        = PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1);
            key_alg         = PSA_ALG_ECDSA(PSA_ALG_SHA_384);
            break;

        case T_COSE_ALGORITHM_ES512:
            private_key     = private_key_521;
            private_key_len = sizeof(private_key_521);
            key_type        = PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1);
            key_alg         = PSA_ALG_ECDSA(PSA_ALG_SHA_512);
            break;

        default:
            return( PSA_ERROR_NOT_SUPPORTED );
    }


    /* OK to call this multiple times */
    crypto_result = psa_crypto_init();
    if(crypto_result != PSA_SUCCESS) {
        return( crypto_result );
    }


    /* When importing a key with the PSA API there are two main things
     * to do.
     *
     * First you must tell it what type of key it is as this cannot be
     * discovered from the raw data. The variable key_type contains
     * that information including the EC curve. This is sufficient for
     * psa_import_key() to succeed, but you probably want actually use
     * the key.
     *
     * Second, you must say what algorithm(s) and operations the key
     * can be used as the PSA Crypto Library has policy enforcement.
     *
     * How this is done varies quite a lot in the newer
     * PSA Crypto API compared to the older.
     */

#ifdef T_COSE_USE_PSA_CRYPTO_FROM_MBED_CRYPTO11
    /* Allocate for the key pair in the Crypto service */
    crypto_result = psa_allocate_key(&key_handle);
    if (crypto_result != PSA_SUCCESS) {
        return( crypto_result );
    }

    /* Say what algorithm and operations the key can be used with / for */
    psa_key_policy_t policy = psa_key_policy_init();
    psa_key_policy_set_usage(&policy,
                             PSA_KEY_USAGE_SIGN | PSA_KEY_USAGE_VERIFY,
                             key_alg);
    crypto_result = psa_set_key_policy(key_handle, &policy);
    if (crypto_result != PSA_SUCCESS) {
        return( crypto_result );
    }

    /* Import the private key. psa_import_key() automatically
     * generates the public key from the private so no need to import
     * more than the private key. (With ECDSA the public key is always
     * deterministically derivable from the private key).
     */
    /* key_type has the type of key including the EC curve */
    crypto_result = psa_import_key(key_handle,
                                   key_type,
                                   private_key,
                                   private_key_len);

#else /* T_COSE_USE_PSA_CRYPTO_FROM_MBED_CRYPTO11 */
    psa_key_attributes_t key_attributes;

    key_attributes = psa_key_attributes_init();

    /* Say what algorithm and operations the key can be used with / for */
    psa_set_key_usage_flags(&key_attributes, PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH);
    psa_set_key_algorithm(&key_attributes, key_alg);

    /* The type of key including the EC curve */
    psa_set_key_type(&key_attributes, key_type);

    /* Import the private key. psa_import_key() automatically
     * generates the public key from the private so no need to import
     * more than the private key. (With ECDSA the public key is always
     * deterministically derivable from the private key).
     */
    crypto_result = psa_import_key(&key_attributes,
                                   private_key,
                                   private_key_len,
                                   key_handle);

#endif /* T_COSE_USE_PSA_CRYPTO_FROM_MBED_CRYPTO11 */

    if (crypto_result != PSA_SUCCESS) {
        return( crypto_result );
    }

    return( PSA_SUCCESS );
}

/**
 * \brief Make an EC key pair in PSA / Mbed library form.
 *
 * \param[in] cose_algorithm_id  The algorithm to sign with, for example
 *                               \ref T_COSE_ALGORITHM_ES256.
 * \param[out] key_pair          The key pair. This must be freed.
 *
 * The key made here is fixed and just useful for testing.
 */
enum t_cose_err_t make_psa_ecdsa_key_pair(int32_t            cose_algorithm_id,
                                          struct t_cose_key *key_pair)
{
    psa_key_type_t      key_type;
    psa_status_t        crypto_result;
    psa_key_handle_t    key_handle;
    psa_algorithm_t     key_alg;
    const uint8_t      *private_key;
    size_t              private_key_len;

    static const uint8_t private_key_256[] = {PRIVATE_KEY_prime256r1};
    static const uint8_t private_key_384[] = {PRIVATE_KEY_secp384r1};
    static const uint8_t private_key_521[] = {PRIVATE_KEY_secp521r1};

    /* There is not a 1:1 mapping from alg to key type, but
     * there is usually an obvious curve for an algorithm. That
     * is what this does.
     */

#ifdef T_COSE_USE_PSA_CRYPTO_FROM_MBED_CRYPTO11
#define PSA_KEY_TYPE_ECC_KEY_PAIR PSA_KEY_TYPE_ECC_KEYPAIR
#endif /* T_COSE_USE_PSA_CRYPTO_FROM_MBED_CRYPTO11 */

    switch(cose_algorithm_id) {
        case T_COSE_ALGORITHM_ES256:
            private_key     = private_key_256;
            private_key_len = sizeof(private_key_256);
            key_type        = PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1);
            key_alg         = PSA_ALG_ECDSA(PSA_ALG_SHA_256);
            break;

        case T_COSE_ALGORITHM_ES384:
            private_key     = private_key_384;
            private_key_len = sizeof(private_key_384);
            key_type        = PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1);
            key_alg         = PSA_ALG_ECDSA(PSA_ALG_SHA_384);
            break;

        case T_COSE_ALGORITHM_ES512:
            private_key     = private_key_521;
            private_key_len = sizeof(private_key_521);
            key_type        = PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1);
            key_alg         = PSA_ALG_ECDSA(PSA_ALG_SHA_512);
            break;

        default:
            return T_COSE_ERR_UNSUPPORTED_SIGNING_ALG;
    }


    /* OK to call this multiple times */
    crypto_result = psa_crypto_init();
    if(crypto_result != PSA_SUCCESS) {
        return T_COSE_ERR_FAIL;
    }


    /* When importing a key with the PSA API there are two main things
     * to do.
     *
     * First you must tell it what type of key it is as this cannot be
     * discovered from the raw data. The variable key_type contains
     * that information including the EC curve. This is sufficient for
     * psa_import_key() to succeed, but you probably want actually use
     * the key.
     *
     * Second, you must say what algorithm(s) and operations the key
     * can be used as the PSA Crypto Library has policy enforcement.
     *
     * How this is done varies quite a lot in the newer
     * PSA Crypto API compared to the older.
     */

#ifdef T_COSE_USE_PSA_CRYPTO_FROM_MBED_CRYPTO11
    /* Allocate for the key pair in the Crypto service */
    crypto_result = psa_allocate_key(&key_handle);
    if (crypto_result != PSA_SUCCESS) {
        return T_COSE_ERR_FAIL;
    }

    /* Say what algorithm and operations the key can be used with / for */
    psa_key_policy_t policy = psa_key_policy_init();
    psa_key_policy_set_usage(&policy,
                             PSA_KEY_USAGE_SIGN | PSA_KEY_USAGE_VERIFY,
                             key_alg);
    crypto_result = psa_set_key_policy(key_handle, &policy);
    if (crypto_result != PSA_SUCCESS) {
        return T_COSE_ERR_FAIL;
    }

    /* Import the private key. psa_import_key() automatically
     * generates the public key from the private so no need to import
     * more than the private key. (With ECDSA the public key is always
     * deterministically derivable from the private key).
     */
    /* key_type has the type of key including the EC curve */
    crypto_result = psa_import_key(key_handle,
                                   key_type,
                                   private_key,
                                   private_key_len);

#else /* T_COSE_USE_PSA_CRYPTO_FROM_MBED_CRYPTO11 */
    psa_key_attributes_t key_attributes;

    key_attributes = psa_key_attributes_init();

    /* Say what algorithm and operations the key can be used with / for */
    psa_set_key_usage_flags(&key_attributes, PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH);
    psa_set_key_algorithm(&key_attributes, key_alg);

    /* The type of key including the EC curve */
    psa_set_key_type(&key_attributes, key_type);

    /* Import the private key. psa_import_key() automatically
     * generates the public key from the private so no need to import
     * more than the private key. (With ECDSA the public key is always
     * deterministically derivable from the private key).
     */
    crypto_result = psa_import_key(&key_attributes,
                                   private_key,
                                   private_key_len,
                                   &key_handle);

#endif /* T_COSE_USE_PSA_CRYPTO_FROM_MBED_CRYPTO11 */

    if (crypto_result != PSA_SUCCESS) {
        return T_COSE_ERR_FAIL;
    }

    key_pair->k.key_handle = key_handle;
    key_pair->crypto_lib   = T_COSE_CRYPTO_LIB_PSA;

    return T_COSE_SUCCESS;
}


/**
 * \brief  Free a PSA / MBed key.
 *
 * \param[in] key_pair   The key pair to close / deallocate / free.
 */
void free_psa_ecdsa_key_pair(struct t_cose_key key_pair)
{
    psa_close_key((psa_key_handle_t) key_pair.k.key_handle);
}


/**
 * \brief  Print a q_useful_buf_c on stdout in hex ASCII text.
 *
 * \param[in] string_label   A string label to output first
 * \param[in] buf            The q_useful_buf_c to output.
 *
 * This is just for pretty printing.
 */
static void print_useful_buf(const char *string_label, struct q_useful_buf_c buf)
{
    if(string_label) {
        printf("%s", string_label);
    }

    printf("    %ld bytes\n", buf.len);

    printf("    ");

    size_t i;
    for(i = 0; i < buf.len; i++) {
        uint8_t Z = ((uint8_t *)buf.ptr)[i];
        printf("%02x ", Z);
        if((i % 32) == 31) {
            printf("\n    ");
        }
    }
    printf("\n");

    fflush(stdout);
}


/**
 \brief Example to encode an EAT token

 @param[in] signing_key    The private key to sign with. This must be in the
                           format of the crypto library that is integrated.
                           See definition in t_cose interface.
 @param[in] nonce          Pointer and length of nonce claim.
 @param[in] output_buffer  Pointer and length of the buffer to output to. Must
                           be big enough to hold the EAT, or an error occurs.
 @param[out] completed_token  Pointer and length of the completed token.
 @return                      0 on success.

 output_buffer is the pointer and length of a buffer to write
 into. The pointer is not const indicating it is for writing.

 completed_token is the const pointer and length of the completed
 token. The storage pointed to by completed_token is inside
 output_buffer, usually the first part, so the pointers point
 to the same place.

 No storage allocation is done and malloc is not used.
 */
int32_t eat_encode(struct t_cose_key signing_key,
                   struct q_useful_buf_c nonce,
                   struct q_useful_buf output_buffer,
                   struct q_useful_buf_c *completed_token)
{
    struct ctoken_encode_ctx encode_ctx;
    int                      return_value;

    /* UEID is hard-coded. A real implementation would fetch it from
     * storage or read it from a register or compute it or such.
     */
    const struct q_useful_buf_c ueid = Q_USEFUL_BUF_FROM_SZ_LITERAL("ueid_ueid");

    /* Initialize, telling is the option (there are none) and
     * the signing algorithm to use.
     */
    ctoken_encode_init(&encode_ctx,
                       0, /* No t_cose options */
                       0, /* No ctoken options */
                       CTOKEN_PROTECTION_COSE_SIGN1,
                       T_COSE_ALGORITHM_ES256);

    /* Next give it the signing key. No kid (key id) is given so
     * NULL_Q_USEFUL_BUF_C is passed.
     */
    ctoken_encode_set_key(&encode_ctx, signing_key, NULL_Q_USEFUL_BUF_C);

    /* Pass in the output buffer and get the encoding started.
     * The output buffer must be big enough for EAT payload, COSE
     * formatting and signature. (There is a way to call
     * ctoken_encode_start() to have this computed which is th
     * same as that used by t_cose and QCBOR, but that is not
     * done in this simple example. */
    ctoken_encode_start(&encode_ctx, output_buffer);

    /* Now start adding the claims into the token. Eat claims
     * can be mixed with PSA IA claims and with CWT claims.
     * You can even make up your own claims.
     */

    ctoken_encode_nonce(&encode_ctx, nonce);

    ctoken_encode_ueid(&encode_ctx, ueid);

    /* Finally completed it. This invokes the signing and
     * ties everything off and outputs the completed token.
     * The variable completed_token has the pointer and length
     * of the result that are in output_buffer.
     */
    return_value = ctoken_encode_finish(&encode_ctx, completed_token);

    return return_value;
}


int32_t cwt_encode(struct t_cose_key signing_key,
                   struct q_useful_buf_c nonce,
                   struct q_useful_buf_c x509,
                   struct q_useful_buf_c eat,
                   struct q_useful_buf output_buffer,
                   struct q_useful_buf_c *completed_token)
{
    struct ctoken_encode_ctx encode_ctx;
    int                      return_value;

    /* Initialize, telling is the option (there are none) and
     * the signing algorithm to use.
     */
    ctoken_encode_init(&encode_ctx,
                       0, /* No t_cose options */
                       0, /* No ctoken options */
                       CTOKEN_PROTECTION_COSE_SIGN1,
                       T_COSE_ALGORITHM_ES256);

    /* Next give it the signing key. No kid (key id) is given so
     * NULL_Q_USEFUL_BUF_C is passed.
     */
    ctoken_encode_set_key(&encode_ctx, signing_key, NULL_Q_USEFUL_BUF_C);

    /* Pass in the output buffer and get the encoding started.
     * The output buffer must be big enough for EAT payload, COSE
     * formatting and signature. (There is a way to call
     * ctoken_encode_start() to have this computed which is th
     * same as that used by t_cose and QCBOR, but that is not
     * done in this simple example. */
    ctoken_encode_start(&encode_ctx, output_buffer);

    /* Now start adding the claims into the token. Eat claims
     * can be mixed with PSA IA claims and with CWT claims.
     * You can even make up your own claims.
     */

    ctoken_encode_nonce(&encode_ctx, nonce);

    ctoken_encode_cnf(&encode_ctx, x509);

    ctoken_encode_eat(&encode_ctx, eat);

    /* Finally completed it. This invokes the signing and
     * ties everything off and outputs the completed token.
     * The variable completed_token has the pointer and length
     * of the result that are in output_buffer.
     */
    return_value = ctoken_encode_finish(&encode_ctx, completed_token);

    return return_value;
}



/**
 Simple EAT decode and verify example.

 @param[in] verification_key  The public key to verify the token with. It must
                              be in the format for the crypto library that
                              ctoken and t_cose are integrated with. See
                              the t_cose headers.
 @param[in] token             Pointer and length of the token to verify.
 @param[out] nonce            Place to return pointer and length of the
                              nonce.
 @return                      0 on success.

 This only retrieves the nonce claim from the token (so far).
 */
int32_t eat_decode(struct t_cose_key     verification_key,
                   struct q_useful_buf_c token,
                   struct q_useful_buf_c *nonce)
{
    struct ctoken_decode_ctx decode_context;

    /* Initialize the decoding context. No options are given.
     * The algorithm in use comes from the header in the token
     * so it is not specified here
     */
    ctoken_decode_init(&decode_context,
                       0,
                       0,
                       CTOKEN_PROTECTION_BY_TAG);

    /* Set the verification key to use. It must be a key that works
     * with the algorithm the token was signed with. (This can be
     * be retrieved, but it is not shown here.)
     */
    ctoken_decode_set_verification_key(&decode_context, verification_key);

    /* Validate the signature on the token */
    ctoken_decode_validate_token(&decode_context, token);

    /* Parse the nonce out of the token */
    ctoken_decode_nonce(&decode_context, nonce);

    return ctoken_decode_get_and_reset_error(&decode_context);
}


int32_t cwt_decode(struct t_cose_key     verification_key,
                   struct q_useful_buf_c token,
                   struct q_useful_buf_c *nonce,
                   struct q_useful_buf_c *eat,
                   struct q_useful_buf_c *crt
    )
{
    struct ctoken_decode_ctx decode_context;

    /* Initialize the decoding context. No options are given.
     * The algorithm in use comes from the header in the token
     * so it is not specified here
     */
    ctoken_decode_init(&decode_context,
                       0,
                       0,
                       CTOKEN_PROTECTION_BY_TAG);

    /* Set the verification key to use. It must be a key that works
     * with the algorithm the token was signed with. (This can be
     * be retrieved, but it is not shown here.)
     */
    ctoken_decode_set_verification_key(&decode_context, verification_key);

    /* Validate the signature on the token */
    ctoken_decode_validate_token(&decode_context, token);

    /* Parse the nonce out of the token */
    ctoken_decode_nonce(&decode_context, nonce);

    /* Extract the EAT claim */
    ctoken_decode_eat(&decode_context, eat);

    /* Extract the CNF claim containing the certificate */
    ctoken_decode_cnf(&decode_context, crt);

    return ctoken_decode_get_and_reset_error(&decode_context);
}

int32_t create_eat( uint8_t *ptr, size_t *len, const uint8_t *nonce, size_t nonce_len, struct t_cose_key *key_pair)
{
    int return_value;

    /* ------   Make an EAT   ------ */

    /* Call to macro to make a 300 byte struct useful_buf on the stack
     * named token_buffer. The expected token is less than 200 bytes.
     */
    MakeUsefulBufOnStack(  token_buffer, 300);
    struct q_useful_buf_c  completed_token;

    /* Make the token */
    return_value = eat_encode(*key_pair,
                              (struct q_useful_buf_c)
                              {
                                .len = nonce_len,
                                .ptr = nonce
                              },
                              token_buffer,
                             &completed_token);

    printf("Finished making EAT: %d (%s)\n", return_value, return_value ? "fail" : "success");
    if(return_value) {
        return (return_value);
    }

    print_useful_buf("Completed EAT:\n", completed_token);

    *len = completed_token.len;

    memcpy(ptr, (uint8_t *) completed_token.ptr, *len);

    return(return_value);
}


int32_t create_cwt( uint8_t *ptr, size_t *len, const uint8_t *nonce, size_t nonce_len, uint8_t *crt, size_t crt_len, struct t_cose_key *key_pair, uint8_t *eat, size_t eat_len)
{
    int return_value;

    /* ------   Make an EAT   ------ */

    /* Call to macro to make a 300 byte struct useful_buf on the stack
     * named token_buffer. The expected token is less than 200 bytes.
     */
    MakeUsefulBufOnStack(  token_buffer, 1500);
    struct q_useful_buf_c  completed_token;

    /* Make the token */
    return_value = cwt_encode(*key_pair,
                              (struct q_useful_buf_c)
                              {
                                .len = nonce_len,
                                .ptr = nonce
                              },
                              (struct q_useful_buf_c)
                              {
                                .len = crt_len,
                                .ptr = crt
                              },
                              (struct q_useful_buf_c)
                              {
                                .len = eat_len,
                                .ptr = eat
                              },
                              token_buffer,
                             &completed_token);

    printf("Finished making CWT: %d (%s)\n", return_value, return_value ? "fail" : "success");
    if(return_value) {
        return(return_value);
    }

    print_useful_buf("Completed CWT:\n", completed_token);

    *len = completed_token.len;

    memcpy(ptr, (uint8_t *) completed_token.ptr, *len);

    return(return_value);

}

int32_t verify_eat( uint8_t *ptr, size_t len, const uint8_t *nonce, size_t nonce_len, struct t_cose_key *key_pair)
{
    struct q_useful_buf_c completed_token;
    struct q_useful_buf_c decoded_nonce;

    int return_value;

    completed_token.len = len;
    completed_token.ptr = ptr;

    /* ------   Verify the EAT   ------ */

    print_useful_buf("Received EAT:\n", completed_token);

    return_value = eat_decode(*key_pair,
                              completed_token,
                              &decoded_nonce);

    printf("EAT Verification complete: %d (%s)\n", return_value, return_value ? "fail" : "success");
    if (return_value) {
        return(return_value);
    }

    print_useful_buf("Decoded nonce:\n", decoded_nonce);

    if (memcmp(decoded_nonce.ptr,nonce,nonce_len )!=0)
    {
        printf("Nonce values do not match!\n");
        return(CTOKEN_ERR_TAMPERING_DETECTED);
    }

    return(return_value);
}


int32_t verify_cwt( uint8_t *ptr, size_t len, const uint8_t *nonce, size_t nonce_len, struct t_cose_key *key_pair, uint8_t *crt, size_t *crt_len)
{
    struct q_useful_buf_c completed_token;
    struct q_useful_buf_c decoded_nonce;
    struct q_useful_buf_c decoded_eat;
    struct q_useful_buf_c decoded_crt;

    int return_value;

    completed_token.len = len;
    completed_token.ptr = ptr;

    /* ------   Verify the CWT  ------ */

    return_value = cwt_decode(*key_pair,
                              completed_token,
                              &decoded_nonce,
                              &decoded_eat,
                              &decoded_crt);

    printf("CWT Verification complete: %d (%s)\n", return_value, return_value ? "fail" : "success");
    if (return_value) {
        return(return_value);
    }


    /* ------   Verify the EAT   ------ */

    print_useful_buf("Received EAT:\n", decoded_eat);

    return_value = eat_decode(*key_pair,
                              decoded_eat,
                              &decoded_nonce);

    printf("EAT Verification complete: %d (%s)\n", return_value, return_value ? "fail" : "success");
    if (return_value) {
        return(return_value);
    }

    print_useful_buf("Decoded nonce:\n", decoded_nonce);

    if (memcmp(decoded_nonce.ptr,nonce,nonce_len )!=0)
    {
        printf("Nonce values do not match!\n");
        return(CTOKEN_ERR_TAMPERING_DETECTED);
    }

    if (decoded_crt.len > *crt_len) {
        printf("Not enough buffer to store certificate!\n");
        return(CTOKEN_ERR_INSUFFICIENT_MEMORY);
    }

    /* ------   Return Certificate   ------ */

    *crt_len = decoded_crt.len;
    memcpy(crt,decoded_crt.ptr,decoded_crt.len);

    return(return_value);
}


