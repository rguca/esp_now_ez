#include <sdkconfig.h>
#include <esp_log.h>
#include <stdlib.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/sha512.h>
#include <mbedtls/hkdf.h>
#include <mbedtls/platform_util.h>
#ifdef CONFIG_IDF_TARGET_ESP8266
	#include <esp_system.h>
#else
	#include <esp_random.h>
#endif

#include "ecdh.h"

#define ERROR_CHECK(ret) { if (ret != 0) { ESP_LOGE(TAG, "error: %d", ret); abort(); } }

void Ecdh::generateKeypair(const uint8_t* entropy_data, const size_t entropy_data_len) {
	uint8_t personal[256];
	esp_fill_random(personal, sizeof(personal));
	if (entropy_data) {
		mbedtls_sha512(entropy_data, entropy_data_len, personal + (sizeof(personal) - 64), 0);
	}

	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_ctr_drbg_init(&ctr_drbg);
	mbedtls_entropy_context entropy;
	mbedtls_entropy_init(&entropy);
	ERROR_CHECK(mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, personal, sizeof(personal)));

	mbedtls_ecp_group ecp_group;
	mbedtls_ecp_group_init(&ecp_group);
	ERROR_CHECK(mbedtls_ecp_group_load(&ecp_group, ECDH_CURVE));

	mbedtls_mpi a;
	mbedtls_mpi_init(&a);
	mbedtls_ecp_point A;
	mbedtls_ecp_point_init(&A);
	ERROR_CHECK(mbedtls_ecp_gen_keypair(&ecp_group, &a, &A, mbedtls_ctr_drbg_random, &ctr_drbg));

	ERROR_CHECK(mbedtls_mpi_write_binary(&a, this->private_key, ECDH_KEY_SIZE));

	size_t olen = 0;
	ERROR_CHECK(mbedtls_ecp_point_write_binary(&ecp_group, &A, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, this->public_key, ECDH_KEY_SIZE));
	if (olen != ECDH_KEY_SIZE) {
		ESP_LOGE(TAG, "invalid public key len: %u", olen);
		abort();
	}

	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);
	mbedtls_ecp_group_free(&ecp_group);
	mbedtls_mpi_free(&a);
	mbedtls_ecp_point_free(&A);

	mbedtls_platform_zeroize(personal, sizeof(personal));
}

bool Ecdh::generateSharedSecret(const uint8_t* public_key, uint8_t* shared_secret) {
	mbedtls_ecp_group ecp_group;
	mbedtls_ecp_group_init(&ecp_group);
	ERROR_CHECK(mbedtls_ecp_group_load(&ecp_group, ECDH_CURVE));

	mbedtls_ecp_point B;
	mbedtls_ecp_point_init(&B);
	ERROR_CHECK(mbedtls_ecp_point_read_binary(&ecp_group, &B, public_key, ECDH_KEY_SIZE));
	if (mbedtls_ecp_check_pubkey(&ecp_group, &B) != 0) {
		return false;
	}

	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_ctr_drbg_init(&ctr_drbg);
	mbedtls_entropy_context entropy;
	mbedtls_entropy_init(&entropy);
	uint8_t personal[256];
	esp_fill_random(personal, sizeof(personal));
	ERROR_CHECK(mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, personal, sizeof(personal)));

	// mbedtls_mpi r;
	// mbedtls_mpi_init(&r);
	// mbedtls_ecp_point R;
	// mbedtls_ecp_point_init(&R);
	// ERROR_CHECK(mbedtls_ecp_gen_keypair(&ecp_group, &r, &R, mbedtls_ctr_drbg_random, &ctr_drbg));
	// ERROR_CHECK(mbedtls_ecp_check_privkey(&ecp_group, &r));
	// ERROR_CHECK(mbedtls_ecp_check_pubkey(&ecp_group, &R));

	// uint8_t R_bytes[ECDH_KEY_SIZE];
	// ERROR_CHECK(mbedtls_ecp_point_write_binary(&ecp_group, &R, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, R_bytes, ECDH_KEY_SIZE));

	mbedtls_mpi a;
	mbedtls_mpi_init(&a);
	ERROR_CHECK(mbedtls_mpi_read_binary(&a, this->private_key, ECDH_KEY_SIZE));

	mbedtls_ecp_point S;
	mbedtls_ecp_point_init(&S);
	ERROR_CHECK(mbedtls_ecp_mul(&ecp_group, &S, &a, &B, mbedtls_ctr_drbg_random, &ctr_drbg));
	size_t olen = 0;
	uint8_t S_bytes[ECDH_KEY_SIZE];
	ERROR_CHECK(mbedtls_ecp_point_write_binary(&ecp_group, &S, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, S_bytes, ECDH_KEY_SIZE));
	if (olen != ECDH_KEY_SIZE) {
		ESP_LOGE(TAG, "invalid share len: %u", olen);
		abort();
	}

	mbedtls_md_context_t md_ctx;
	mbedtls_md_init(&md_ctx);
	ERROR_CHECK(mbedtls_md_setup(&md_ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA512), 1));
	ERROR_CHECK(mbedtls_hkdf(
		mbedtls_md_info_from_type(MBEDTLS_MD_SHA512),
		nullptr, 0, 
		S_bytes, ECDH_KEY_SIZE, 
		nullptr, 0, 
		shared_secret, ECDH_SHARED_SECRET_SIZE
	));

	// mbedtls_gcm_context aes_ctx;
	// mbedtls_gcm_init(&aes_ctx);
	// ERROR_CHECK(mbedtls_gcm_setkey(&aes_ctx, MBEDTLS_CIPHER_ID_AES, aes_key, 256));

	// size_t olen = cecies_calc_output_buffer_needed_size(input_data_length, key_length);

	// uint8_t* o = malloc(olen);
	// if (o == NULL)
	// {
	// 	ret = CECIES_ENCRYPT_ERROR_CODE_OUT_OF_MEMORY;
	// 	goto exit;
	// }

	// uint8_t iv[16];
	// ERROR_CHECK(mbedtls_ctr_drbg_random(&ctr_drbg, iv, 16));

	// memcpy(o, iv, 16);
	// memcpy(o + 16, salt, 32);
	// memcpy(o + 16 + 32, R_bytes, R_bytes_length);

	// ret = mbedtls_gcm_crypt_and_tag(       //
	// 	&aes_ctx,                          // MbedTLS AES context pointer.
	// 	MBEDTLS_GCM_ENCRYPT,               // Encryption mode.
	// 	input_data_length,                 // Input data length (or compressed input data length if compression is enabled).
	// 	iv,                                // The initialization vector.
	// 	16,                                // Length of the IV.
	// 	NULL,                              // No additional data.
	// 	0,                                 // ^
	// 	input_data,                        // The input data to encrypt (or compressed input data if compression is enabled).
	// 	o + 16 + 32 + R_bytes_length + 16, // Where to write the encrypted output bytes into: this is offset so that the order of the ciphertext prefix IV + Salt + Ephemeral Key + Tag is skipped.
	// 	16,                                // Length of the authentication tag.
	// 	o + 16 + 32 + R_bytes_length       // Where to insert the tag bytes inside the output ciphertext.
	// );

	// if (ret != 0)
	// {
	// 	free(o);
	// 	cecies_fprintf(stderr, "CECIES: AES-GCM encryption failed! mbedtls_gcm_crypt_and_tag returned %d\n", ret);
	// 	goto exit;
	// }

	// mbedtls_gcm_free(&aes_ctx);
	mbedtls_ecp_group_free(&ecp_group);
	mbedtls_md_free(&md_ctx);
	mbedtls_entropy_free(&entropy);
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_mpi_free(&a);
	// mbedtls_ecp_point_free(&R);
	mbedtls_ecp_point_free(&S);
	mbedtls_ecp_point_free(&B);

	// mbedtls_platform_zeroize(iv, sizeof(iv));
	// mbedtls_platform_zeroize(salt, sizeof(salt));
	mbedtls_platform_zeroize(personal, sizeof(personal));
	// mbedtls_platform_zeroize(aes_key, sizeof(aes_key));
	mbedtls_platform_zeroize(S_bytes, sizeof(S_bytes));
	// mbedtls_platform_zeroize(R_bytes, sizeof(R_bytes));
	return true;
}
