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

	mbedtls_mpi a;
	mbedtls_mpi_init(&a);
	ERROR_CHECK(mbedtls_mpi_read_binary(&a, this->private_key, ECDH_KEY_SIZE));

	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_ctr_drbg_init(&ctr_drbg);
	mbedtls_entropy_context entropy;
	mbedtls_entropy_init(&entropy);
	ERROR_CHECK(mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, nullptr, 0));

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

	mbedtls_ecp_group_free(&ecp_group);
	mbedtls_md_free(&md_ctx);
	mbedtls_entropy_free(&entropy);
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_mpi_free(&a);
	mbedtls_ecp_point_free(&B);
	mbedtls_ecp_point_free(&S);

	mbedtls_platform_zeroize(S_bytes, sizeof(S_bytes));

	return true;
}
