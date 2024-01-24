#pragma once

#include <mbedtls/ecp.h>

class Ecdh {
public:
   #define ECDH_CURVE MBEDTLS_ECP_DP_CURVE25519
   #define ECDH_KEY_SIZE 32
   #define ECDH_SHARED_SECRET_SIZE 16

   const char* TAG = "ecdh";
   
   void generateKeypair(const uint8_t* entropy_data = nullptr, const size_t entropy_data_len = 0);
   bool generateSharedSecret(const uint8_t* public_key, uint8_t* shared_secret);

   uint8_t private_key[ECDH_KEY_SIZE];
   uint8_t public_key[ECDH_KEY_SIZE];

protected:
   void writePublicKey(const mbedtls_ecp_point* pk, uint8_t* data);
   void readPublicKey(const uint8_t* data, mbedtls_ecp_point* pk);
};
