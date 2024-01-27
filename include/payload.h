#pragma once

#include "ecdh.h"

#pragma pack(push, 1)
struct Payload {
	#define ESP_NOW_PAYLOAD_SIZE 250

	enum Type : uint8_t {
		DISCOVERY = 0,
		CONFIG = 1,
		DATA = 255
	};

	uint16_t crc = 0; // 2 byte
	Type type; // 1 byte
	uint32_t seq = 0; // 4 byte

	#define ESP_NOW_EZ_HEADER_SIZE 7
	#define ESP_NOW_EZ_PAYLOAD_SIZE ESP_NOW_PAYLOAD_SIZE - ESP_NOW_EZ_HEADER_SIZE

	Payload(Type type);
};

struct DiscoveryPayload : Payload {
	uint8_t key[ECDH_KEY_SIZE];
	char name[ESP_NOW_EZ_PAYLOAD_SIZE - ECDH_KEY_SIZE];

	DiscoveryPayload();
};

struct ConfigPayload : Payload {
	uint32_t old_seq = 0; // 4 byte
	uint32_t new_seq = 0; // 4 byte
	uint32_t sleep_ms = 0; // 4 byte

	ConfigPayload();
};

struct DataPayload : Payload {
	uint8_t data[ESP_NOW_EZ_PAYLOAD_SIZE];

	DataPayload();
};

#pragma pack(pop)
// uint8_t (*__kaboom)[sizeof( DataPayload )] = 1; // check if size is <=250
