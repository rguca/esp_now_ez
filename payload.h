#pragma once

#include <cstring>
#include "esp_now.h"

#pragma pack(push, 1)
struct Payload {
	#define ESP_NOW_PAYLOAD_SIZE 250

	enum Type : uint8_t {
		DISCOVERY = 0,
		TIME = 1,
		DATA = 255
	};

	uint16_t crc = 0; // 2 byte
	Type type; // 1 byte

	#define ESP_NOW_EZ_HEADER_SIZE 3
	#define ESP_NOW_EZ_PAYLOAD_SIZE ESP_NOW_PAYLOAD_SIZE - ESP_NOW_EZ_HEADER_SIZE

	Payload(Type type);
};

struct DiscoveryPayload : Payload {
	uint8_t key[ESP_NOW_KEY_LEN];
	char name[ESP_NOW_EZ_PAYLOAD_SIZE - ESP_NOW_KEY_LEN];

	DiscoveryPayload();
};

struct TimePayload : Payload {
	uint64_t time; // 8 byte

	TimePayload();
};

struct DataPayload : Payload {
	uint8_t data[ESP_NOW_EZ_PAYLOAD_SIZE];

	DataPayload();
};

#pragma pack(pop)
// uint8_t (*__kaboom)[sizeof( DataPayload )] = 1; // check if size is <=250
