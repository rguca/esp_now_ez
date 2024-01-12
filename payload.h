#pragma once

#include <cstring>
#include "esp_now.h"

#pragma pack(push, 1)
struct Payload {
   #define ESP_NOW_PAYLOAD_SIZE 250

   enum Type : uint8_t {
      DISCOVERY = 0,
      TEXT = 10,
      DISPLAY_TEXT = 20,
   } type; // 1 byte

   #define ESP_NOW_EZ_PAYLOAD_SIZE ESP_NOW_PAYLOAD_SIZE - 1

   Payload(Type type) { this->type = type; };
   uint8_t size() const;
};

struct DiscoveryPayload : Payload {
   uint8_t pmk[ESP_NOW_KEY_LEN];
   uint8_t lmk[ESP_NOW_KEY_LEN];
   char name[100];

   DiscoveryPayload();
};

struct TextPayload : Payload {
   char text[ESP_NOW_EZ_PAYLOAD_SIZE];

   TextPayload(const char* text);
};

struct DisplayTextPayload : Payload {
   bool clear; // 1 byte
   uint16_t x; // 2 byte
   uint16_t y; // 2 byte
   uint8_t font_size; // 1 byte
   char text[ESP_NOW_EZ_PAYLOAD_SIZE - 6];
   
   DisplayTextPayload() : Payload{DISPLAY_TEXT}{};
};
#pragma pack(pop)
// uint8_t (*__kaboom)[sizeof( DiscoveryPayload )] = 1; // check if size is <=250
