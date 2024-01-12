#include "payload.h"

DiscoveryPayload::DiscoveryPayload() : Payload{DISCOVERY} {}

TextPayload::TextPayload(const char* text) : Payload{TEXT} {
   strncpy(this->text, text, sizeof(this->text));
   this->text[sizeof(this->text) - 1] = '\0';
};

uint8_t Payload::size() const {
	switch(this->type) {
	case DISCOVERY:
		return sizeof(DiscoveryPayload);
	case TEXT:
		return ESP_NOW_PAYLOAD_SIZE - sizeof(TextPayload) + strlen(((TextPayload*)this)->text) + 1;
	case DISPLAY_TEXT:
		return ESP_NOW_PAYLOAD_SIZE - sizeof(DisplayTextPayload) + strlen(((DisplayTextPayload*)this)->text) + 1;
	default:
		return ESP_NOW_PAYLOAD_SIZE; 
	}
}
