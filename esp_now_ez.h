#include <cstring>
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_wifi.h"
#include "esp_now.h"
#include "esp_mac.h"
#include "nvs_flash.h"

class EspNowEz {
public:
	struct Config {
		uint8_t channel = 7;
		bool is_master = false;
		char* name = nullptr;
		uint8_t* pmk = nullptr;
		uint8_t* lmk = nullptr;
	};

	const char* TAG = "espnowez";
   const uint8_t BROADCAST_MAC[ESP_NOW_ETH_ALEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

   void init(Config* config = nullptr);
	void startPair(uint16_t time_ms = 0);
	void stopPair();
   void sendDiscovery(const uint8_t* dst_mac = nullptr);
	void addPeer(const uint8_t* mac, bool encrypt = false);
	void installPeerLmk(const uint8_t* mac, const uint8_t* lmk = nullptr);
	~EspNowEz();

protected:
	#pragma pack(push, 1)
	class Payload {
	public:
		#define PAYLOAD_SIZE 250

		enum Type : uint8_t {
			DISCOVERY = 0,
			DISPLAY_TEXT = 10
		} type; // 1 byte

		#define BODY_SIZE PAYLOAD_SIZE - 1

		struct Discovery {
			uint8_t pmk[ESP_NOW_KEY_LEN];
			uint8_t lmk[ESP_NOW_KEY_LEN];
			char name[100];
		};

		struct DisplayText {
			bool clear; // 1 byte
			uint16_t x; // 2 byte
			uint16_t y; // 2 byte
			uint8_t size; // 1 byte
			char text[BODY_SIZE - 6];
		};

		union Body {
			Discovery discovery;
			DisplayText displayText;
		} body;
	};
	#pragma pack(pop)
	// uint8_t (*__kaboom)[sizeof( Payload )] = 1; // check if size is 250

	static EspNowEz* instance;
	Config* config;
	bool is_pair = false;

	void installPmk(const uint8_t* pmk = nullptr);
	void onMessageReceived(const esp_now_recv_info_t *recv_info, const uint8_t *data, int len);
	void onMessageSent(const uint8_t *mac_addr, esp_now_send_status_t status);
};
