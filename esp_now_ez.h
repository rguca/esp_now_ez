#include <cstring>
#include <vector>
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_wifi.h"
#include "esp_now.h"
#include "esp_mac.h"
#include "nvs_flash.h"

#include "payload.h"

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
	void sendMessage(const Payload* payload, const uint8_t* mac = nullptr);
   void sendDiscovery(const uint8_t* mac = nullptr);
	void addPeer(const uint8_t* mac, const uint8_t* lmk = nullptr);
	void modifyPeer(const uint8_t* mac, const uint8_t* lmk = nullptr);
	std::vector<esp_now_peer_info_t> getPeers();
	~EspNowEz();

protected:
	static EspNowEz* instance;
	Config* config;
	bool is_pair = false;

	void installPmk(const uint8_t* pmk = nullptr);
	void onMessageReceived(const esp_now_recv_info_t *recv_info, const uint8_t *data, int len);
	void onMessageSent(const uint8_t* mac_addr, esp_now_send_status_t status);
	void logKey(const char* name, const uint8_t* key);
};
