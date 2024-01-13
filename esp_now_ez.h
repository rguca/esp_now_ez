#include <cstring>
#include <vector>

#include "esp_log.h"
#include "esp_netif.h"
#include "esp_wifi.h"
#include "esp_now.h"
#include "esp_mac.h"
#include "nvs_flash.h"

#include "cppcrc.h"

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
	template<typename T>
	void sendMessage(T* data, const uint8_t* mac = nullptr);
	void sendMessage(const uint8_t* data, uint8_t size, const uint8_t* mac = nullptr);
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
	void send(Payload* payload, uint8_t size, const uint8_t* mac = nullptr);
	void onReceive(const esp_now_recv_info_t *recv_info, const uint8_t *data, int len);
	void onSent(const uint8_t* mac_addr, esp_now_send_status_t status);
	bool checkCrc(const Payload* payload, uint8_t size);
	uint16_t calcCrc(const uint8_t* data, uint8_t size, uint8_t pad_bytes = 0);
	void logKey(const char* name, const uint8_t* key);
};

#include "esp_now_ez.tpp"
