#include <vector>
#include <functional>
#include <esp_now.h>
#include "ecdh.h"
#include "payload.h"

class EspNowEz {
public:
	struct Config {
		uint8_t channel = 7;
		bool is_server = false;
		char* name = nullptr;
		uint8_t* pmk = nullptr;
		Ecdh* ecdh = nullptr;
	};

	struct Peer {
		uint8_t mac[ESP_NOW_ETH_ALEN];
		uint32_t send_seq = 0;
		uint32_t recv_seq = 0;

		Peer(esp_now_peer_info peer_info);
	};

	typedef std::function<void(const uint8_t* data, size_t size)> OnMessageCallback;

	const char* TAG = "espnowez";
	const char* NVS_NAMESPACE = "espnowez";
   const uint8_t BROADCAST_MAC[ESP_NOW_ETH_ALEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

	void setDebug(bool enable);
   void init(Config* config = nullptr);
	void startPair(uint16_t time_ms = 0);
	void stopPair();
	template<typename T>
	void sendMessage(T* data, const uint8_t* mac = nullptr);
	void sendMessage(const uint8_t* data, uint8_t size, const uint8_t* mac = nullptr);
   void sendDiscovery(const uint8_t* mac = nullptr);
	void sendConfig(const uint8_t* mac, uint32_t old_seq);
	void onMessage(OnMessageCallback callback);
	void addPeer(const uint8_t* mac, const uint8_t* lmk = nullptr);
	void modifyPeer(const uint8_t* mac, const uint8_t* lmk = nullptr);
	Peer* findPeer(const uint8_t* mac);
	std::vector<Peer*> getPeers();
	bool isBroadcastMac(const uint8_t* mac);
	~EspNowEz();

protected:
	static EspNowEz* instance;

	bool is_debug = false;
	Config* config;
	bool is_pair = false;
	std::vector<Peer*> peers;
	OnMessageCallback on_message_callback;

	void send(Payload* payload, uint8_t size, const uint8_t* mac = nullptr);
	void onReceive(const uint8_t *mac, const uint8_t *data, int len);
	void onSent(const uint8_t* mac_addr, esp_now_send_status_t status);
	template<typename T>
	bool checkSize(T* payload, uint8_t size);
	bool checkCrc(const Payload* payload, uint8_t size);
	uint16_t calcCrc(const uint8_t* data, uint8_t size, uint8_t pad_bytes = 0);
	bool checkSeq(const uint8_t *mac, const Payload* payload);
	bool checkConfig(const uint8_t *mac, const ConfigPayload* config);
	void loadPeers();
	void persistPeer(const uint8_t* mac);
	void logKey(const char* name, const uint8_t* key);
};

#include "esp_now_ez.tpp"
