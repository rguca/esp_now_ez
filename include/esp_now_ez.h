#pragma once

#include <vector>
#include <functional>

#include <esp_now.h>

#include "ecdh.h"
#include "payload.h"

namespace EspNowEz {
	struct Config {
		uint8_t channel = 7;
		bool is_server = false;
		char* name = nullptr;
		uint8_t* pmk = nullptr;
		Ecdh* ecdh = nullptr;

		~Config();
	};

	struct Peer {
		uint8_t mac[ESP_NOW_ETH_ALEN];
		uint32_t send_seq = 0;
		uint32_t recv_seq = 0;

		Peer(esp_now_peer_info peer_info);
	};

	typedef std::function<void(const uint8_t* data, size_t size)> OnMessageCallback;

	const static char* NVS_NAMESPACE = "espnowez";
	const static char* TAG = "espnowez";
	const static uint8_t BROADCAST_MAC[ESP_NOW_ETH_ALEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

   void init(Config* config);
	void startPair(uint16_t time_ms = 0);
	void stopPair();
	void sendMessage(const char* text, Peer* peer = nullptr);
	void sendMessage(const uint8_t* data, uint8_t size, Peer* peer = nullptr);
   void sendDiscovery(Peer* peer = nullptr);
	void sendConfig(Peer* peer, uint32_t old_seq);
	void onMessage(OnMessageCallback callback);
	Peer* addPeer(const uint8_t* mac, const uint8_t* lmk = nullptr);
	void modifyPeer(const uint8_t* mac, const uint8_t* lmk = nullptr);
	bool removePeer(const uint8_t* mac);
	Peer* findPeer(const uint8_t* mac);
	std::vector<Peer*> getPeers();
	void deinit();
};
