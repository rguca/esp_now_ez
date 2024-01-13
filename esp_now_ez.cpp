#include "esp_now_ez.h"

EspNowEz* EspNowEz::instance;

void EspNowEz::init(Config* config) {
	if (config == nullptr) {
		config = new Config;
	}
	this->config = config;
	ESP_ERROR_CHECK(nvs_flash_init());
	ESP_ERROR_CHECK(esp_netif_init());
	ESP_ERROR_CHECK(esp_event_loop_create_default());
	wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
	cfg.nvs_enable = 0;
	ESP_ERROR_CHECK(esp_wifi_init(&cfg) );
	ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
	ESP_ERROR_CHECK(esp_wifi_start());
	ESP_ERROR_CHECK(esp_wifi_set_channel(config->channel, WIFI_SECOND_CHAN_NONE));

	// Enable long range
	ESP_ERROR_CHECK(esp_wifi_set_protocol(WIFI_IF_STA, WIFI_PROTOCOL_11B|WIFI_PROTOCOL_11G|WIFI_PROTOCOL_11N|WIFI_PROTOCOL_LR));

	ESP_ERROR_CHECK(esp_now_init());
	this->instance = this;
	ESP_ERROR_CHECK(esp_now_register_recv_cb([](const esp_now_recv_info_t *recv_info, const uint8_t *data, int len) {
		EspNowEz::instance->onMessageReceived(recv_info, data, len);
	}));
	ESP_ERROR_CHECK(esp_now_register_send_cb([](const uint8_t *mac_addr, esp_now_send_status_t status) {
		EspNowEz::instance->onMessageSent(mac_addr, status);
	}));

	// Add broadcast "peer"
	this->addPeer(this->BROADCAST_MAC);

	// Generate keys
	uint8_t chip_id[6];
   ESP_ERROR_CHECK(esp_efuse_mac_get_default(chip_id));

	if (config->pmk == nullptr || config->lmk == nullptr) {
		unsigned int seed;
		std::memcpy(&seed, chip_id, sizeof(unsigned int));
		srand(seed);

		if (config->pmk == nullptr) {
			config->pmk = new uint8_t[sizeof(DiscoveryPayload::key)];
			for (int i=0; i<sizeof(DiscoveryPayload::key); i++) {
				config->pmk[i] = rand() & 0xff;
			}
		}
		if (config->lmk == nullptr) {
			config->lmk = new uint8_t[sizeof(DiscoveryPayload::key)];
			for (int i=0; i<sizeof(DiscoveryPayload::key); i++) {
				config->lmk[i] = rand() & 0xff;
			}
		}
	}
	this->installPmk();
	this->logKey("lmk", this->config->lmk);

	if (config->name == nullptr) {
		config->name = new char[sizeof(DiscoveryPayload::name)];
		snprintf(config->name, sizeof(DiscoveryPayload::name), "%02x%02x%02x%02x%02x%02x", 
			chip_id[0], chip_id[1], chip_id[2], chip_id[3], chip_id[4], chip_id[5]);
	}
	
	ESP_LOGI(TAG, "Initialized");
}

void EspNowEz::installPmk(const uint8_t* pmk) {
	if (pmk != nullptr) {
		std::memcpy(this->config->pmk, pmk, sizeof(DiscoveryPayload::key));
	}
	this->logKey("pmk", this->config->pmk);
	ESP_ERROR_CHECK(esp_now_set_pmk(this->config->pmk));
}

void EspNowEz::startPair(uint16_t time_ms) {
	if (this->is_pair) {
		return;
	}
	ESP_LOGI(TAG, "Start pair");
	this->is_pair = true;
	if (this->config->is_master) {
		this->sendDiscovery();
	}
	if (time_ms == 0) {
		return;
	}
	vTaskDelay(time_ms / portTICK_PERIOD_MS);
	this->stopPair();
}

void EspNowEz::stopPair() {
	if (!this->is_pair) {
		return;
	}
	ESP_LOGI(TAG, "Stop pair");
	this->is_pair = false;
}

void EspNowEz::sendDiscovery(const uint8_t* mac) {
	DiscoveryPayload discovery;
	std::strncpy(discovery.name, this->config->name, sizeof(discovery.name));
	discovery.name[sizeof(discovery.name) - 1] = '\0';
	const uint8_t* key = this->config->is_master ? this->config->pmk : this->config->lmk;
	std::memcpy(discovery.key, key, sizeof(DiscoveryPayload::key));

	this->sendMessage(&discovery, mac);
	ESP_LOGI(TAG, "Discovery sent");
}

void EspNowEz::sendMessage(const uint8_t* data, uint8_t size, const uint8_t* mac) {
	if (mac == nullptr) {
		mac = this->BROADCAST_MAC;
	}
	ESP_ERROR_CHECK(esp_now_send(mac, data, size));
	ESP_LOGD(TAG, "Sent %uB to %02x:%02x:%02x:%02x:%02x:%02x", size, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void EspNowEz::addPeer(const uint8_t* mac, const uint8_t* lmk) {
	ESP_LOGI(TAG, "Add peer: %02x:%02x:%02x:%02x:%02x:%02x",	mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	esp_now_peer_info_t peer;
	memset(&peer, 0, sizeof(esp_now_peer_info_t));
	peer.ifidx = WIFI_IF_STA;
	peer.channel = config->channel;
	std::memcpy(peer.peer_addr, mac, ESP_NOW_ETH_ALEN);
	peer.encrypt = lmk != nullptr;
	if (lmk != nullptr) {
		std::memcpy(peer.lmk, lmk, sizeof(ESP_NOW_KEY_LEN));
		this->logKey("lmk", lmk);
	}
	ESP_ERROR_CHECK(esp_now_add_peer(&peer));
}

void EspNowEz::modifyPeer(const uint8_t* mac, const uint8_t* lmk) {
	ESP_LOGD(TAG, "Modify peer: %02x:%02x:%02x:%02x:%02x:%02x",	mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	esp_now_peer_info_t peer;
	memset(&peer, 0, sizeof(esp_now_peer_info_t));
	ESP_ERROR_CHECK(esp_now_get_peer(mac, &peer));
	peer.encrypt = lmk != nullptr;
	if (lmk != nullptr) {
		std::memcpy(peer.lmk, lmk, sizeof(ESP_NOW_KEY_LEN));
		this->logKey("lmk", lmk);
	}
	ESP_ERROR_CHECK(esp_now_mod_peer(&peer));
}

std::vector<esp_now_peer_info_t> EspNowEz::getPeers() {
	std::vector<esp_now_peer_info_t> peers;
	esp_now_peer_info_t peer;
	if (esp_now_fetch_peer(true, &peer) != ESP_OK) return peers;
	peers.push_back(peer);
	while (esp_now_fetch_peer(false, &peer) == ESP_OK) {
		peers.push_back(peer);
	}
	return peers;
}

void EspNowEz::onMessageReceived(const esp_now_recv_info_t *recv_info, const uint8_t *data, int len) {
	if (esp_log_level_get(TAG) >= ESP_LOG_DEBUG) {
		uint8_t* s = recv_info->src_addr;
		const char* b = memcmp(recv_info->des_addr, BROADCAST_MAC, sizeof(BROADCAST_MAC)) == 0 ? " (Broadcast)" : "";
		ESP_LOGD(TAG, "Received %dB from %02x:%02x:%02x:%02x:%02x:%02x%s", len, s[0], s[1], s[2], s[3], s[4], s[5], b);
	}

	const Payload* payload = reinterpret_cast<const Payload*>(data);

	if (this->is_pair && payload->type == Payload::Type::DISCOVERY) {
		const DiscoveryPayload* discovery = reinterpret_cast<const DiscoveryPayload*>(payload);
		ESP_LOGI(TAG, "Discovery received: %s", discovery->name);

		uint8_t* mac = recv_info->src_addr;
		if (this->config->is_master) {
			this->addPeer(mac, discovery->key);
		} else {
			this->addPeer(mac);
			this->sendDiscovery(mac);
			this->installPmk(discovery->key);
			this->modifyPeer(mac, config->lmk);
		}

		this->stopPair();
	}
}

void EspNowEz::onMessageSent(const uint8_t *mac_addr, esp_now_send_status_t status) {
	ESP_LOGD(TAG, "Delivery status: %s", status == ESP_NOW_SEND_SUCCESS ? "OK" : "NOK");
}

uint16_t EspNowEz::calcCrc(const uint8_t* data, uint8_t size) {
	uint16_t crc = CRC16::ARC::calc(data, size);
	ESP_LOGD(TAG, "crc=%04x size=%u", crc, size);
	return crc;
}

void EspNowEz::logKey(const char* name, const uint8_t* key) {
	if (esp_log_level_get(TAG) < ESP_LOG_DEBUG) {
		return;
	}
	const uint8_t* k = key;
	ESP_LOGD(TAG, "%s=%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x", 
			name, k[0], k[1], k[2], k[3], k[4], k[5], k[6], k[7], k[8], k[9], k[10], k[11], k[12], k[13], k[14], k[15]);
}

EspNowEz::~EspNowEz() {
	delete this->config->name;
	delete[] this->config->pmk;
	delete[] this->config->lmk;
	delete this->config;
}
