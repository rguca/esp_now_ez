#include "include/esp_now_ez.h"

EspNowEz* EspNowEz::instance;

void EspNowEz::init(Config* config) {
	if (config == nullptr) {
		config = new Config;
	}
	this->config = config;

	uint8_t chip_id[6];
   ESP_ERROR_CHECK(esp_efuse_mac_get_default(chip_id));
	esp_base_mac_addr_set(chip_id); // Without this, base mac is read multiple times from nvs
	
	ESP_ERROR_CHECK(nvs_flash_init());

	ESP_ERROR_CHECK(esp_netif_init());
	ESP_ERROR_CHECK(esp_event_loop_create_default());

	wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
	cfg.nvs_enable = 0;
	ESP_ERROR_CHECK(esp_wifi_init(&cfg) );
	ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
	ESP_ERROR_CHECK(esp_wifi_start());
	uint8_t primary_channel;
	wifi_second_chan_t secondary_channel;
	ESP_ERROR_CHECK(esp_wifi_get_channel(&primary_channel, &secondary_channel));
	if (primary_channel != config->channel) {
		ESP_LOGD(TAG, "switching channel %u -> %u", primary_channel, config->channel);
		ESP_ERROR_CHECK(esp_wifi_set_channel(config->channel, WIFI_SECOND_CHAN_NONE));
	}
	#ifdef CONFIG_IDF_TARGET_ESP8266
		ESP_ERROR_CHECK(esp_wifi_set_protocol(WIFI_IF_STA, WIFI_PROTOCOL_11B|WIFI_PROTOCOL_11G|WIFI_PROTOCOL_11N));
	#else
		// Enable long range
		ESP_ERROR_CHECK(esp_wifi_set_protocol(WIFI_IF_STA, WIFI_PROTOCOL_11B|WIFI_PROTOCOL_11G|WIFI_PROTOCOL_11N|WIFI_PROTOCOL_LR));
	#endif

	ESP_ERROR_CHECK(esp_now_init());
	this->instance = this;
	#ifdef CONFIG_IDF_TARGET_ESP8266
		ESP_ERROR_CHECK(esp_now_register_recv_cb([](const uint8_t* mac, const uint8_t *data, int len) {
			EspNowEz::instance->onReceive(mac, data, len);
		}));
	#else
		ESP_ERROR_CHECK(esp_now_register_recv_cb([](const esp_now_recv_info_t *recv_info, const uint8_t *data, int len) {
			EspNowEz::instance->onReceive(recv_info->src_addr, data, len);
		}));
	#endif
	ESP_ERROR_CHECK(esp_now_register_send_cb([](const uint8_t *mac_addr, esp_now_send_status_t status) {
		EspNowEz::instance->onSent(mac_addr, status);
	}));

	// Add broadcast "peer"
	this->addPeer(this->BROADCAST_MAC);

	// Generate keys
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
	auto payload = DataPayload{};
   memcpy(payload.data, data, size);
   this->send(&payload, ESP_NOW_EZ_HEADER_SIZE + size, mac);
}

void EspNowEz::send(Payload* payload, uint8_t size, const uint8_t* mac) {
	if (mac == nullptr) {
		mac = this->BROADCAST_MAC;
	}
	payload->crc = this->calcCrc((uint8_t*) payload, size);

	ESP_ERROR_CHECK(esp_now_send(mac, (uint8_t*) payload, size));
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

void EspNowEz::onReceive(const uint8_t *mac, const uint8_t *data, int len) {
	if constexpr(LOG_LOCAL_LEVEL >= ESP_LOG_DEBUG) {
		ESP_LOGD(TAG, "received %dB from %02x:%02x:%02x:%02x:%02x:%02x", len, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	}

	const Payload* payload = reinterpret_cast<const Payload*>(data);
	if (!this->checkCrc(payload, len)) return;

	if (this->is_pair && payload->type == Payload::Type::DISCOVERY) {
		const DiscoveryPayload* discovery = reinterpret_cast<const DiscoveryPayload*>(payload);
		ESP_LOGI(TAG, "Discovery received: %s", discovery->name);

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

void EspNowEz::onSent(const uint8_t *mac_addr, esp_now_send_status_t status) {
	ESP_LOGD(TAG, "Delivery status: %s", status == ESP_NOW_SEND_SUCCESS ? "OK" : "NOK");
}

bool EspNowEz::checkCrc(const Payload* payload, uint8_t size) {
	uint8_t crc_size = sizeof(Payload::crc);
	if (size <= crc_size) return false;

	uint16_t crc = this->calcCrc(((uint8_t*)payload) + crc_size, size - crc_size, crc_size);
	if (payload->crc != crc) {
		ESP_LOGD(TAG, "crc mismatch %04x<>%04x", payload->crc, crc);
		return false;
	}

	ESP_LOGD(TAG, "crc match");
	return true;
}

uint16_t EspNowEz::calcCrc(const uint8_t* data, uint8_t size, uint8_t pad_bytes) {
	uint16_t crc;
	if (pad_bytes) {
		uint8_t padding[pad_bytes];
		memset(padding, 0, pad_bytes);
		crc = CRC16::ARC::calc(padding, pad_bytes);
		crc = CRC16::ARC::calc(data, size, crc);
	} else {
		crc = CRC16::ARC::calc(data, size);
	}
	ESP_LOGD(TAG, "crc=%04x size=%u", crc, size + pad_bytes);
	return crc;
}

void EspNowEz::logKey(const char* name, const uint8_t* key) {
	if (LOG_LOCAL_LEVEL < ESP_LOG_DEBUG) {
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
