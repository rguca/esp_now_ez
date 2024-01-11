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
			config->pmk = new uint8_t[sizeof(Payload::Discovery::pmk)];
			for (int i=0; i<sizeof(Payload::Discovery::pmk); i++) {
				config->pmk[i] = rand() & 0xff;
			}
		}
		if (config->lmk == nullptr) {
			config->lmk = new uint8_t[sizeof(Payload::Discovery::lmk)];
			for (int i=0; i<sizeof(Payload::Discovery::lmk); i++) {
				config->lmk[i] = rand() & 0xff;
			}
		}
	}
	this->installPmk();

	if (config->name == nullptr) {
		config->name = new char[sizeof(Payload::Discovery::name)];
		const char* prefix;
		if (config->is_master) {
			prefix = "Gateway";
		} else {
			prefix = "Device";
		}
		snprintf(config->name, sizeof(Payload::Discovery::name), "%s-%02x%02x%02x%02x%02x%02x", 
			prefix, chip_id[0], chip_id[1], chip_id[2], chip_id[3], chip_id[4], chip_id[5]);
	}
	
	ESP_LOGI(TAG, "Initialized");
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
	ESP_LOGI(TAG, "Stop pair");
	this->is_pair = false;
}

void EspNowEz::sendDiscovery(const uint8_t* dst_mac) {
	if (dst_mac == nullptr) {
		dst_mac = this->BROADCAST_MAC;
	}

	Payload::Discovery discovery;
	std::strncpy(discovery.name, this->config->name, sizeof(discovery.name));
	discovery.name[sizeof(discovery.name) - 1] = '\0';
	std::memcpy(discovery.pmk, this->config->pmk, sizeof(discovery.pmk));
	std::memcpy(discovery.lmk, this->config->lmk, sizeof(discovery.lmk));

	Payload payload;
	payload.type = Payload::Type::DISCOVERY;
	payload.body.discovery = discovery;

	ESP_ERROR_CHECK(esp_now_send(dst_mac, (const uint8_t*) &payload, sizeof(payload)));
	ESP_LOGI(TAG, "Discovery sent");
}

void EspNowEz::addPeer(const uint8_t* mac, bool encrypt) {
	esp_now_peer_info_t peer;
	peer.ifidx = WIFI_IF_STA;
	peer.channel = config->channel;
	peer.encrypt = encrypt;
	std::memcpy(peer.peer_addr, mac, ESP_NOW_ETH_ALEN);
	ESP_ERROR_CHECK(esp_now_add_peer(&peer));
}

void EspNowEz::installPmk(const uint8_t* pmk) {
	if (pmk != nullptr) {
		std::memcpy(this->config->pmk, pmk, sizeof(Payload::Discovery::pmk));
	}
	ESP_ERROR_CHECK(esp_now_set_pmk(this->config->pmk));
	if (esp_log_level_get(TAG) >= ESP_LOG_DEBUG) {
		uint8_t* k = this->config->pmk;
		ESP_LOGD(TAG, "set pmk: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x", 
			k[0], k[1], k[2], k[3], k[4], k[5], k[6], k[7], k[8], k[9], k[10], k[11], k[12], k[13], k[14], k[15]);
	}
}

void EspNowEz::installPeerLmk(const uint8_t* mac, const uint8_t* lmk) {
	esp_now_peer_info_t peer;
	ESP_ERROR_CHECK(esp_now_get_peer(mac, &peer));
	peer.encrypt = lmk != nullptr;
	if (lmk != nullptr) {
		std::memcpy(peer.lmk, lmk, sizeof(ESP_NOW_KEY_LEN));
	}
	ESP_ERROR_CHECK(esp_now_mod_peer(&peer));
	if (lmk != nullptr && esp_log_level_get(TAG) >= ESP_LOG_DEBUG) {
		const uint8_t* k = lmk;
		ESP_LOGD(TAG, "set peer lmk: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x", 
			k[0], k[1], k[2], k[3], k[4], k[5], k[6], k[7], k[8], k[9], k[10], k[11], k[12], k[13], k[14], k[15]);
	}
}

void EspNowEz::onMessageReceived(const esp_now_recv_info_t *recv_info, const uint8_t *data, int len) {
	if (esp_log_level_get(TAG) >= ESP_LOG_DEBUG) {
		uint8_t* mac = recv_info->src_addr;
		ESP_LOGD(TAG, "src: %02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
		mac = recv_info->des_addr;
		ESP_LOGD(TAG, "dst: %02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
		ESP_LOGD(TAG, "len: %d", len);
	}

	const Payload* payload = reinterpret_cast<const Payload*>(data);

	if (payload->type == Payload::Type::DISCOVERY) {
		ESP_LOGI(TAG, "Discovery name: %s", payload->body.discovery.name);

		if (this->is_pair) {
			const Payload::Discovery* discovery = &payload->body.discovery;
			uint8_t* mac = recv_info->src_addr;

			if (this->config->is_master) {
				this->installPeerLmk(mac, discovery->lmk);
			} else {
				this->addPeer(mac);
				this->sendDiscovery(mac);
				this->installPmk(discovery->pmk);
				this->installPeerLmk(mac, discovery->lmk);
			}

			ESP_LOGI(TAG, "paired %02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
			this->stopPair();
		}
	}
}

void EspNowEz::onMessageSent(const uint8_t *mac_addr, esp_now_send_status_t status) {
	ESP_LOGI(TAG, "Delivery status: %s", status == ESP_NOW_SEND_SUCCESS ? "OK" : "NOK");
}

EspNowEz::~EspNowEz() {
	delete this->config->name;
	delete[] this->config->pmk;
	delete[] this->config->lmk;
	delete this->config;
}
