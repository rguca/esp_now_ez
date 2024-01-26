#define LOG_LOCAL_LEVEL ESP_LOG_DEBUG

#include <cstring>
#include <algorithm>

#include "esp_log.h"
#include "esp_netif.h"
#include "esp_wifi.h"
#include "esp_now.h"
#include "esp_system.h"
#include "nvs_flash.h"
#ifndef CONFIG_IDF_TARGET_ESP8266
	#include "esp_mac.h"
#endif

#include "cppcrc.h"
#include "ecdh.h"
#include "esp_now_ez.h"

EspNowEz* EspNowEz::instance;

void EspNowEz::setDebug(bool enable) {
	this->is_debug = enable;
}

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
		if (this->is_debug)
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

	// Set pairwise master key
	if (config->pmk != nullptr) {
		this->logKey("pmk", this->config->pmk);
		ESP_ERROR_CHECK(esp_now_set_pmk(this->config->pmk));
	}

	// Generate keys
	if (config->ecdh == nullptr) {
		config->ecdh = new Ecdh;
		config->ecdh->generateKeypair();
	}

	if (config->name == nullptr) {
		config->name = new char[sizeof(DiscoveryPayload::name)];
		snprintf(config->name, sizeof(DiscoveryPayload::name), "%02x%02x%02x%02x%02x%02x", 
			chip_id[0], chip_id[1], chip_id[2], chip_id[3], chip_id[4], chip_id[5]);
	}
	
	ESP_LOGI(TAG, "Initialized");
}

void EspNowEz::startPair(uint16_t time_ms) {
	if (this->is_pair) {
		return;
	}
	ESP_LOGI(TAG, "Start pair");
	this->is_pair = true;
	if (this->config->is_server) {
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
	std::memcpy(discovery.key, this->config->ecdh->public_key, ECDH_KEY_SIZE);

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
	} else {
		Peer* peer = this->findPeer(mac);
		if (peer) {
			payload->seq = ++peer->send_seq;
			if (this->is_debug) ESP_LOGD(TAG, "seq=%08x", (unsigned int)payload->seq);
		}
	}
	payload->crc = this->calcCrc((uint8_t*) payload, size);

	ESP_ERROR_CHECK(esp_now_send(mac, (uint8_t*) payload, size));
	if (this->is_debug)
		ESP_LOGD(TAG, "Sent %uB to %02x:%02x:%02x:%02x:%02x:%02x", size, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void EspNowEz::addPeer(const uint8_t* mac, const uint8_t* lmk) {
	ESP_LOGI(TAG, "Add peer: %02x:%02x:%02x:%02x:%02x:%02x",	mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	esp_now_peer_info_t peer_info;
	memset(&peer_info, 0, sizeof(esp_now_peer_info_t));
	peer_info.ifidx = WIFI_IF_STA;
	peer_info.channel = config->channel;
	std::memcpy(peer_info.peer_addr, mac, ESP_NOW_ETH_ALEN);
	peer_info.encrypt = lmk != nullptr;
	if (lmk != nullptr) {
		std::memcpy(peer_info.lmk, lmk, sizeof(ESP_NOW_KEY_LEN));
		this->logKey("lmk", lmk);
	}
	ESP_ERROR_CHECK(esp_now_add_peer(&peer_info));

	if (!this->isBroadcastMac(peer_info.peer_addr)) {
		this->peers.push_back(new Peer(peer_info));
	}
}

void EspNowEz::modifyPeer(const uint8_t* mac, const uint8_t* lmk) {
	if (this->is_debug) 
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

std::vector<EspNowEz::Peer*> EspNowEz::getPeers() {
	if (this->peers.size() > 0)
		return this->peers;

	esp_now_peer_info_t peer_info;
	if (esp_now_fetch_peer(true, &peer_info) != ESP_OK) 
		return this->peers;
	
	do {
		this->peers.push_back(new Peer(peer_info));
	} while (esp_now_fetch_peer(false, &peer_info) == ESP_OK);

	return this->peers;
}

EspNowEz::Peer* EspNowEz::findPeer(const uint8_t* mac) {
	for(auto it = this->peers.begin(); it != this->peers.end(); ++it) {
		if (memcmp(mac, (*it)->mac, ESP_NOW_ETH_ALEN) != 0)
			continue;
		if (it != this->peers.begin()) {
			std::rotate(this->peers.begin(), it, this->peers.end()); // move to front
		}
		return *this->peers.begin();
	}
	return nullptr;
}

void EspNowEz::onReceive(const uint8_t *mac, const uint8_t *data, int len) {
	if (this->is_debug)
		ESP_LOGD(TAG, "received %dB from %02x:%02x:%02x:%02x:%02x:%02x", len, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

	const Payload* payload = reinterpret_cast<const Payload*>(data);
	if (!this->checkCrc(payload, len)) return;

	if (this->is_pair && payload->type == Payload::Type::DISCOVERY) {
		const DiscoveryPayload* discovery = reinterpret_cast<const DiscoveryPayload*>(payload);
		if (!this->checkSize(discovery, len)) {
			return;
		}
		ESP_LOGI(TAG, "Discovery received: %s", discovery->name);

		uint8_t shared_secret[ECDH_SHARED_SECRET_SIZE];
		if (!this->config->ecdh->generateSharedSecret(discovery->key, shared_secret)) {
			return;
		}
		if (this->config->is_server) {
			this->addPeer(mac, shared_secret);
		} else {
			this->addPeer(mac);
			this->sendDiscovery(mac);
			this->modifyPeer(mac, shared_secret);
		}

		this->stopPair();
		return;
	}

	if (!this->checkSeq(mac, payload)) return;
}

void EspNowEz::onSent(const uint8_t *mac_addr, esp_now_send_status_t status) {
	if (this->is_debug) ESP_LOGD(TAG, "Delivery status: %s", status == ESP_NOW_SEND_SUCCESS ? "OK" : "NOK");
}

bool EspNowEz::checkCrc(const Payload* payload, uint8_t size) {
	uint8_t crc_size = sizeof(Payload::crc);
	if (size <= crc_size) return false;

	uint16_t crc = this->calcCrc(((uint8_t*)payload) + crc_size, size - crc_size, crc_size);
	if (payload->crc != crc) {
		if (this->is_debug) ESP_LOGD(TAG, "crc NOK: %04x<>%04x", payload->crc, crc);
		return false;
	}

	if (this->is_debug) ESP_LOGD(TAG, "crc OK");
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
	if (this->is_debug) ESP_LOGD(TAG, "crc=%04x size=%u", crc, size + pad_bytes);
	return crc;
}

bool EspNowEz::checkSeq(const uint8_t *mac, const Payload* payload) {
	Peer* peer = this->findPeer(mac);
	if (!peer) {
		if (this->is_debug) ESP_LOGD(TAG, "seq NOK: peer not found");
		return false;
	}
	if (payload->seq != (peer->recv_seq + 1)) {
		if (this->is_debug) ESP_LOGD(TAG, "seq NOK: %08x<>%08x", (unsigned int)payload->seq, (unsigned int)(peer->recv_seq + 1));
		return false;
	}
	peer->recv_seq++;
	if (this->is_debug) ESP_LOGD(TAG, "seq OK");
	return true;
}

void EspNowEz::logKey(const char* name, const uint8_t* key) {
	 if (!this->is_debug) return;

	const uint8_t* k = key;
	ESP_LOGD(TAG, "%s=%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x", 
			name, k[0], k[1], k[2], k[3], k[4], k[5], k[6], k[7], k[8], k[9], k[10], k[11], k[12], k[13], k[14], k[15]);
}

bool EspNowEz::isBroadcastMac(const uint8_t* mac) {
	return memcmp(mac, BROADCAST_MAC, ESP_NOW_ETH_ALEN) == 0;
}

EspNowEz::~EspNowEz() {
	for(EspNowEz::Peer* peer : this->peers) {
		delete peer;
	}

	delete this->config->name;
	delete[] this->config->pmk;
	delete this->config->ecdh;
	delete this->config;
}

EspNowEz::Peer::Peer(esp_now_peer_info peer_info) {
	memcpy(this->mac, peer_info.peer_addr, sizeof(Peer::mac));
}
