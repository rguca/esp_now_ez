#define LOG_LOCAL_LEVEL ESP_LOG_DEBUG

#include <cstring>
#include <algorithm>

#include <esp_log.h>
#include <esp_netif.h>
#include <esp_wifi.h>
#include <esp_now.h>
#include <esp_system.h>
#include <nvs_flash.h>
#ifndef CONFIG_IDF_TARGET_ESP8266
	#include <esp_mac.h>
	#include <esp_random.h>
#endif

#include "cppcrc.h"
#include "ecdh.h"
#include "esp_now_ez.h"

EspNowEz* EspNowEz::instance;

#ifdef CONFIG_IDF_TARGET_ESP8266
	static esp_err_t nvs_entry_find(const char *part_name, const char *namespace_name, nvs_type_t type, nvs_iterator_t* output_iterator) {
		nvs_iterator_t it = nvs_entry_find(part_name, namespace_name, type);
		if (it == nullptr) return ESP_ERR_NVS_NOT_FOUND;
		*output_iterator = it;
		return ESP_OK;
	}

	static esp_err_t nvs_entry_next(nvs_iterator_t *iterator) {
		nvs_iterator_t it = nvs_entry_next(*iterator);
		if (it == nullptr) return ESP_ERR_NVS_NOT_FOUND;
		*iterator = it;
		return ESP_OK;
	}	
#endif

void EspNowEz::setDebug(bool enable) {
	this->is_debug = enable;
}

void EspNowEz::init(Config* config) {
	if (config == nullptr) {
		config = new Config;
	}
	this->config = config;
	
	ESP_ERROR_CHECK(esp_efuse_mac_get_default(this->mac));
	esp_base_mac_addr_set(this->mac); // Without this, base mac is read multiple times from nvs

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

	this->loadPeers();

	ESP_LOGI(TAG, "Initialized");
}

void EspNowEz::startPair(uint16_t time_ms) {
	if (this->is_pair) {
		return;
	}
	ESP_LOGI(TAG, "Start pair");

	// Generate keys
	if (config->ecdh == nullptr) {
		config->ecdh = new Ecdh;
		config->ecdh->generateKeypair();
		ESP_LOGD(TAG, "generated keys");
	}

	this->is_pair = true;
	if (!this->config->is_server) {
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
	ESP_LOGI(TAG, "Send discovery");
	if (config->name == nullptr) {
		config->name = new char[sizeof(DiscoveryPayload::name)];
		snprintf(config->name, sizeof(DiscoveryPayload::name), "%02x%02x%02x%02x%02x%02x", 
			this->mac[0], this->mac[1], this->mac[2], this->mac[3], this->mac[4], this->mac[5]);
	}

	DiscoveryPayload discovery;
	std::strncpy(discovery.name, this->config->name, sizeof(discovery.name));
	discovery.name[sizeof(discovery.name) - 1] = '\0';
	std::memcpy(discovery.key, this->config->ecdh->public_key, ECDH_KEY_SIZE);

	this->sendMessage(&discovery, mac);
}

void EspNowEz::sendConfig(const uint8_t* mac, uint32_t old_seq) {
	if (this->is_debug) ESP_LOGD(TAG, "send config");
	Peer* peer = this->findPeer(mac);
	if (!peer) {
		if (this->is_debug) ESP_LOGD(TAG, "peer not found");
		return;
	}

	ConfigPayload payload;
	payload.old_seq = old_seq;
	payload.new_seq = peer->recv_seq;

	this->sendMessage(&payload, mac);
}

void EspNowEz::sendMessage(const uint8_t* data, uint8_t size, const uint8_t* mac) {
	auto payload = DataPayload{};
   memcpy(payload.data, data, size);
   this->send(&payload, ESP_NOW_EZ_HEADER_SIZE + size, mac);
}

void EspNowEz::send(Payload* payload, uint8_t size, const uint8_t* mac) {
	bool is_broadcast = mac == nullptr;
	if (is_broadcast)
		mac = this->BROADCAST_MAC;

	if (this->is_debug)
		ESP_LOGD(TAG, "send %uB to %02x:%02x:%02x:%02x:%02x:%02x", size, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

	if (!is_broadcast) {
		Peer* peer = this->findPeer(mac);
		if (peer) {
			payload->seq = ++peer->send_seq;
			if (this->is_debug) ESP_LOGD(TAG, "seq=%08" PRIx32, payload->seq);
		}
	}

	payload->crc = this->calcCrc((uint8_t*) payload, size);
	if (this->is_debug) ESP_LOGD(TAG, "crc=%04x", payload->crc);

	ESP_ERROR_CHECK(esp_now_send(mac, (uint8_t*) payload, size));
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

	esp_err_t result = esp_now_add_peer(&peer_info);
	if (result == ESP_ERR_ESPNOW_EXIST) {
		this->modifyPeer(mac, lmk);
		return;
	}
	ESP_ERROR_CHECK(result);

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

std::vector<EspNowEz::Peer*> EspNowEz::getPeers() {
	return this->peers;
}

void EspNowEz::loadPeers() {
	if (this->is_debug) ESP_LOGD(TAG, "load peers");

	nvs_handle_t nvs;
	ESP_ERROR_CHECK(nvs_open(NVS_NAMESPACE, NVS_READWRITE, &nvs));

	nvs_iterator_t it = nullptr;
	esp_err_t res = nvs_entry_find(NVS_DEFAULT_PART_NAME, NVS_NAMESPACE, NVS_TYPE_BLOB, &it);
	while(res == ESP_OK) {
		nvs_entry_info_t info;
		nvs_entry_info(it, &info);

		uint8_t mac[sizeof(esp_now_peer_info_t::peer_addr)];
		for (int i=0; i<sizeof(mac); i++) {
			char ch = info.key[i * 2];
			mac[i] = (ch > 57 ? (ch - 87) : (ch - 48)) << 4;
			ch = info.key[i * 2 + 1];
			mac[i] |= ch > 57 ? (ch - 87) : (ch - 48);
		}

		size_t size = sizeof(esp_now_peer_info_t::lmk);
		uint8_t lmk[size];
		ESP_ERROR_CHECK(nvs_get_blob(nvs, info.key, lmk, &size));

		this->addPeer(mac, lmk);
		res = nvs_entry_next(&it);
	}
	nvs_release_iterator(it);
}

void EspNowEz::persistPeer(const uint8_t* mac, const uint8_t* lmk) {
	if (this->is_debug) ESP_LOGD(TAG, "persist peer");
	
	nvs_handle_t nvs;
	ESP_ERROR_CHECK(nvs_open(NVS_NAMESPACE, NVS_READWRITE, &nvs));

	char mac_string[ESP_NOW_ETH_ALEN * 2 + 1];
	snprintf(mac_string, sizeof(mac_string), "%02x%02x%02x%02x%02x%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

	ESP_ERROR_CHECK(nvs_set_blob(nvs, mac_string, lmk, ESP_NOW_KEY_LEN));
	nvs_commit(nvs);
}

void EspNowEz::onMessage(OnMessageCallback callback) {
	this->on_message_callback = callback;
}

void EspNowEz::onReceive(const uint8_t *mac, const uint8_t *data, int len) {
	if (this->is_debug)
		ESP_LOGD(TAG, "received %dB from %02x:%02x:%02x:%02x:%02x:%02x", len, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

	const Payload* payload = reinterpret_cast<const Payload*>(data);
	if (!this->checkCrc(payload, len)) return;

	if (payload->type == Payload::Type::DISCOVERY) {
		if (!this->is_pair) return;

		const DiscoveryPayload* discovery = reinterpret_cast<const DiscoveryPayload*>(payload);
		if (!this->checkSize(discovery, len)) return;

		ESP_LOGI(TAG, "Discovery received: %s", discovery->name);

		uint8_t shared_secret[ECDH_SHARED_SECRET_SIZE];
		if (!this->config->ecdh->generateSharedSecret(discovery->key, shared_secret)) return;

		if (this->config->is_server) {
			this->addPeer(mac);
			this->sendDiscovery(mac);
			this->modifyPeer(mac, shared_secret);
		} else {
			this->addPeer(mac, shared_secret);
		}
		this->persistPeer(mac, shared_secret);
		this->stopPair();
		return;
	}

	if (payload->type == Payload::Type::CONFIG) {
		const ConfigPayload* config = reinterpret_cast<const ConfigPayload*>(payload);
		if (!this->checkConfig(mac, config)) return;
	}

	if (!this->checkSeq(mac, payload)) {
		this->sendConfig(mac, payload->seq);
		return;
	}

	if (payload->type == Payload::Type::DATA) {
		const DataPayload* data = reinterpret_cast<const DataPayload*>(payload);
		if (this->on_message_callback) this->on_message_callback(data->data, len - ESP_NOW_EZ_HEADER_SIZE);
	}
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

	if (this->is_debug) ESP_LOGD(TAG, "crc OK: %04x", payload->crc);
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
	return crc;
}

bool EspNowEz::checkSeq(const uint8_t *mac, const Payload* payload) {
	Peer* peer = this->findPeer(mac);
	if (!peer) {
		if (this->is_debug) ESP_LOGD(TAG, "seq NOK: peer not found");
		return false;
	}
	if (payload->seq != (peer->recv_seq + 1)) {
		if (this->is_debug) ESP_LOGD(TAG, "seq NOK: %08" PRIx32 "<>%08" PRIx32, payload->seq, (peer->recv_seq + 1));
		return false;
	}
	peer->recv_seq++;
	if (this->is_debug) ESP_LOGD(TAG, "seq OK: %08" PRIx32, payload->seq);
	return true;
}

bool EspNowEz::checkConfig(const uint8_t *mac, const ConfigPayload* config) {
	Peer* peer = this->findPeer(mac);
	if (!peer) {
		if (this->is_debug) ESP_LOGD(TAG, "config NOK: peer not found");
		return false;
	}
	if (config->old_seq != peer->send_seq) {
		if (this->is_debug) ESP_LOGD(TAG, "config old_seq NOK: %08" PRIx32 "<>%08" PRIx32, config->old_seq, peer->send_seq);
		return false;
	}
	if (this->is_debug) ESP_LOGD(TAG, "config OK");
	if (config->new_seq != peer->send_seq) {
		peer->send_seq = config->new_seq;
		if (this->is_debug) ESP_LOGD(TAG, "seq=%08" PRIx32, peer->send_seq);
	}
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
	this->send_seq = esp_random();
	this->recv_seq = esp_random();
}
