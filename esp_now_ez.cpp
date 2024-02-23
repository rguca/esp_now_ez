#define LOG_LOCAL_LEVEL ESP_LOG_DEBUG

#include <cstring>
#include <algorithm>

#include <esp_log.h>
#include <esp_netif.h>
#include <esp_wifi.h>
#include <esp_now.h>
#include <esp_system.h>
#include <nvs_flash.h>
#include <esp_crc.h>
#if ESP_IDF_VERSION >= ESP_IDF_VERSION_VAL(4, 4, 0)
	#include <esp_mac.h>
	#include <esp_random.h>
#endif

#include "ecdh.h"
#include "esp_now_ez.h"

#if ESP_IDF_VERSION < ESP_IDF_VERSION_VAL(4, 4, 0)
	esp_err_t nvs_entry_find(const char *part_name, const char *namespace_name, nvs_type_t type, nvs_iterator_t* output_iterator) {
		nvs_iterator_t it = nvs_entry_find(part_name, namespace_name, type);
		if (it == nullptr) return ESP_ERR_NVS_NOT_FOUND;
		*output_iterator = it;
		return ESP_OK;
	}

	esp_err_t nvs_entry_next(nvs_iterator_t *iterator) {
		nvs_iterator_t it = nvs_entry_next(*iterator);
		if (it == nullptr) return ESP_ERR_NVS_NOT_FOUND;
		*iterator = it;
		return ESP_OK;
	}

	uint16_t esp_crc16_le(uint16_t crc, uint8_t const *buf, uint32_t len) {
		return crc16_le(crc, buf, len);
	}
#endif

namespace EspNowEz {

#ifdef ESP_NOW_EZ_DEBUG
	#define LOG_DEBUG(...)  \
		ESP_LOGD(TAG, __VA_ARGS__);

	#define LOG_DEBUG_KEY(name, key) \
		const uint8_t* k = key; \
		ESP_LOGD(TAG, "%s=%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x", \
				name, k[0], k[1], k[2], k[3], k[4], k[5], k[6], k[7], k[8], k[9], k[10], k[11], k[12], k[13], k[14], k[15]);
#else
	#define LOG_DEBUG(...)
	#define LOG_DEBUG_KEY(name, key)
#endif

namespace {
	Config* config = nullptr;
	bool is_pair = false;
	std::vector<Peer*> peers;
	OnMessageCallback on_message_callback;

	static void initWifi();
	void send(Payload* payload, uint8_t size, Peer* peer = nullptr);
	void loadPeers();
	void persistPeer(const uint8_t* mac, const uint8_t* lmk);
	void onReceive(const uint8_t *mac, const uint8_t *data, int len);
	void onSent(const uint8_t* mac_addr, esp_now_send_status_t status);
	bool checkCrc(const Payload* payload, uint8_t size);
	bool checkConfig(Peer* peer, const ConfigPayload* config);
	bool checkSeq(Peer* peer, const Payload* payload);
	bool isBroadcastMac(const uint8_t* mac);
	uint16_t calcCrc(const uint8_t* data, uint8_t size, uint8_t pad_bytes = 0);
}

void init(Config* config) {
	EspNowEz::config = config;
	
	initWifi();
	ESP_ERROR_CHECK(esp_now_init());

	#if ESP_IDF_VERSION >= ESP_IDF_VERSION_VAL(4, 4, 0)
		ESP_ERROR_CHECK(esp_now_register_recv_cb([](const esp_now_recv_info_t *recv_info, const uint8_t *data, int len) {
			onReceive(recv_info->src_addr, data, len);
		}));
	#else
		ESP_ERROR_CHECK(esp_now_register_recv_cb([](const uint8_t* mac, const uint8_t *data, int len) {
			onReceive(mac, data, len);
		}));
	#endif
	ESP_ERROR_CHECK(esp_now_register_send_cb([](const uint8_t *mac_addr, esp_now_send_status_t status) {
		onSent(mac_addr, status);
	}));

	// Add broadcast "peer"
	addPeer(BROADCAST_MAC);

	// Set pairwise master key
	if (config->pmk != nullptr) {
		LOG_DEBUG_KEY("pmk", config->pmk);
		ESP_ERROR_CHECK(esp_now_set_pmk(config->pmk));
	}

	loadPeers();

	ESP_LOGI(TAG, "Initialized");
}

void startPair(uint16_t time_ms) {
	if (is_pair) return;

	ESP_LOGI(TAG, "Start pair");

	// Generate keys
	if (config->ecdh == nullptr) {
		config->ecdh = new Ecdh;
		config->ecdh->generateKeypair();
		LOG_DEBUG("generated keys");
	}

	is_pair = true;
	if (!config->is_server) {
		sendDiscovery();
	}

	if (time_ms == 0) return;

	vTaskDelay(time_ms / portTICK_PERIOD_MS);
	stopPair();
}

void stopPair() {
	if (!is_pair) return;
	
	ESP_LOGI(TAG, "Stop pair");
	is_pair = false;
}

void sendMessage(const uint8_t* data, uint8_t size, Peer* peer) {
	auto payload = DataPayload{};
	memcpy(payload.data, data, size);
	send(&payload, ESP_NOW_EZ_HEADER_SIZE + size, peer);
}

void sendMessage(const char* text, Peer* peer) {
	sendMessage((uint8_t*) text, strlen(text) + 1, peer);
}

void sendDiscovery(Peer* peer) {
	ESP_LOGI(TAG, "Send discovery");
	if (config->name == nullptr) {
		config->name = new char[sizeof(DiscoveryPayload::name)];
		uint8_t m[6];
		ESP_ERROR_CHECK(esp_base_mac_addr_get(m));
		snprintf(config->name, sizeof(DiscoveryPayload::name), 
			"%02x%02x%02x%02x%02x%02x", m[0], m[1], m[2], m[3], m[4], m[5]);
	}

	DiscoveryPayload discovery;
	std::strncpy(discovery.name, config->name, sizeof(discovery.name));
	discovery.name[sizeof(discovery.name) - 1] = '\0';
	std::memcpy(discovery.key, config->ecdh->public_key, ECDH_KEY_SIZE);

	send(&discovery, sizeof(DiscoveryPayload), peer);
}

void sendConfig(Peer* peer, uint32_t old_seq) {
	LOG_DEBUG("send config");

	ConfigPayload payload;
	payload.old_seq = old_seq;
	payload.new_seq = peer->recv_seq;

	send(&payload, sizeof(ConfigPayload), peer);
}

void onMessage(OnMessageCallback callback) {
	on_message_callback = callback;
}

std::vector<Peer*> getPeers() {
	return peers;
}

Peer* findPeer(const uint8_t* mac) {
	for(auto it = peers.begin(); it != peers.end(); ++it) {
		if (memcmp(mac, (*it)->mac, ESP_NOW_ETH_ALEN) != 0)
			continue;
		if (it != peers.begin()) {
			std::rotate(peers.begin(), it, peers.end()); // move to front
		}
		return *peers.begin();
	}
	return nullptr;
}

Peer* addPeer(const uint8_t* mac, const uint8_t* lmk) {
	ESP_LOGI(TAG, "Add peer: %02x:%02x:%02x:%02x:%02x:%02x",	mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	esp_now_peer_info_t peer_info;
	memset(&peer_info, 0, sizeof(esp_now_peer_info_t));
	peer_info.ifidx = WIFI_IF_STA;
	peer_info.channel = config->channel;
	std::memcpy(peer_info.peer_addr, mac, ESP_NOW_ETH_ALEN);
	peer_info.encrypt = lmk != nullptr;
	if (lmk != nullptr) {
		std::memcpy(peer_info.lmk, lmk, sizeof(ESP_NOW_KEY_LEN));
		LOG_DEBUG_KEY("lmk", lmk);
	}

	ESP_ERROR_CHECK(esp_now_add_peer(&peer_info));

	if (!isBroadcastMac(peer_info.peer_addr)) {
		Peer* peer = new Peer(peer_info);
		peers.push_back(peer);
		return peer;
	}
	return nullptr;
}

void modifyPeer(const uint8_t* mac, const uint8_t* lmk) {
	LOG_DEBUG("Modify peer: %02x:%02x:%02x:%02x:%02x:%02x",	mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

	esp_now_peer_info_t peer;
	memset(&peer, 0, sizeof(esp_now_peer_info_t));
	ESP_ERROR_CHECK(esp_now_get_peer(mac, &peer));
	peer.encrypt = lmk != nullptr;
	if (lmk != nullptr) {
		std::memcpy(peer.lmk, lmk, sizeof(ESP_NOW_KEY_LEN));
		LOG_DEBUG_KEY("lmk", lmk);
	}
	ESP_ERROR_CHECK(esp_now_mod_peer(&peer));
}

bool removePeer(const uint8_t* mac) {
	ESP_LOGI(TAG, "Remove peer: %02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

	for(auto it = peers.begin(); it != peers.end(); ++it) {
		if (memcmp(mac, (*it)->mac, ESP_NOW_ETH_ALEN) != 0)
			continue;
		peers.erase(it);
		ESP_ERROR_CHECK(esp_now_del_peer(mac));

		nvs_handle_t nvs;
		ESP_ERROR_CHECK(nvs_open(NVS_NAMESPACE, NVS_READWRITE, &nvs));
		char mac_string[ESP_NOW_ETH_ALEN * 2 + 1];
		snprintf(mac_string, sizeof(mac_string), "%02x%02x%02x%02x%02x%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
		nvs_erase_key(nvs, mac_string);
		ESP_ERROR_CHECK(nvs_commit(nvs));
		return true;
	}

	ESP_LOGE(TAG, "Peer not found");
	return false;
}

void deinit() {
	ESP_ERROR_CHECK(esp_now_deinit());
	for(Peer* peer : peers) {
		delete peer;
	}
	peers.clear();
}

Config::~Config() {
	delete name;
	delete pmk;
	delete ecdh;
}

Peer::Peer(esp_now_peer_info peer_info) {
	memcpy(mac, peer_info.peer_addr, sizeof(Peer::mac));
	send_seq = esp_random();
	recv_seq = esp_random();
}

namespace {
void initWifi() {
	wifi_mode_t mode;
	if (esp_wifi_get_mode(&mode) == ESP_ERR_WIFI_NOT_INIT) {
		// Without this, base mac is read multiple times from nvs (saves 30ms)
		uint8_t mac[6];
		esp_err_t result = esp_base_mac_addr_get(mac);
		if (result == ESP_ERR_INVALID_MAC) {
			ESP_ERROR_CHECK(esp_efuse_mac_get_default(mac));
			esp_base_mac_addr_set(mac); 
		}

		ESP_ERROR_CHECK(nvs_flash_init());
		ESP_ERROR_CHECK(esp_netif_init());

		result = esp_event_loop_create_default();
		if (result != ESP_OK && result != ESP_ERR_INVALID_STATE ) { // ESP_ERR_INVALID_STATE if loop already created
			ESP_ERROR_CHECK(result);
		}

		wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
		cfg.nvs_enable = 0;
		ESP_ERROR_CHECK(esp_wifi_init(&cfg) );
		ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
		ESP_ERROR_CHECK(esp_wifi_start());

		#ifdef CONFIG_IDF_TARGET_ESP8266
			ESP_ERROR_CHECK(esp_wifi_set_protocol(WIFI_IF_STA, WIFI_PROTOCOL_11B|WIFI_PROTOCOL_11G|WIFI_PROTOCOL_11N));
		#else
			// Enable long range
			ESP_ERROR_CHECK(esp_wifi_set_protocol(WIFI_IF_STA, WIFI_PROTOCOL_11B|WIFI_PROTOCOL_11G|WIFI_PROTOCOL_11N|WIFI_PROTOCOL_LR));
		#endif
	}

	uint8_t primary_channel;
	wifi_second_chan_t secondary_channel;
	ESP_ERROR_CHECK(esp_wifi_get_channel(&primary_channel, &secondary_channel));
	if (primary_channel != config->channel) {
		LOG_DEBUG("switching channel %u -> %u", primary_channel, config->channel);
		ESP_ERROR_CHECK(esp_wifi_set_channel(config->channel, WIFI_SECOND_CHAN_NONE));
	}
}

void send(Payload* payload, uint8_t size, Peer* peer) {
	bool is_broadcast = peer == nullptr;
	const uint8_t* mac;
	if (is_broadcast) {
		mac = BROADCAST_MAC;
	}

	LOG_DEBUG("send %uB to %02x:%02x:%02x:%02x:%02x:%02x", size, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

	if (!is_broadcast) {
		payload->seq = ++peer->send_seq;
		LOG_DEBUG("seq=%08" PRIx32, payload->seq);
	}

	payload->crc = calcCrc((uint8_t*) payload, size);
	LOG_DEBUG("crc=%04x", payload->crc);

	ESP_ERROR_CHECK(esp_now_send(mac, (uint8_t*) payload, size));
}

void loadPeers() {
	LOG_DEBUG("load peers");

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

		addPeer(mac, lmk);
		res = nvs_entry_next(&it);
	}
	nvs_release_iterator(it);
}

void persistPeer(const uint8_t* mac, const uint8_t* lmk) {
	LOG_DEBUG("persist peer");
	
	nvs_handle_t nvs;
	ESP_ERROR_CHECK(nvs_open(NVS_NAMESPACE, NVS_READWRITE, &nvs));

	char mac_string[ESP_NOW_ETH_ALEN * 2 + 1];
	snprintf(mac_string, sizeof(mac_string), "%02x%02x%02x%02x%02x%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

	ESP_ERROR_CHECK(nvs_set_blob(nvs, mac_string, lmk, ESP_NOW_KEY_LEN));
	ESP_ERROR_CHECK(nvs_commit(nvs));
}

void onReceive(const uint8_t *mac, const uint8_t *data, int len) {
	LOG_DEBUG("received %dB from %02x:%02x:%02x:%02x:%02x:%02x", len, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

	const Payload* payload = reinterpret_cast<const Payload*>(data);
	if (!checkCrc(payload, len)) return;

	if (payload->type == Payload::Type::DISCOVERY) {
		if (!is_pair) return;

		const DiscoveryPayload* discovery = reinterpret_cast<const DiscoveryPayload*>(payload);
		if (len != sizeof(DiscoveryPayload)) {
			ESP_LOGE(TAG, "Payload size NOK. type: %u, %d<>%u", payload->type, len, sizeof(DiscoveryPayload));
			return;
		}

		ESP_LOGI(TAG, "Discovery received: %s", discovery->name);

		uint8_t shared_secret[ECDH_SHARED_SECRET_SIZE];
		if (!config->ecdh->generateSharedSecret(discovery->key, shared_secret)) return;

		if (config->is_server) {
			Peer* peer = addPeer(mac);
			sendDiscovery(peer);
			modifyPeer(mac, shared_secret);
		} else {
			addPeer(mac, shared_secret);
		}
		persistPeer(mac, shared_secret);
		stopPair();
		return;
	}

	Peer* peer = findPeer(mac);
	if (!peer) {
		LOG_DEBUG("peer not found");
		return;
	}

	if (payload->type == Payload::Type::CONFIG) {
		const ConfigPayload* config = reinterpret_cast<const ConfigPayload*>(payload);
		if (!checkConfig(peer, config)) return;
	}

	if (!checkSeq(peer, payload)) {
		sendConfig(peer, payload->seq);
		return;
	}

	if (payload->type == Payload::Type::DATA) {
		const DataPayload* data = reinterpret_cast<const DataPayload*>(payload);
		if (on_message_callback) on_message_callback(data->data, len - ESP_NOW_EZ_HEADER_SIZE);
	}
}

void onSent(const uint8_t *mac_addr, esp_now_send_status_t status) {
	LOG_DEBUG("Delivery status: %s", status == ESP_NOW_SEND_SUCCESS ? "OK" : "NOK");
}

bool checkCrc(const Payload* payload, uint8_t size) {
	uint8_t crc_size = sizeof(Payload::crc);
	if (size <= crc_size) return false;

	uint16_t crc = calcCrc(((uint8_t*)payload) + crc_size, size - crc_size, crc_size);
	if (payload->crc != crc) {
		LOG_DEBUG("crc NOK: %04x<>%04x", payload->crc, crc);
		return false;
	}

	LOG_DEBUG("crc OK: %04x", payload->crc);
	return true;
}

bool checkConfig(Peer* peer, const ConfigPayload* config) {
	if (config->old_seq != peer->send_seq) {
		LOG_DEBUG("config old_seq NOK: %08" PRIx32 "<>%08" PRIx32, config->old_seq, peer->send_seq);
		return false;
	}
	LOG_DEBUG("config OK");
	if (config->new_seq != peer->send_seq) {
		peer->send_seq = config->new_seq;
		LOG_DEBUG("seq=%08" PRIx32, peer->send_seq);
	}
	return true;
}

bool checkSeq(Peer* peer, const Payload* payload) {
	if (payload->seq != (peer->recv_seq + 1)) {
		LOG_DEBUG("seq NOK: %08" PRIx32 "<>%08" PRIx32, payload->seq, (peer->recv_seq + 1));
		return false;
	}
	peer->recv_seq++;
	LOG_DEBUG("seq OK: %08" PRIx32, payload->seq);
	return true;
}

bool isBroadcastMac(const uint8_t* mac) {
	return memcmp(mac, BROADCAST_MAC, ESP_NOW_ETH_ALEN) == 0;
}

uint16_t calcCrc(const uint8_t* data, uint8_t size, uint8_t pad_bytes) {
	uint16_t crc;
	if (pad_bytes) {
		uint8_t padding[pad_bytes];
		memset(padding, 0, pad_bytes);
		crc = esp_crc16_le(0, padding, pad_bytes);
		crc = esp_crc16_le(crc, data, size);
	} else {
		crc = esp_crc16_le(0, data, size);
	}
	return crc;
}
}
}
