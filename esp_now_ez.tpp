template<typename T>
void EspNowEz::sendMessage(T* data, const uint8_t* mac) {
   if constexpr (std::is_base_of_v<Payload, T>) {
      this->send(data, sizeof(T), mac);
   } else if constexpr (std::is_same_v<T, char> || std::is_same_v<T, const char>) {
      this->sendMessage((uint8_t*) data, strlen(data) + 1, mac);
   } else {
      ESP_LOGE(TAG, "Unsupported message data");
   }
};
