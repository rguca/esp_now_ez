template<typename T>
void EspNowEz::sendMessage(const T* payload, const uint8_t* mac) {
   uint8_t size;
   if constexpr (std::is_same_v<T, char>) {
      size = strlen(payload) + 1 - ESP_NOW_EZ_HEADER_SIZE;
   } else {
      size = sizeof(T);
   }
   if constexpr (std::is_base_of_v<Payload, T>) {
      ((Payload*)payload)->crc = this->calcCrc((uint8_t*) payload, size);
   }
   this->sendMessage((uint8_t*) payload, size, mac);
};
