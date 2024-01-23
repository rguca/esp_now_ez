#include "payload.h"

Payload::Payload(Type type) { 
   this->type = type;
}

DiscoveryPayload::DiscoveryPayload() : Payload{DISCOVERY} {
}

ConfigPayload::ConfigPayload() : Payload{CONFIG} {
}

DataPayload::DataPayload() : Payload{DATA} {
}
