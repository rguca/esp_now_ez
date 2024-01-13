#include "payload.h"

Payload::Payload(Type type) { 
   this->type = type;
}

DiscoveryPayload::DiscoveryPayload() : Payload{DISCOVERY} {
}

TimePayload::TimePayload() : Payload{TIME} {
}

DataPayload::DataPayload() : Payload{DATA} {
}
