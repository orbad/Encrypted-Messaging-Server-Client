#include "Ticket.h"
#include <cstring>

Ticket::Ticket() {
    // Initialize members to default values
    std::memset(clientUUID, 0, UUID_SIZE);
    std::memset(serverUUID, 0, UUID_SIZE);
    creationTime = 0;
    std::memset(ticketIV, 0, IV_SIZE);
    std::memset(aesKey, 0, AES_KEY_LEN);
    expirationTime = 0;
    version = 0;
}

Ticket::~Ticket() {
    // Cleanup resources if necessary (not needed for this basic example)
}

void Ticket::parseFromBuffer(const char* buffer, size_t& offset) {

    std::memcpy(&version, buffer + offset, VERSION_SIZE);
    offset += VERSION_SIZE;

    std::memcpy(clientUUID, buffer + offset, UUID_SIZE);
    offset += UUID_SIZE;

    std::memcpy(serverUUID, buffer + offset, UUID_SIZE);
    offset += UUID_SIZE;

    std::memcpy(&creationTime, buffer + offset, TIMESTAMP_SIZE);
    offset += TIMESTAMP_SIZE;

    std::memcpy(ticketIV, buffer + offset, IV_SIZE);
    offset += IV_SIZE;

    std::memcpy(aesKey, buffer + offset, ENC_AES_SIZE);
    offset += ENC_AES_SIZE;

    std::memcpy(&expirationTime, buffer + offset, ENC_TIMESTAMP_SIZE);
    offset += ENC_TIMESTAMP_SIZE;
}