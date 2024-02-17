#ifndef TICKET_H
#define TICKET_H

#include <cstdint>

#define UUID_SIZE 16
#define IV_SIZE  16
#define AES_KEY_LEN 32
#define ENC_AES_SIZE 48
#define TIMESTAMP_SIZE  8
#define VERSION_SIZE  1
#define ENC_AES_LEN  32
#define ENC_TIMESTAMP_SIZE  16


class Ticket {
public:
    uint8_t version;
    uint8_t clientUUID[UUID_SIZE];
    uint8_t serverUUID[UUID_SIZE];
    uint64_t creationTime;
    uint8_t ticketIV[IV_SIZE];
    uint8_t aesKey[ENC_AES_SIZE];
    uint64_t expirationTime;

    Ticket();  // Constructor
    ~Ticket(); // Destructor

    void parseFromBuffer(const char* buffer, size_t& offset);
};

#endif // TICKET_H