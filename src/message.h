#include <iostream>
#include <vector>
#include <gmssl/sm3.h>
#include <gmssl/sm2.h>
#include <gmssl/sm4.h>
#include <gmssl/ec.h>
#include <gmssl/base64.h>
#include <gmssl/error.h>
#include <gmssl/pem.h>
#include <gmssl/rand.h>
#include <unistd.h>

#include "netio.h"
typedef uint8_t BYTE;
#define BUFSIZE 1024

enum MessageType
{
    client_hello = 0x80,
    server_hello = 0x81,
    server_certificate = 0x82,
    client_certificate = 0x83,
    certificate_verify = 0x84,
    client_key_exchange = 0x85,
    server_finished = 0x86,
    client_finished = 0x87,
    error_message = 0x88,
    application_data = 0x89
};
struct Message
{
    MessageType msg_type;
    size_t length;

    virtual std::vector<uint8_t> serialize() const = 0;
    virtual void deserialize(const std::vector<uint8_t> &data) = 0;
};
int sendmessage(Message &msg);
int receivemessage(Message &msg);

struct ClientHello : Message
{
    BYTE random[32];
    BYTE cipherSuite[2];

    ClientHello()
    {
        msg_type = client_hello;
        length = sizeof(random) + sizeof(cipherSuite) + 1;
    }

    std::vector<uint8_t> serialize() const override
    {
        std::vector<uint8_t> data;
        data.push_back(static_cast<uint8_t>(msg_type));
        data.insert(data.end(), random, random + sizeof(random));
        data.insert(data.end(), cipherSuite, cipherSuite + sizeof(cipherSuite));
        return data;
    }

    void deserialize(const std::vector<uint8_t> &data) override
    {
        msg_type = static_cast<MessageType>(data[0]);
        std::copy(data.begin() + 1, data.begin() + 33, random);
        std::copy(data.begin() + 33, data.end(), cipherSuite);
    }
};

struct ServerHello : Message
{
    BYTE random[32];
    BYTE cipherSuite[2];
    ServerHello()
    {
        msg_type = server_hello;
        length = sizeof(random) + sizeof(cipherSuite) + 1;
    }
    std::vector<uint8_t> serialize() const override
    {
        std::vector<uint8_t> data;
        data.push_back(static_cast<uint8_t>(msg_type));
        data.insert(data.end(), random, random + sizeof(random));
        data.insert(data.end(), cipherSuite, cipherSuite + sizeof(cipherSuite));
        return data;
    }

    void deserialize(const std::vector<uint8_t> &data) override
    {
        msg_type = static_cast<MessageType>(data[0]);
        std::copy(data.begin() + 1, data.begin() + 33, random);
        std::copy(data.begin() + 33, data.end(), cipherSuite);
    }
};

struct ClientCertificate : Message
{
    BYTE certificate[64];
    ClientCertificate()
    {
        msg_type = client_certificate;
        length = sizeof(certificate) + 1;
    }
    std::vector<uint8_t> serialize() const override
    {
        std::vector<uint8_t> data;
        data.push_back(static_cast<uint8_t>(msg_type));
        data.insert(data.end(), certificate, certificate + sizeof(certificate));
        return data;
    }

    void deserialize(const std::vector<uint8_t> &data) override
    {
        msg_type = static_cast<MessageType>(data[0]);
        std::copy(data.begin() + 1, data.begin() + sizeof(certificate) + 1, certificate);
    }
};

struct ServerCertificate : Message
{
    BYTE certificate[64];
    ServerCertificate()
    {
        msg_type = server_hello;
        length = sizeof(certificate) + 1;
    }
    std::vector<uint8_t> serialize() const override
    {
        std::vector<uint8_t> data;
        data.push_back(static_cast<uint8_t>(msg_type));
        data.insert(data.end(), certificate, certificate + sizeof(certificate));
        return data;
    }

    void deserialize(const std::vector<uint8_t> &data) override
    {
        msg_type = static_cast<MessageType>(data[0]);
        std::copy(data.begin() + 1, data.begin() + sizeof(certificate) + 1, certificate);
    }
};

// struct CertificateVerify : Message
// {
//     BYTE signature[64];
//     CertificateVerify()
//     {
//         msg_type = certificate_verify;
//         length = sizeof(signature) + 1;
//     }
//     std::vector<uint8_t> serialize() const override
//     {
//         std::vector<uint8_t> data;
//         data.push_back(static_cast<uint8_t>(msg_type));
//         data.insert(data.end(), signature, signature + sizeof(signature));
//         return data;
//     }

//     void deserialize(const std::vector<uint8_t> &data) override
//     {
//         msg_type = static_cast<MessageType>(data[0]);
//         std::copy(data.begin() + 1, data.begin() + sizeof(signature) + 1, signature);
//     }
// };
struct CertificateVerify : Message
{
    BYTE signature[256];
    size_t len;
    CertificateVerify()
    {
        msg_type = certificate_verify;
        length = sizeof(signature) + 1 + sizeof(len);
    }
    std::vector<uint8_t> serialize() const override
    {
        std::vector<uint8_t> data;
        data.push_back(static_cast<uint8_t>(msg_type));
        data.insert(data.end(), signature, signature + sizeof(signature));
        data.insert(data.end(), (uint8_t *)&len, (uint8_t *)&len + sizeof(len));
        return data;
    }

    void deserialize(const std::vector<uint8_t> &data) override
    {
        msg_type = static_cast<MessageType>(data[0]);
        std::copy(data.begin() + 1, data.begin() + sizeof(signature) + 1, signature);
        std::copy(data.begin() + sizeof(signature) + 1, data.begin() + sizeof(signature) + 1 + sizeof(len), (uint8_t *)&len);
    }
};

struct ClientKeyExchange : Message
{
    BYTE encryptedSharedSecret[256];
    size_t len;
    ClientKeyExchange()
    {
        msg_type = client_key_exchange;
        length = sizeof(encryptedSharedSecret) + 1 + sizeof(len);
    }
    std::vector<uint8_t> serialize() const override
    {
        std::vector<uint8_t> data;
        data.push_back(static_cast<uint8_t>(msg_type));
        data.insert(data.end(), encryptedSharedSecret, encryptedSharedSecret + sizeof(encryptedSharedSecret));
        data.insert(data.end(), (uint8_t *)&len, (uint8_t *)&len + sizeof(len));
        return data;
    }

    void deserialize(const std::vector<uint8_t> &data) override
    {
        msg_type = static_cast<MessageType>(data[0]);
        std::copy(data.begin() + 1, data.begin() + sizeof(encryptedSharedSecret) + 1, encryptedSharedSecret);
        std::copy(data.begin() + sizeof(encryptedSharedSecret) + 1, data.begin() + sizeof(encryptedSharedSecret) + 1 + sizeof(len), (uint8_t *)&len);
    }
};

struct ServerFinished : Message
{
    BYTE message_MAC[32];
    ServerFinished()
    {
        msg_type = server_finished;
        length = sizeof(message_MAC) + 1;
    }
    std::vector<uint8_t> serialize() const override
    {
        std::vector<uint8_t> data;
        data.push_back(static_cast<uint8_t>(msg_type));
        data.insert(data.end(), message_MAC, message_MAC + sizeof(message_MAC));
        return data;
    }

    void deserialize(const std::vector<uint8_t> &data) override
    {
        msg_type = static_cast<MessageType>(data[0]);
        std::copy(data.begin() + 1, data.begin() + sizeof(message_MAC) + 1, message_MAC);
    }
};

struct ClientFinished : Message
{
    BYTE message_MAC[32];
    ClientFinished()
    {
        msg_type = client_finished;
        length = sizeof(message_MAC) + 1;
    }
    std::vector<uint8_t> serialize() const override
    {
        std::vector<uint8_t> data;
        data.push_back(static_cast<uint8_t>(msg_type));
        data.insert(data.end(), message_MAC, message_MAC + sizeof(message_MAC));
        return data;
    }

    void deserialize(const std::vector<uint8_t> &data) override
    {
        msg_type = static_cast<MessageType>(data[0]);
        std::copy(data.begin() + 1, data.begin() + sizeof(message_MAC) + 1, message_MAC);
    }
};
struct AppliacationData : Message
{
    BYTE encryptedData[1024];
    AppliacationData()
    {
        msg_type = application_data;
        length = sizeof(encryptedData) + 1 ;
    }
    std::vector<uint8_t> serialize() const override
    {
        std::vector<uint8_t> data;
        data.push_back(static_cast<uint8_t>(msg_type));
        data.insert(data.end(), encryptedData, encryptedData + sizeof(encryptedData));

        return data;
    }

    void deserialize(const std::vector<uint8_t> &data) override
    {
        msg_type = static_cast<MessageType>(data[0]);
        std::copy(data.begin() + 1, data.begin() + sizeof(encryptedData) + 1, encryptedData);
    }
};