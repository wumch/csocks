
#pragma once

#include <boost/static_assert.hpp>
#include <crypto++/modes.h>
#include <crypto++/aes.h>
#include <crypto++/filters.h>
#include "Buffer.hpp"

namespace csocks {

class Crypto
{
private:
    BOOST_STATIC_ASSERT(sizeof(byte) == 1);     // 以下不再考虑 sizeof(byte) != 1 的情况。
    byte key[CryptoPP::AES::DEFAULT_KEYLENGTH];
    byte iv[CryptoPP::AES::BLOCKSIZE];

public:
    Crypto()
    {}

    void encrypt(const Buffer& in, Buffer& out)
    {
        CryptoPP::AES::Encryption aesEnc(key, sizeof(key));
        CryptoPP::CFB_Mode_ExternalCipher::Encryption cfbEnc(aesEnc, iv);
        CryptoPP::StreamTransformationFilter streamEncor(cfbEnc, new CryptoPP::ArraySink(reinterpret_cast<byte*>(out.data), out.size));
        streamEncor.Put(reinterpret_cast<byte*>(in.data), in.size);
        streamEncor.MessageEnd();
    }

private:
    void init()
    {
        std::memset(key, 0x01, sizeof(key));
        std::memset(iv, 0x01, sizeof(iv));
    }
};

}
