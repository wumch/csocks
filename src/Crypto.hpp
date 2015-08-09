
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

    CryptoPP::CFB_Mode<CryptoPP::AES>::Encryption encor;
    CryptoPP::CFB_Mode<CryptoPP::AES>::Decryption decor;

public:
    Crypto()
    {}

    void encrypt(const Buffer& in, Buffer& out)
    {
    	encrypt(in.data, in.filled, out.data);
    }

    void encrypt(const char* in, std::size_t len, Buffer& out)
    {
    	encrypt(in, len, out.data);
    }

    void encrypt(const char* in, std::size_t len, char* out)
    {
    	encor.ProcessData(reinterpret_cast<byte*>(out),
			reinterpret_cast<byte*>(in), len);
    }

    void decrypt(const Buffer& in, Buffer& out)
    {
    	decrypt(in.data, in.filled, out.data);
    }

    void decrypt(const char* in, std::size_t len, Buffer& out)
    {
    	decrypt(in, len, out.data);
    }

    void decrypt(const char* in, std::size_t len, char* out)
    {
    	decor.ProcessData(reinterpret_cast<byte*>(out),
			reinterpret_cast<byte*>(in), len);
    }

    void setEncKeyWithIv(const char* _key, std::size_t keyLen, const char* _iv, std::size_t ivLen)
    {
    	encor.SetKeyWithIV(reinterpret_cast<const byte*>(_key), keyLen,
    			reinterpret_cast<const byte*>(_iv), ivLen);
    }

    void setDecKeyWithIv(const char* _key, std::size_t keyLen, const char* _iv, std::size_t ivLen)
    {
    	decor.SetKeyWithIV(reinterpret_cast<const byte*>(_key), keyLen,
    			reinterpret_cast<const byte*>(_iv), ivLen);
    }
};

}
