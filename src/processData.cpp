
#include <cstring>
#include <iostream>
#include <boost/lexical_cast.hpp>
#include <crypto++/modes.h>
#include <crypto++/aes.h>
#include <crypto++/filters.h>
#include "stage/meta.hpp"

int main(int argc, char* argv[])
{
	byte key[CryptoPP::AES::DEFAULT_KEYLENGTH], iv[CryptoPP::AES::BLOCKSIZE];

	std::memcpy(key, "23DE1972B7E7D2EE", 16);
	std::memcpy(iv, "23DE1972B7E7D2EE", 16);

	CryptoPP::CFB_Mode<CryptoPP::AES>::Encryption cfbEnc(key, sizeof(key), iv);

	byte plain[100], cipher[100], deced[100];
	std::memset(plain, 0, 100);
	std::memset(cipher, 0, 100);
	std::memset(deced, 0, 100);

	int pos = 2, len = 0;

	if (argc > 2) {
		len = std::strlen(argv[1]);
		std::memcpy(plain, argv[1], len);
		pos = boost::lexical_cast<int>(argv[2]);
	}

	std::memcpy(plain, "1234567890qwertyuiopasdfghjklzxcvbnm", 36);

	cfbEnc.ProcessData(cipher, plain, 100);

	CryptoPP::CFB_Mode<CryptoPP::AES>::Decryption cfbDec(key, sizeof(key), iv);

	cfbDec.ProcessData(deced, cipher, pos);
	CS_DUMP(deced);

	std::memset(deced, 0, 100);
	cfbDec.ProcessData(deced, cipher + pos, len - pos);
	CS_DUMP(deced);
}
