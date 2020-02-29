#include <cstdio>
#include <iostream>
#include "..\CryptoPP\osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include <iostream>
using namespace std;

#include "..\CryptoPP\filters.h"
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::StreamTransformationFilter;

//В каких режимах мы хотим использовать блочные шифры?
#include "..\CryptoPP\modes.h"
using CryptoPP::CBC_Mode;
using CryptoPP::ECB_Mode;
using CryptoPP::OFB_Mode;
using CryptoPP::CTR_Mode;

//Какие алгоритмы мы хотим использовать?
#include "..\CryptoPP\gost.h"
using CryptoPP::GOST;

/*
CryptoPP::SecByteBlock HexDecodeString(const char *hex)
{
CryptoPP::StringSource ss(hex, true, new CryptoPP::HexDecoder);
CryptoPP::SecByteBlock result((size_t)ss.MaxRetrievable());
ss.Get(result, result.size());
return result;
}*/


int main(int argc, char* argv[]) {

	//HMODULE DLL = LoadLibrary(_T("cryptopp.dll"));
	//
	// Key and IV setup
	//AES encryption uses a secret key of a variable length (128-bit, 196-bit or 256-
	//bit). This key is secretly exchanged between two parties before communication
	//begins. DEFAULT_KEYLENGTH= 16 bytes

	std::string key = "0123456789abcdef";
	std::string iv = "aaaaaaaaaaaaaaaa";
	//string plain = "CBC Mode Test";
	string cipher, encoded, recovered;


	std::string plaintext = "name macmilan age 24 ciy bonn country germany";
	std::string ciphertext;
	std::string decryptedtext;

	std::cout << "Plain Text (" << plaintext.size() << " bytes)" << std::endl;
	std::cout << plaintext;
	std::cout << std::endl << std::endl;
	int a = 5;
	int* b = &a;
	cout << &b << endl;
	cout << *b << endl;

	//+++ ШИФРОВАНИЕ
	CryptoPP::GOST::Encryption gostEncryption((unsigned char*)key.c_str(), CryptoPP::GOST::DEFAULT_KEYLENGTH);
	CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption(gostEncryption, (unsigned char*)iv.c_str());
	CryptoPP::StreamTransformationFilter stfEncryptor(cbcEncryption, new CryptoPP::StringSink(ciphertext));
	stfEncryptor.Put((const unsigned char*)(plaintext.c_str()), plaintext.length() + 1);
	stfEncryptor.MessageEnd();

	
	//--- ШИФОРОВАНИЕ

	cout << "cipher text plain: " << ciphertext << endl;
	std::cout << "Cipher Text (" << ciphertext.size() << " bytes)" << std::endl;
	cout << endl;
	cout << endl;
	

	//+++ ДЕШИФРОВАНИЕ
	CryptoPP::GOST::Decryption gostDecryption((unsigned char*)key.c_str(), CryptoPP::GOST::DEFAULT_KEYLENGTH);
	CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDecryption(gostDecryption, (unsigned char*)iv.c_str());
	CryptoPP::StreamTransformationFilter stfDecryptor(cbcDecryption, new CryptoPP::StringSink(decryptedtext));
	stfDecryptor.Put(reinterpret_cast<const unsigned char*>(ciphertext.c_str()), ciphertext.size());
	stfDecryptor.MessageEnd();

	
	
	//--- ДЕШИФРОВАНИЕ
	std::cout << "Decrypted Text: " << std::endl;
	std::cout << decryptedtext;
	std::cout << std::endl << std::endl;

	system("pause");

	return 0;
}
