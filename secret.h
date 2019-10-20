#pragma once
#include "..\cryptopp820\rsa.h"
#include "..\cryptopp820\cryptlib.h"
#include "osrng.h"

class secret : CryptoPP::RSA 
{
public:
	secret(CryptoPP::InvertibleRSAFunction params, std::string password);

	RSA::PrivateKey getPrivate();
	RSA::PublicKey getPublic();
	std::string getPlain();
	std::string getCipher();
	std::string getSign();
	bool doEncryption(PublicKey publicKey, std::string message);
	bool doDecryption(PrivateKey privateKey, std::string cMessage);
private:
	RSA::PrivateKey privateKey;
	RSA::PublicKey publicKey;
	CryptoPP::AutoSeededRandomPool rng;
	bool doSign(std::string password, PrivateKey privateKey);
	std::string  signature = "";
	std::string recoveredPlain = "";
	std::string newCipher = "";
};