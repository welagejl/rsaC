#include "..\cryptopp820\rsa.h"
#include "..\cryptopp820\cryptlib.h"
#include "osrng.h"
#include "secret.h"
secret::secret(CryptoPP::InvertibleRSAFunction params, std::string password)
{
	params.GenerateRandomWithKeySize(rng, 2048);

	RSA::PublicKey pubKey(params);
	publicKey = pubKey;
	RSA::PrivateKey privKey(params);
	privateKey = privKey;
	
	if (!doSign(password, this->getPrivate()))
		std::cout << "sdf";
}
bool secret::doSign(std::string password, RSA::PrivateKey privKey)
{
	CryptoPP::RSASSA_PKCS1v15_SHA_Signer signer(privKey);
	std::string signature;
	CryptoPP::StringSource string(password,true, new CryptoPP::SignerFilter(rng, signer, new CryptoPP::StringSink(signature)));
	this->signature = signature;
	return true;
}
bool secret::doEncryption(PublicKey publicKeys, std::string message)
{
	std::string cipher;
	CryptoPP::RSAES_OAEP_SHA_Encryptor crip(publicKeys);
	CryptoPP::StringSource doCipher(message, true, new CryptoPP::PK_EncryptorFilter(rng, crip, new CryptoPP::StringSink(cipher)));
	newCipher = cipher;
	return true;
}
bool secret::doDecryption(PrivateKey privateKey, std::string cmessage)
{
	std::string plain;
	CryptoPP::RSAES_OAEP_SHA_Decryptor deCrip(privateKey);
	CryptoPP::StringSource deCipher(cmessage, true, new CryptoPP::PK_DecryptorFilter(rng, deCrip, new CryptoPP::StringSink(plain)));
	recoveredPlain = plain;
	return true;
}
CryptoPP::RSA::PrivateKey secret::getPrivate()
{
	return privateKey;
}
CryptoPP::RSA::PublicKey secret::getPublic()
{
	return publicKey;
	
}
std::string secret::getCipher()
{
	return newCipher;
}
std::string secret::getPlain()
{
	return recoveredPlain;
}
std::string secret::getSign()
{
	return signature;
}
int main()
{
	CryptoPP::InvertibleRSAFunction params;
	secret newProc(params, "psssss");
	if(newProc.doEncryption(newProc.getPublic(),"hsdfsdfsdf"))
		std::cout << newProc.getCipher();
	if (newProc.doDecryption(newProc.getPrivate(), newProc.getCipher()))
		std::cout << newProc.getPlain();
	std::cout << newProc.getSign();
}