#include "RSA.h"
#include "EllipticCurve.h"
#include "AES.h"
#include "SHA3.h"
#include <cstdlib>
#include <ctime>

int main() {

	//This is for RSA

	//string message{};
	//std::cout << "Enter message" << std::endl;
	//std::getline(std::cin, message);

	////Generate private key
	//KeyGeneration key;
	//key.ConvertASCII(message);
	//key.CalculatePhi();
	//key.CalculateKey();

	////Message to encrypt, decrypt, digital signature and verify
	//std::cout << "Enter message" << std::endl;
	//std::getline(std::cin, message);
	//key.EncryptMessage(message);
	//key.DecryptMessage();
	//key.RSAHash(message);

	//This is for ECC

	//Pass Generator point
	/*int GenNumbersA, GenNumbersB;

	std::cout << "First Generator point" << std::endl;
	std::cin >> GenNumbersA;
	std::cout << "Second Generator point" << std::endl;
	std::cin >> GenNumbersB;

	EllipticCurve ECC;
	ECC.Generator(GenNumbersA, GenNumbersB);
	ECC.GeneratePublicKey();*/
	

	//AES aes;
	//aes.InverseSBox(0xc7);
	//aes.Multiplier(14, 0x77);
	//uint8_t Key[16] = {
	//	1, 2, 3, 4,
	//	5, 6, 7, 8,
	//	9, 10, 11, 12,
	//	13, 14, 15, 16
	//};
	//string Message = "Hello Sir. How do you do?";
	//aes.KeyExpansion(Key);

	////16 byte message block
	//int TotalLength = Message.length();
	//while (TotalLength % 16 != 0) {
	//	Message += '\0';
	//	TotalLength++;
	//}

	//int j{}, k{};
	//uint8_t MBlock[16]{};
	//int RowsRequired = TotalLength / 16;
	//uint8_t* block;
	//std::vector<uint8_t*> EncryptedBlock(RowsRequired);
	//for (int i = 0; i < RowsRequired; i++) {
	//	while (j < 16) {
	//		MBlock[j++] = Message[k++];
	//	}
	//	j = 0;
	//	block = aes.MessageBlock(MBlock);
	//	EncryptedBlock.at(i) = block;
	//}
	//for (int i = 0; i < EncryptedBlock.size(); i++) {
	//	aes.AESDecryption(EncryptedBlock.at(i));
	//}

	//Generate a random key
	//uint8_t AESPrivateKey[16]{}; uint16_t AESKey{}, ECCKey{};
	//std::cout << "Enter your 4 digits AES Key" << std::endl;
	//std::cin >> AESKey;

	//AESPrivateKey[0] = AESKey / 1000;
	//AESPrivateKey[1] = (AESKey / 100) - (AESPrivateKey[0] * 10);
	//AESPrivateKey[2] = (AESKey / 10) - (AESPrivateKey[0] * 100) - (AESPrivateKey[1] * 10);
	//AESPrivateKey[3] = AESKey - (AESPrivateKey[0] * 1000) - (AESPrivateKey[1] * 100) - (AESPrivateKey[2] * 10);

	////RNG
	//srand(time(0));
	//for (int i = 4; i < 16; i++) {
	//	AESPrivateKey[i] = rand();
	//}

	//std::cout << "Enter your 4 digits ECC Key" << std::endl;
	//std::cin >> ECCKey;

	//EllipticCurve ECC;
	//ECC.PrivateKeyGenerator(ECCKey);

	//SHA 256
	string message = "hello world";
	
	SHA3 Sha3;
	Sha3.Preprocessing(message);
	return 0;
}