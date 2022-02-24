#include "RSA.h"
#include "EllipticCurve.h"
#include "AES.h"

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
	

	AES aes;
	uint8_t Key[16] = {
		1, 2, 3, 4,
		5, 6, 7, 8,
		9, 10, 11, 12,
		13, 14, 15, 16
	};
	string Message = "Hello Sir. How do you do?";
	aes.KeyExpansion(Key);

	//16 byte message block
	int TotalLength = Message.length();
	while (TotalLength % 16 != 0) {
		Message += '\0';
		TotalLength++;
	}

	int j{}, k{};
	uint8_t MBlock[16]{};
	int RowsRequired = TotalLength / 16;
	for (int i = 0; i < RowsRequired; i++) {
		while (j < 16) {
			MBlock[j++] = Message[k++];
		}
		j = 0;
		aes.MessageBlock(MBlock);
	}
	return 0;
}