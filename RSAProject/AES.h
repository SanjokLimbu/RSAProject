#ifndef AES_H
#define AES_H

#include <string>
#include <vector>
#include <iostream>
#include <array>
#include <bitset>

using std::string;

class AES
{
private:
    uint8_t AESKey[16]{};
    uint8_t Antilog[256]{}, Log[256]{};
    uint8_t Mverse[8]{
        0xF1, 0xE3, 0xC7, 0x8F, 0x1F, 0x3E, 0x7C, 0xF8
    };
    uint8_t Dverse[8]{
        0xA4, 0x49, 0x92, 0x25, 0x4A, 0x94, 0x29, 0x52
    };
    uint16_t PolyMod{0x11B};
	const uint8_t R_Con[10]{ 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };
    int ExpansionkeyCounter{0}, RoundKeyCounter{};
    uint8_t Subkey[16]{}, ExpandedRoundKey[11][16]{}, Chunks[16]{}, DecryptionChunks[16]{};

public:
	void KeyExpansion(uint8_t Key[16]);
    uint8_t* MessageBlock(uint8_t Message[16]);
    uint8_t* AESEncryption(uint8_t Message[16]);
    uint8_t Multiplier(uint8_t multiple, uint8_t value);
    uint8_t Multiple(uint8_t multiple,uint8_t value);
    uint8_t SBoxCalculator(uint8_t value);
    uint8_t MulInverse(uint8_t value);
    void BuildTable();
    int GCD(int mod, int value);
    int Power(int x, int y, int m);
    uint8_t Bitsize(long value);
    void AESDecryption(uint8_t Message[16]);
    uint8_t InverseSBox(uint8_t value);
};

#endif // !AES_H