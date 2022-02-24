#include "AES.h"

void AES::KeyExpansion(uint8_t Key[16]) {
    for (int i = 0; i < 16; i++) {
        ExpandedRoundKey[0][i] = i + 1;
    }
    
    for (int i = 0; i < 16; i++) {
        AESKey[i] = Key[i];
    }
    
    uint8_t Rotword[4];
    uint8_t Subword[4];
    //rot word
    for (int i = 12; i < 16; i++) {
        Rotword[i - 12] = AESKey[i];
    }
    //rotate rotword
    uint8_t temp = Rotword[0];
    Rotword[0] = Rotword[1];
    Rotword[1] = Rotword[2];
    Rotword[2] = Rotword[3];
    Rotword[3] = temp;

    //Byte substitution
    Subword[0] = SBoxCalculator(Rotword[0]);
    Subword[1] = SBoxCalculator(Rotword[1]);
    Subword[2] = SBoxCalculator(Rotword[2]);
    Subword[3] = SBoxCalculator(Rotword[3]);

    //XOR Rcon with Subword
    Subword[0] ^= R_Con[ExpansionkeyCounter++];
    //Generate subkey
    int j{};
    uint8_t tem[4];
    while (j < 16) {
        for (int i = 0; i < 4; i++) {
            AESKey[j] ^= Subword[i];
            tem[i] = AESKey[j];
            Subkey[j] = AESKey[j];
            Subword[i] = AESKey[j];
            AESKey[j] = tem[i];
            j++;
        }
    }

    //Generate Roundkey
    while (ExpansionkeyCounter < 11) {
        for (int i = 0; i < 16; i++) {
            ExpandedRoundKey[ExpansionkeyCounter][i] = Subkey[i];
        }
        KeyExpansion(Subkey);
    }
}

void AES::MessageBlock(uint8_t Message[16]) {
    for (int i = 0; i < 16; i++) {
        Chunks[i] = Message[i];
    }

    //Perform Key Whitening
    for (int i = 0; i < 16; i++) {
        Chunks[i] ^= ExpandedRoundKey[0][i];
    }

    AESEncryption(Chunks);
}

void AES::AESEncryption(uint8_t Message[16]) {
    while (RoundKeyCounter < 10) {
        //Byte Substitution
        for (int i = 0; i < 16; i++) {
            Chunks[i] = SBoxCalculator(Message[i]);
        }

        //ShiftRow
        uint8_t temp[16]{};

        temp[0] = Chunks[0];
        temp[1] = Chunks[5];
        temp[2] = Chunks[10];
        temp[3] = Chunks[15];

        temp[4] = Chunks[4];
        temp[5] = Chunks[9];
        temp[6] = Chunks[14];
        temp[7] = Chunks[3];

        temp[8] = Chunks[8];
        temp[9] = Chunks[13];
        temp[10] = Chunks[2];
        temp[11] = Chunks[7];

        temp[12] = Chunks[12];
        temp[13] = Chunks[1];
        temp[14] = Chunks[6];
        temp[15] = Chunks[11];

        for (int i = 0; i < 16; i++) {
            Chunks[i] = temp[i];
        }

        //Mixcolumn
        temp[0] = Multiple(2, Chunks[0]) ^ Multiple(3, Chunks[1]) ^ Chunks[2] ^ Chunks[3];
        temp[1] = Chunks[0] ^ Multiple(2, Chunks[1]) ^ Multiple(3, Chunks[2]) ^ Chunks[3];
        temp[2] = Chunks[0] ^ Chunks[1] ^ Multiple(2, Chunks[2]) ^ Multiple(3, Chunks[3]);
        temp[3] = Multiple(3, Chunks[0]) ^ Chunks[1] ^ Chunks[2] ^ Multiple(2, Chunks[3]);

        temp[4] = Multiple(2, Chunks[4]) ^ Multiple(3, Chunks[5]) ^ Chunks[6] ^ Chunks[7];
        temp[5] = Chunks[4] ^ Multiple(2, Chunks[5]) ^ Multiple(3, Chunks[6]) ^ Chunks[7];
        temp[6] = Chunks[4] ^ Chunks[5] ^ Multiple(2, Chunks[6]) ^ Multiple(3, Chunks[7]);
        temp[7] = Multiple(3, Chunks[4]) ^ Chunks[5] ^ Chunks[6] ^ Multiple(2, Chunks[7]);

        temp[8] = Multiple(2, Chunks[8]) ^ Multiple(3, Chunks[9]) ^ Chunks[10] ^ Chunks[11];
        temp[9] = Chunks[8] ^ Multiple(2, Chunks[9]) ^ Multiple(3, Chunks[10]) ^ Chunks[11];
        temp[10] = Chunks[8] ^ Chunks[9] ^ Multiple(2, Chunks[10]) ^ Multiple(3, Chunks[11]);
        temp[11] = Multiple(3, Chunks[8]) ^ Chunks[9] ^ Chunks[10] ^ Multiple(2, Chunks[11]);

        temp[12] = Multiple(2, Chunks[12]) ^ Multiple(3, Chunks[13]) ^ Chunks[14] ^ Chunks[15];
        temp[13] = Chunks[12] ^ Multiple(2, Chunks[13]) ^ Multiple(3, Chunks[14]) ^ Chunks[15];
        temp[14] = Chunks[12] ^ Chunks[13] ^ Multiple(2, Chunks[14]) ^ Multiple(3, Chunks[15]);
        temp[15] = Multiple(3, Chunks[12]) ^ Chunks[13] ^ Chunks[14] ^ Multiple(2, Chunks[15]);

        for (int i = 0; i < 16; i++) {
            Chunks[i] = temp[i];
        }

        //Keyaddition layer
        for (int j = 0; j < 16; j++) {
            Chunks[j] ^= ExpandedRoundKey[RoundKeyCounter][j];
        }

        RoundKeyCounter++;
    }
    //reset Round key counter
    RoundKeyCounter = 1;
    //Final round
    // 
    //Byte Substitution
    for (int i = 0; i < 16; i++) {
        Chunks[i] = SBoxCalculator(Message[i]);
    }

    //ShiftRow
    uint8_t temp[16]{};

    temp[0] = Chunks[0];
    temp[1] = Chunks[5];
    temp[2] = Chunks[10];
    temp[3] = Chunks[15];

    temp[4] = Chunks[4];
    temp[5] = Chunks[9];
    temp[6] = Chunks[14];
    temp[7] = Chunks[3];

    temp[8] = Chunks[8];
    temp[9] = Chunks[13];
    temp[10] = Chunks[2];
    temp[11] = Chunks[7];

    temp[12] = Chunks[12];
    temp[13] = Chunks[1];
    temp[14] = Chunks[6];
    temp[15] = Chunks[11];

    for (int i = 0; i < 16; i++) {
        Chunks[i] = temp[i];
    }

    //AddRound
    for (int j = 0; j < 16; j++) {
        Chunks[j] ^= ExpandedRoundKey[10][j];
    }
    for (int i = 0; i < 16; i++) {
        std::cout << std::nouppercase << std::showbase << std::hex << (int)Chunks[i] << " ";
    }
}

uint8_t AES::SBoxCalculator(uint8_t value) {
    uint8_t val = MulInverse(value);
    uint8_t OutS{};
    uint8_t temp[8]{};
    std::bitset<8> inv{ val };
    std::bitset<8> bites[8]{};
    std::bitset<8> bits{};
    std::bitset<8> mul{ "01100011" };
    for (int i = 0; i < 8; i++) {
        std::bitset<8> mat = Mverse[i];
        bites[i] = mat & inv;
    }
    for (int i = 0; i < 8; i++) {
        bits[i] = bites[i][0] ^ bites[i][1] ^ bites[i][2] ^ bites[i][3] ^ bites[i][4] ^ bites[i][5] ^ bites[i][6] ^ bites[i][7] ^ mul[i];
    }
    uint8_t SBoxValue = bits.to_ulong();

    return SBoxValue;
}

uint8_t AES::MulInverse(uint8_t value) {
    if (value == 0) {
        return 0;
    }

    uint16_t mod = PolyMod;
    uint8_t val{ value }, Inverse = 1, Q1{ 1 }, Q{ 0 }, C1{ 0 }, C2{ 0 };
    std::bitset<9> modulo = mod;
    std::bitset<9> valu = val;
    std::bitset<8> C2temp = C2;
    long modtemp{};

    while (val > 1) {
        std::bitset<8> C1bit = C1;
        std::bitset<8> C2bit = C2;
        std::bitset<8> inversebit = Inverse;
        modtemp = modulo.to_ulong();
        uint8_t k = Bitsize(modtemp);

        while (valu[k] != modulo[k]) {
            valu <<= 1;
            Q1 *= 2;
        }
        modulo ^= valu;
        modtemp = modulo.to_ulong();
        valu = val;
        Q += Q1;
        Q1 = 1;
        
        uint8_t a = Bitsize(modtemp), b = Bitsize(val);
        if (modtemp < val && a < b) {
            std::bitset<8> Qbits = Q;
            uint8_t bitlength = Bitsize(Q);
            for (int i = bitlength; i >= 0; i--) {
                if (Qbits[i] == 0b1) {
                    C1bit = inversebit << bitlength;
                    C2bit ^= C1bit;
                    bitlength -= 1;
                }
                else {
                    bitlength -= 1;
                }
            }
            modulo = val;
            valu = val = modtemp;
            Q = 0;
            C2bit ^= C2temp;
            C2temp = Inverse;

            Inverse = C2bit.to_ulong();
        }
    }
    return Inverse;
}

uint8_t AES::Multiple(uint8_t multiple, uint8_t value) {
    if (value == 0) {
        return 0;
    }
    std::bitset<8> val = value;
    std::bitset<8> multiplier = multiple;
    std::bitset<15> Temp[8]{};
    std::bitset<15> Mul{};

    for (int j = 0; j < multiplier.size(); j++) {
        for (int k = 0; k < val.size(); k++) {
            Mul[k] = multiplier[j] & val[k];
        }
        Temp[j] = Mul;
    }
    Temp[1] <<= 1;
    Temp[2] <<= 2;
    Temp[3] <<= 3;
    Temp[4] <<= 4;
    Temp[5] <<= 5;
    Temp[6] <<= 6;
    Temp[7] <<= 7;

    Temp[0] ^= Temp[1] ^ Temp[2] ^ Temp[3] ^ Temp[4] ^ Temp[5] ^ Temp[6] ^ Temp[7];

    uint16_t mulvalue = Temp[0].to_ulong();
    if (mulvalue > 255) {
        mulvalue ^= PolyMod;
    }

    return mulvalue;
}

uint8_t AES::Bitsize(long value) {
    if (value == 0) {
        return 0;
    }

    std::bitset<9> val = value;
    uint8_t i{ 8 };
    while (val[i] != 0b1) {
        i--;
    }

    return i;
}

void AES::BuildTable() {
    //Other way to calculate inverse is to use
    //Exponential and logarithm table lookup
    //Generator is 0x03
    std::bitset<8> Generator = 0x03;
    std::bitset<8> Exponential = 0x03;
    std::bitset<15> Temp[8]{};
    std::bitset<15> arr;

    //Fill exponential and logarithm table table
    Antilog[0] = 0x01;
    Antilog[1] = 0x03;
    Log[0] = 0;
    Log[1] = 0;
    Log[3] = 1;
    for (int i = 2; i < 256; i++) {
        for (int j = 0; j < Generator.size(); j++) {
            for (int k = 0; k < Exponential.size(); k++) {
                arr[k] = Exponential[k] & Generator[j];
            }
            Temp[j] = arr;
        }
        Temp[1] <<= 1;
        Temp[2] <<= 2;
        Temp[3] <<= 3;
        Temp[4] <<= 4;
        Temp[5] <<= 5;
        Temp[6] <<= 6;
        Temp[7] <<= 7;

        Temp[0] ^= Temp[1] ^ Temp[2] ^ Temp[3] ^ Temp[4] ^ Temp[5] ^ Temp[6] ^ Temp[7];

        long exp = Temp[0].to_ulong();

        while (exp > 255) {
            exp = exp ^ PolyMod;
        }
        Antilog[i] = exp;
        Log[exp] = i;

        Exponential = exp;
    }
}

int AES::GCD(int mod, int value) {
    if (value == 0) 
    return mod;
    return GCD(value, mod % value);
}

int AES::Power(int x, int y, int mod) {
    if (y == 0)
        return 1;
    int p = Power(x, y / 2, mod) % mod;
    p = (p * p) % mod;

    return (y % 2 == 0) ? p : (x * p) % mod;
}

