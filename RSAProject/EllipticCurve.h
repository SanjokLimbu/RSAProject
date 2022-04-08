#ifndef ELLIPTICCURVE_H
#define ELLIPTICCURVE_H

#include <vector>
#include <boost/multiprecision/cpp_int.hpp>

using namespace boost::multiprecision;

//The demo elliptic curve is y^2 = x^3 + 2x + 2 mod 17

#define MODULUS 17

class EllipticCurve
{
private:
	cpp_int ECCKey{}; uint32_t ECCPrivateKey{}; unsigned char Key[78];
	int PrivateKey = 13, x3Coordinate{}, y3Coordinate{}, GeneratorPoint[2]{}, x1Coordinate{}, y1Coordinate{}, Slope{}, xGCoordinate{}, yGCoordinate{};
	std::vector<int> CyclicPoints{};
	std::vector<int> BinaryPoints{};
	

public:
	void PrivateKeyGenerator(uint16_t value);
	void Generator(int a, int b);
	void GeneratePublicKey();
	struct EEA {
		int x{}, y{}, GCD{};
	};
	EEA CalculateGCD(int a, int b);
};

#endif // !ELLIPTICCURVE_H