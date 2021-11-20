#include "EllipticCurve.h"
#include <bitset>

void EllipticCurve::Generator(int a, int b) {
	GeneratorPoint[0] = a;
	GeneratorPoint[1] = b;
	//Constant Generator reference
	xGCoordinate = GeneratorPoint[0];
	yGCoordinate = GeneratorPoint[1];

	//Variable Coordinate reference for calculation
	x1Coordinate = GeneratorPoint[0];
	y1Coordinate = GeneratorPoint[1];
}

void EllipticCurve::GeneratePublicKey() {

	//Get Binary value of private key
	//We'll assume the key is 4 bit
	std::bitset<4> PKey(PrivateKey);
	std::string BinayValue = PKey.to_string();
	for (size_t i = 1; i < BinayValue.length(); i++) {
		//If index is 1 binary, we use point doubling and addition
		if (BinayValue[i] == '1') {
			int SlopeDividend = (3 * x1Coordinate * x1Coordinate + 2) % MODULUS;
			int SlopeDivisor = (2 * y1Coordinate) % MODULUS;

			//Check if inverse exist for A/B
			int remainder = SlopeDividend % SlopeDivisor;
			
			if (remainder != 0) {
				EEA Calc = CalculateGCD(MODULUS, SlopeDivisor);
				int InverseValue = Calc.y;
				if (InverseValue < 0) {
					InverseValue += 17;
				}
				Slope = (SlopeDividend * InverseValue) % MODULUS;
				x3Coordinate = (Slope * Slope - x1Coordinate - x1Coordinate) % MODULUS;
				if (x3Coordinate < 0) {
					x3Coordinate += MODULUS;
				}
				y3Coordinate = (Slope * (x1Coordinate - x3Coordinate) - y1Coordinate) % MODULUS;
				if (y3Coordinate < 0) {
					y3Coordinate += MODULUS;
				}
			}
			else {
				Slope = (SlopeDividend / SlopeDivisor) % MODULUS;
				x3Coordinate = (Slope * Slope - x1Coordinate - x1Coordinate) % MODULUS;
				if (x3Coordinate < 0) {
					x3Coordinate += MODULUS;
				}
				y3Coordinate = (Slope * (x1Coordinate - x3Coordinate) - y1Coordinate) % MODULUS;
				if (y3Coordinate < 0) {
					y3Coordinate += MODULUS;
				}
			}

			//Now we do point addition
			int x2Coordinate = x3Coordinate, y2Coordinate = y3Coordinate;
			SlopeDividend = (y2Coordinate - yGCoordinate) % MODULUS;
			SlopeDivisor = (x2Coordinate - xGCoordinate) % MODULUS;
			if (SlopeDividend < 0) {
				SlopeDividend += MODULUS;
			}
			if (SlopeDivisor < 0) {
				SlopeDivisor += MODULUS;
			}

			//Check if inverse exist
			remainder = SlopeDividend % SlopeDivisor;

			if (remainder != 0) {
				EEA Calc = CalculateGCD(MODULUS, SlopeDivisor);
				int InverseValue = Calc.y;
				if (InverseValue < 0) {
					InverseValue += MODULUS;
				}
				Slope = (SlopeDividend * InverseValue) % MODULUS;
				x3Coordinate = (Slope * Slope - x2Coordinate - xGCoordinate) % MODULUS;
				if (x3Coordinate < 0) {
					x3Coordinate += MODULUS;
				}
				y3Coordinate = (Slope * (x2Coordinate - x3Coordinate) - y2Coordinate) % MODULUS;
				if (y3Coordinate < 0) {
					y3Coordinate += MODULUS;
				}
			}
			else {
				Slope = (SlopeDividend / SlopeDivisor) % MODULUS;
				x3Coordinate = (Slope * Slope - x2Coordinate - xGCoordinate) % MODULUS;
				if (x3Coordinate < 0) {
					x3Coordinate += MODULUS;
				}
				y3Coordinate = (Slope * (x2Coordinate - x3Coordinate) - y2Coordinate) % MODULUS;
				if (y3Coordinate < 0) {
					y3Coordinate += MODULUS;
				}
			}

			//Final points are
			x1Coordinate = x3Coordinate;
			if (x1Coordinate < 0) {
				x1Coordinate += MODULUS;
			}
			y1Coordinate = y3Coordinate;
			if (y1Coordinate < 0) {
				y1Coordinate += MODULUS;
			}
		}
		else //The binary value is not 1. We only do point addition
		{
			int SlopeDividend = (3 * x1Coordinate * x1Coordinate + 2) % MODULUS;
			int SlopeDivisor = (2 * y1Coordinate) % MODULUS;

			//Check if inverse exist for A/B
			int remainder = SlopeDividend % SlopeDivisor;

			if (remainder != 0) {
				EEA Calc = CalculateGCD(MODULUS, SlopeDivisor);
				int InverseValue = Calc.y;
				if (InverseValue < 0) {
					InverseValue += MODULUS;
				}
				Slope = (SlopeDividend * InverseValue) % MODULUS;
				x3Coordinate = (Slope * Slope - x1Coordinate - x1Coordinate) % MODULUS;
				y3Coordinate = (Slope * (x1Coordinate - x3Coordinate) - y1Coordinate) % MODULUS;
			}
			else {
				Slope = (SlopeDividend / SlopeDivisor) % MODULUS;
				x3Coordinate = (Slope * Slope - x1Coordinate - x1Coordinate) % MODULUS;
				y3Coordinate = (Slope * (x1Coordinate - x3Coordinate) - y1Coordinate) % MODULUS;
			}
			//Final points are
			x1Coordinate = x3Coordinate;
			if (x1Coordinate < 0) {
				x1Coordinate += MODULUS;
			}
			y1Coordinate = y3Coordinate;
			if (y1Coordinate < 0) {
				y1Coordinate += MODULUS;
			}
		}

		std::cout << x1Coordinate << " " << y1Coordinate << std::endl;
	}
}

EllipticCurve::EEA EllipticCurve::CalculateGCD(int a, int b)
{
	if (b == 0) {
		EllipticCurve::EEA triple;
		triple.GCD = a;
		triple.x = 1;
		triple.y = 0;

		return triple;
	}

	EllipticCurve::EEA smallGCD = CalculateGCD(b, a % b);
	EllipticCurve::EEA triple;
	triple.GCD = smallGCD.GCD;
	triple.x = smallGCD.y;
	triple.y = smallGCD.x - (a / b) * smallGCD.y;

	return triple;
}