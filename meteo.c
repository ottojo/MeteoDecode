/*
 * MeteoDecode
 * Written in 2019 by ottojo
 * To the extent possible under law, the author(s) have dedicated all copyright and related
 * and neighboring rights to this software to the public domain worldwide. This software is
 * distributed without any warranty.
 * You should have received a copy of the CC0 Public Domain Dedication along with this
 * software. If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
 */

#include "meteo.h"
#include "MeteoSecrets/secrets.h"

/**
 * Splits 40 bit time data and stores into timeH and timeL
 */
void copyTime(const uint8_t *time, uint32_t *timeH, uint32_t *timeL) {
    *timeL = time[0] | time[1] << 8u | (time[2] & 0xFu) << 16u; // NOLINT(hicpp-signed-bitwise)
    *timeH = (time[2] | (time[3] << 8u) | (time[4] << 16u)) >> 4u; // NOLINT(hicpp-signed-bitwise)
}

/**
 * Splits initial ciphertext in R and L
 */
void initRL(const uint8_t *cipher, uint32_t *R, uint32_t *L) {
    *L = cipher[0] | cipher[1] << 8u | (cipher[2] & 0xFu) << 16u; // NOLINT(hicpp-signed-bitwise)
    *R = (cipher[2] | cipher[3] << 8u | cipher[4] << 16u) >> 4u; // NOLINT(hicpp-signed-bitwise)
}

/**
 * Rotate the last 20 bit of the argument right
 */
void rotateLast20bitRight(uint32_t *b) {
    // store last bit
    uint8_t tmp = *b & 1u;
    *b >>= 1u;
    // insert last bit at position 19
    *b |= tmp << 19u;
}

/**
 * Expands the R parameter from 20 to 30 bits
 */
uint32_t expandR(uint32_t r) {
    uint32_t tmp;

    // Use only lower 20 bit (clear previous expansion?)
    r &= 0x000FFFFFu; // clear 0D(4-7),0E

    // Set bits right to left, starting here:
    tmp = 0x00100000; // and set bits form 0B-0D(0-3)
    for (unsigned int i = 0; i < 12; i++) {
        // last 2 elements in array are 0?
        // -> makes sense, need 10 new bits to expand from 20 to 30
        // why iteration until 12 and not 10?
        if ((r & expandRTable[i]) != 0)
            r |= tmp;
        tmp <<= 1u;
    }

    return r;
}


/**
 * Compresses the 40bit time information to 30bit key
 */
uint32_t compressKey(uint32_t timeH, uint32_t timeL) {
    uint32_t compressedKey = 0;
    uint32_t bitmask = 1;
    for (int i = 0; i < 30; i++) {
        if (timeL & timeCompression1[i] || timeH & timeCompression2[i]) {
            compressedKey |= bitmask;
        }
        bitmask <<= 1u;
    }
    return compressedKey;
}

/**
 * Build 6-bit groups for substitution:
 * From LSB to MSB:
 *  use 4 bit from lowIndex  (initially 0)
 *  use 2 bit from highIndex (initially 20)
 *  increment indices
 */
uint32_t distributeBitsForS(uint32_t input) {
    uint32_t output = 0;
    unsigned int lowIndex = 0;
    unsigned int highIndex = 20;
    for (unsigned int i = 0; i < 30; i++) {
        if ((i + 1) % 6 == 0 || (i + 2) % 6 == 0) {
            // Bits 4,5, 10,11,...
            output |= ((input >> highIndex) & 0b1u) << i;
            highIndex++;
        } else {
            // Bits 0-3, 6-9,...
            output |= ((input >> lowIndex) & 0b1u) << i;
            lowIndex++;
        }
    }
    return output;
}

/**
 * Apply B-Box permutation
 * @param input Usually output from S-Box
 */
uint32_t pBox(uint32_t input) {
    uint32_t r = 0;
    uint32_t tmp = 0x00000001;
    for (int i = 0; i < 20; i++) {
        if ((input & pBoxTable[i]) != 0) {
            // Set this bit (RTL)
            r |= tmp;
        }
        tmp <<= 1u;
    }

    return r;
}

/**
 * Apply S-Box to input.
 * After substituting, shuffle the result around in a way that does not make
 * any sense to me, but is necessary to work.
 * @param input 30 bits, formatted correctly (see distributeBitsForS)
 * @return 20 bit substituted input
 */
uint32_t sBox(uint32_t input) {
    uint32_t output = 0;
    // S5 (store at offset 12)
    output |= ((sTable1[input & 0x3Fu] & 0xFu) << 12u);

    // S4 Use bits 3 to 7 here (store at offset 16)
    output |= (sTable1[(input >> 6u) & 0x3Fu] & 0xF0u) << 12u;

    // S3 (store at offset 4)
    output |= (sTable2[(input >> 12u) & 0x3Fu] & 0xFu) << 4u;

    // S2 Use bits 3 to 7 here (store at offset 8)
    output |= (sTable2[(input >> 18u) & 0x3Fu] & 0xF0u) << 4u;

    // S1 (store at offset 0)
    output |= (sTable3[(input >> 24u) & 0x3Fu] & 0xFu);

    return output;
}

/**
 * DES f-function:
 * - expand R
 * - XOR that with compressed key
 * - shuffle bits around into 5 6-bit-groups
 * - apply S-Box substitution to each 6-bit-group
 *   (results in 5 4-bit-groups)
 * - apply P-box permutation
 * @param compressedKey     30 bit compressed Key ("Ki")
 * @param R                 Parameter "R" of current round
 * @return 20 bit result
 */
uint32_t f(uint32_t compressedKey, uint32_t R) {
    uint32_t expandedR = expandR(R);
    //printf("f: expanded R: 0x%x\n", expandedR);
    uint32_t sBoxInput = expandedR ^compressedKey;
    //printf("f: sBoxIn (R^key): 0x%x\n", sBoxInput);
    sBoxInput = distributeBitsForS(sBoxInput);
    //printf("f: built 6bit groups: 0x%x\n", sBoxInput);
    uint32_t sbr = sBox(sBoxInput);
    //printf("f: sbox result: 0x%x\n", sbr);
    return pBox(sbr);
}


/**
 * This rotates the data right by 4 bit and sets bits for successful conversion.
 * Also reverses order for correct output order.
 * @param plainBytes
 * @return 22 weather bits and 2 status bits
 */
uint32_t plaintextToMeteoData(const uint8_t *plainBytes) {
    uint32_t result;

    result = (plainBytes[4] & 0xFu) | 0b10000u;
    result <<= 8u;
    result |= plainBytes[0];
    result <<= 8u;
    result |= plainBytes[1];
    result <<= 4u;
    result |= (plainBytes[2] >> 4u);


    result &= 0x3FFFFFu; // truncate to 22bit
    result |= 0b10000000000000000000000u; // set bit 22 (1 after reversing) (indicates successful conversion)

    // This result is still in reverse order.

    uint32_t reversedResult = 0;
    for (int i = 0; i < 24; ++i) {
        reversedResult <<= 1u;
        reversedResult |= (result & 1u);
        result >>= 1u;
    }

    return reversedResult;
}


/**
 * Our Plaintext is in reverse order to C#
 * @return 0x2501 if data is valid
 */
uint32_t checksum(const uint8_t plainBytes[5]) {
    uint32_t checkSum;
    checkSum = plainBytes[2] & 0x0Fu;
    checkSum <<= 8;
    checkSum |= plainBytes[3];
    checkSum <<= 4;
    checkSum |= plainBytes[4] >> 4;

    return checkSum;
}


/**
 * Decrypt DCF77 weather data.
 * Input data is collected over three minutes.
 * The byte order is big endian, bit order is little endian.
 * For reference: The input 00101000100111001101110000011100111000000000010100000000000101101110011000011001
 * should be passed to this function as {40, 156, 220, 28, 224, 5, 0, 22, 230, 25}
 * @param 40 bits of weather data (3 packets of size 14, without the first and 8th bit received),
 *        then Minute, Hour, Day, Month, Day of Week, Year in BCD (as received)
 * @return 24 bits of decoded weather data
 */
uint32_t decryptMeteoData(uint8_t data[10]) {
    uint32_t L;
    uint32_t R;
    uint32_t timeL;
    uint32_t timeH;
    uint8_t *cipher = data;     // 5 bytes ciphertext
    uint8_t *key = data + 5;    // 5 bytes key (built from last time information)

    copyTime(key, &timeH, &timeL);
    initRL(cipher, &R, &L);

    for (int round = 16; round > 0; round--) {

        //printf("Round %d: L=0x%x, R=0x%x\n", round, L, R);
        //printf("Time: timeH=0x%x, timeL=0x%x\n", timeH, timeL);

        rotateLast20bitRight(&timeL);
        rotateLast20bitRight(&timeH);

        if (round == 16 || round == 8 || round == 7 || round == 3) {
            rotateLast20bitRight(&timeL);
            rotateLast20bitRight(&timeH);
        }


        //printf("Rotated Time. timeH=0x%x, timeL=0x%x\n", timeH, timeL);

        uint32_t oldR = R;

        uint32_t compressedKey = compressKey(timeH, timeL);

        //printf("Compressed key = 0x%x\n", compressedKey);

        uint32_t f_result = f(compressedKey, R);

        //printf("Applied f: 0x%x\n", f_result);

        R = L ^ f_result;
        L = oldR;
    }

    uint8_t plain[5] = {0};

    for (unsigned int i = 0; i < 10; i++) {
        // TODO make this nicer
        // This works but is ugly.
        // if R = 0x01234, L = 0x56789,
        // the output will be [0x01 0x23 0x45 0x67 0x89]
        if (i < 5) {
            // Place R in plain[0] and adjacent
            uint8_t dataToStore = (R >> 4 * (4 - i)) & 0xFu;
            plain[i / 2] |= dataToStore << (i % 2 == 0 ? 4u : 0);
        } else {
            // Place L in plain[5] and adjacent
            uint8_t dataToStore = (L >> 4 * (4u - (i - 5))) & 0xFu;
            plain[i / 2] |= dataToStore << ((i - 5) % 2 == 1 ? 4u : 0);
        }
    }

    //printf("Plaintext:\n");
    //for (int i = 0; i < 5; i++) {
    //    printf("plain[%d] = 0x%02x\n", i, plain[i]);
    //}

    if (checksum(plain) != 0x2501) {
        // Checksum invalid.
        // Returns this value for compatibility with C# lib,
        // the relevant part is the last 2 bits not being 0b10.
        return 0x100002;
    }

    return plaintextToMeteoData(plain);
}
