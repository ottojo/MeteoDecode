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
#include <stdio.h>

void hello(void) {
    printf("Hello, World!\n");
}

// Splits time data and stores into thing
void copyTime(const uint8_t *key, cryptThing *thing) {
    thing->timeL = key[0] | key[1] << 8u | (key[2] & 0xFu) << 16u; // NOLINT(hicpp-signed-bitwise)
    thing->timeH = (key[2] | (key[3] << 8u) | (key[4] << 16u)) >> 4u; // NOLINT(hicpp-signed-bitwise)
}

void initRL(const uint8_t *cipher, cryptThing *thing) {
    thing->L = cipher[0] | cipher[1] << 8u | (cipher[2] & 0xFu) << 16u; // NOLINT(hicpp-signed-bitwise)
    thing->R = (cipher[2] | cipher[3] << 8u | cipher[4] << 16u) >> 4u; // NOLINT(hicpp-signed-bitwise)
}

void rotateLast20bitRight(uint32_t *b) {
    // store last bit
    uint8_t tmp = *b & 1u;
    *b >> 1u;
    // insert last bit at position 19
    *b |= tmp << 19u;
}

/**
 * Expands the R parameter from 20 to 30 bits
 * @param thing
 */
void expandR(cryptThing *thing) {
    // Reset any previous expansion
    thing->R &= 0xFFFFFu;

    // Start expansion left of data
    uint32_t bitmask = 0x1000000; // (that should be 1<<20 i think)
    for (int i = 0; i < 12; i++) {
        if (thing->R & expandRTable[i]) {
            thing->R |= bitmask;
        }
        bitmask <<= 1u;
    }
}

/**
 * Compresses the 40bit time information to 30bit key and stores this in L'
 * @param thing
 */
void compressKey(cryptThing *thing) {
    thing->L_ = 0;
    uint32_t bitmask = 1;
    for (int i = 0; i < 30; i++) {
        if (thing->timeL & timeCompression1[i] || thing->timeH & timeCompression2[i]) {
            thing->timeL |= bitmask;
        }
        bitmask <<= 1;
    }
}

void shiftTimeRight(int round, cryptThing *thing) {
    rotateLast20bitRight(&thing->timeH);
    rotateLast20bitRight(&thing->timeL);
    if (round == 16 || round == 8 || round == 7 || round == 3) {
        // rotate twice
        rotateLast20bitRight(&thing->timeH);
        rotateLast20bitRight(&thing->timeL);
    }
}

uint32_t decryptMeteoData(uint8_t data[10]) {

    cryptThing thing;

    uint8_t *cipher = data;
    uint8_t *key = data + 5;

    copyTime(key, &thing);
    initRL(cipher, &thing);


    return 0;
}
