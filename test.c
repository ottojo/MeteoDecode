//
// Created by jonas on 6/6/19.
//

#include <stdint.h>
#include <stdio.h>
#include "meteo.h"

void binprintf(int v) {
    unsigned int mask = 1 << ((sizeof(int) << 3) - 1);
    while (mask) {
        printf("%d", (v & mask ? 1 : 0));
        mask >>= 1;
    }
}

void main() {
    uint8_t data[10] = {247, 58, 153, 242, 160, 2, 0, 3, 38, 25};

    binprintf(decryptMeteoData(data));
    printf("\nExpected001011000000100000001110\n");

}