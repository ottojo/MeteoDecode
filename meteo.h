/*
 * MeteoDecode
 * Written in 2019 by ottojo
 * To the extent possible under law, the author(s) have dedicated all copyright and related
 * and neighboring rights to this software to the public domain worldwide. This software is
 * distributed without any warranty.
 * You should have received a copy of the CC0 Public Domain Dedication along with this
 * software. If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
 */

#ifndef METEODECODE_METEO_H
#define METEODECODE_METEO_H

#include "secrets.h"
#include <stdint-gcc.h>


typedef struct {
    uint32_t L;
    uint32_t L_;
    uint32_t R;
    uint32_t timeL;
    uint32_t timeH;
} cryptThing;

/**
 * Decrype DCF77 weather data
 * @param data Encrypted weather data without bits 0 and 7, order as received
 * @return 22 data bits, 2 status bits
 */
uint32_t decryptMeteoData(uint8_t *data);


#endif //METEODECODE_METEO_H