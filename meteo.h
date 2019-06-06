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

#include <stdint-gcc.h>

/**
 * Decrypt DCF77 weather data.
 * Input data is collected over three minutes.
 * @param 40 bits of weather data (3 packets of size 14, without the first and 8th bit received),
 *        then Minute, Hour, Day, Month, Day of Week, Year in BCD (as received)
 * @return 24 bits of decoded weather data
 */
uint32_t decryptMeteoData(uint8_t *data);

#endif //METEODECODE_METEO_H