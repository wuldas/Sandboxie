/*
 * Copyright 2026 David Xanatos, xanasoft.com
 *
 * This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

//---------------------------------------------------------------------------
// Capture Network Encoding
//---------------------------------------------------------------------------

#include "capture_network.h"


void CaptureNetwork_EncodeIpv4(
    UCHAR output[16], ULONG hostOrderAddress)
{
    ULONG index;
    for (index = 0; index < 16; ++index)
        output[index] = 0;

    output[0] = (UCHAR)(hostOrderAddress >> 24);
    output[1] = (UCHAR)(hostOrderAddress >> 16);
    output[2] = (UCHAR)(hostOrderAddress >> 8);
    output[3] = (UCHAR)hostOrderAddress;
}
