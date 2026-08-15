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
// Session CA internals -- OpenSSL types stay out of public headers
//---------------------------------------------------------------------------

#ifndef _MY_CAPTURE_CA_PRIV_H
#define _MY_CAPTURE_CA_PRIV_H

#include <openssl/evp.h>
#include <openssl/x509.h>

#include "capture_ca.h"

struct _CAPTURE_CA {

    EVP_PKEY *key;
    X509 *cert;

};

int CaptureCa_MintLeaf(
    CAPTURE_CA *ca,
    const char *sni,
    X509 **cert,
    EVP_PKEY **key);

#endif /* _MY_CAPTURE_CA_PRIV_H */
