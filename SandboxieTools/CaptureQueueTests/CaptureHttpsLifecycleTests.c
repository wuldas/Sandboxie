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
// HTTPS capture lifecycle tests
//---------------------------------------------------------------------------

#include <stdio.h>

#include "../../Sandboxie/core/svc/capture_https_lifecycle.h"


static int Require(int condition, const char *message)
{
    if (! condition) {
        fprintf(stderr, "FAILED: %s\n", message);
        return 0;
    }
    return 1;
}


static int TestHttpsNeedsBothExports(void)
{
    return Require(
        CaptureHttpsLifecycle_OnExport(TRUE, FALSE, FALSE) ==
            CAPTURE_HTTPS_LIFECYCLE_WAITING,
        "https without exports waits") &&
        Require(
            CaptureHttpsLifecycle_OnExport(TRUE, TRUE, FALSE) ==
                CAPTURE_HTTPS_LIFECYCLE_WAITING,
            "https with only pcap waits") &&
        Require(
            CaptureHttpsLifecycle_OnExport(TRUE, FALSE, TRUE) ==
                CAPTURE_HTTPS_LIFECYCLE_WAITING,
            "https with only har waits") &&
        Require(
            CaptureHttpsLifecycle_OnExport(TRUE, TRUE, TRUE) ==
                CAPTURE_HTTPS_LIFECYCLE_SPAWN,
            "https with both exports can spawn");
}


static int TestPacketNeedsOnlyPcap(void)
{
    return Require(
        CaptureHttpsLifecycle_OnExport(FALSE, TRUE, FALSE) ==
            CAPTURE_HTTPS_LIFECYCLE_SPAWN,
        "packet mode spawns on pcap only") &&
        Require(
            CaptureHttpsLifecycle_OnExport(FALSE, FALSE, FALSE) ==
                CAPTURE_HTTPS_LIFECYCLE_WAITING,
            "packet mode waits without pcap");
}


static int TestHttpsBrokerDeathKeepsRedirect(void)
{
    return Require(
        CaptureHttpsLifecycle_OnBrokerDeath(TRUE, TRUE) ==
            CAPTURE_HTTPS_BROKER_ACTION_KEEP_REDIRECT,
        "https broker death keeps redirect") &&
        Require(
            CaptureHttpsLifecycle_OnBrokerDeath(FALSE, TRUE) ==
                CAPTURE_HTTPS_BROKER_ACTION_TEARDOWN,
            "packet broker death tears down");
}


int main(void)
{
    int ok = TestHttpsNeedsBothExports() &&
        TestPacketNeedsOnlyPcap() &&
        TestHttpsBrokerDeathKeepsRedirect();
    if (! ok)
        return 1;
    printf("https lifecycle tests passed\n");
    return 0;
}
