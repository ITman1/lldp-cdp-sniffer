/*******************************************************************************
 * Projekt:         Programování síťové služby: Sniffer CDP a LLDP
 * Jméno:           Radim
 * Příjmení:        Loskot
 * Login autora:    xlosko01
 * E-mail:          xlosko01(at)stud.fit.vutbr.cz
 * Popis:           Modul definující deklarující funkce pro získání informací o rozhraních.
 *
 ******************************************************************************/

/**
 * @file network.cpp
 *
 * @brief Module which defines functions for getting informations about interfaces
 * @author Radim Loskot xlosko01(at)stud.fit.vutbr.cz
 */

#include <iostream>
#include <cstdio>

using namespace std;

#include "network.h"

/**
  * Tests whether is enabled forwarding between interfaces
  * @return If forwading is enabled returns true else false.
  */
int Network::forwardingEnabled() {

    size_t len;
    int ipv4_forwarding = 0, ipv6_forwarding = 0;

    // test whether IPv4 forawrding is enabled
    len = sizeof ipv4_forwarding;
    if (sysctl (const_cast<int *>(IPv4_FORWARDING_MIB.mib), IPv4_FORWARDING_MIB.length, &ipv4_forwarding, &len, 0, 0) < 0) {
        perror("sysctl() failed");
        return 0;
    }

    // test whether IPv6 forawrding is enabled
    len = sizeof ipv6_forwarding;
    if (sysctl (const_cast<int *>(IPv6_FORWARDING_MIB.mib), IPv6_FORWARDING_MIB.length, &ipv6_forwarding, &len, 0, 0) < 0) {
        perror("sysctl() failed");
        return 0;
    }

    return ipv4_forwarding || ipv6_forwarding;
}
