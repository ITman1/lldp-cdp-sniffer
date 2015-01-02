/*******************************************************************************
 * Projekt:         Programování síťové služby: Sniffer CDP a LLDP
 * Jméno:           Radim
 * Příjmení:        Loskot
 * Login autora:    xlosko01
 * E-mail:          xlosko01(at)stud.fit.vutbr.cz
 * Popis:           Hlavičkový soubor deklarující funkce pro získání informací o rozhraních.
 *
 ******************************************************************************/

/**
 * @file network.h
 *
 * @brief Header file which declares functions for getting informations about interfaces
 * @author Radim Loskot xlosko01(at)stud.fit.vutbr.cz
 */

#ifndef NETWORK_H
#define NETWORK_H

#include <netinet/in.h>
#include <sys/sysctl.h>
#include <sys/socket.h>

#include "lib/sniffers/packets/frames/frame.h"

namespace Network {
    /**
      * Tests whether is enabled forwarding between interfaces
      * @return If forwading is enabled returns true else false.
      */
    int forwardingEnabled();

    /**
      * Struvture that holds sysctl request path.
      */
    typedef struct {
        static const int MAX_MIB_LENGTH = 10;
        int length;
        int mib[MAX_MIB_LENGTH];
    } MIB;


#ifdef __FreeBSD__
    /**
      * FreeBSD sysctl IPv4 forwarding enable path.
      */
    // net.inet.ip.forwarding
    const MIB IPv4_FORWARDING_MIB = {4, {CTL_NET, PF_INET, IPPROTO_IP, IPCTL_FORWARDING}};
    /**
      * FreeBSD sysctl IPv6 forwarding enable path.
      */
    // net.inet6.ip6.forwarding
    const MIB IPv6_FORWARDING_MIB = {4, {CTL_NET, PF_INET6, IPPROTO_IPV6, IPV6CTL_FORWARDING}};
#else
    /**
      * Sysctl IPv4 forwarding enable path.
      */
    // net.ipv4.ip_forward
    const MIB IPv4_FORWARDING_MIB = {3, {CTL_NET, NET_IPV4, NET_IPV4_FORWARD}};
    /**
      * Sysctl IPv6 forwarding enable path.
      */
    // net.ipv6.conf.all.forwarding
    const MIB IPv6_FORWARDING_MIB = {5, {CTL_NET, NET_IPV6, NET_IPV6_CONF, NET_PROTO_CONF_ALL, NET_IPV6_FORWARDING}};
#endif

}

#endif // NETWORK_H
