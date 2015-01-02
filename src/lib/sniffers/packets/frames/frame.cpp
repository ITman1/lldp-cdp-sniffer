/*******************************************************************************
 * Projekt:         Programování síťové služby: Sniffer CDP a LLDP
 * Jméno:           Radim
 * Příjmení:        Loskot
 * Login autora:    xlosko01
 * E-mail:          xlosko01(at)stud.fit.vutbr.cz
 * Popis:           Modul definující třídu MAC adresy.
 *
 ******************************************************************************/

/**
 * @file frame.cpp
 *
 * @brief Module which defines class of MAC address.
 * @author Radim Loskot xlosko01(at)stud.fit.vutbr.cz
 */

#include <cstring>
#include <cstdio>
#include <iostream>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>

// FreeBSD solution
#if !defined(SIOCGIFHWADDR) && !defined(SIOCGENADDR)
    #include <ifaddrs.h>
    #include <net/if_dl.h>
    #include <net/if_types.h>
#endif

#include "frame.h"
#include "data.h"

using namespace std;

/**
  * Retrieves MAC address of interface specified by name.
  * @param interface Name of interface where to get MAC address.
  * @param  address MAC address of interface will be set here.
  * @return True on success, false on fail.
  */
// Linux solution
#if defined(SIOCGIFHWADDR) ||  defined(SIOCGENADDR)
int MACAddress::getInterfaceMACAddress(string interface, MACAddress &address) {
    int sock;
    struct ifreq ifr;

    // opening socket
    if((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket() failed");
        return 0;
    }

    // setting request interface name
    ifr.ifr_addr.sa_family = AF_INET;
    memcpy(ifr.ifr_name, interface.c_str(), interface.length() + 1);

    // requesting MAC address
    #ifdef SIOCGIFHWADDR
    if (ioctl(sock, SIOCGIFHWADDR, &ifr)) {
    #else
    if (ioctl(sock, SIOCGENADDR, &ifr)) {
    #endif
        perror("Unable get MAC address");
        close(sock);
        return 0;
    }

    // Converting MAC and setting return value
    #ifdef SIOCGIFHWADDR
    address = MACAddress((u_int8_t *)ifr.ifr_hwaddr.sa_data);
    #else
    address = MACAddress((u_int8_t *)ifr->ifr_enaddr);
    #endif

    return 1;
}
// FreeBSD solution
#else
int MACAddress::getInterfaceMACAddress(string interface, MACAddress &address) {
    int ret = 0;
    struct ifaddrs *ifaddr, *ifa;
    struct sockaddr_dl *addr;

    // getting list of all interfaces
    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs() failed");
        return 0;
    }

    // loop through all interfaces
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {

        // select interfaces with demanding interface name and AF_LINK family
        if ((string(ifa->ifa_name) == interface) && (ifa->ifa_addr->sa_family == AF_LINK)) {
            addr = (struct sockaddr_dl *)ifa->ifa_addr;

            // MAC address has length 6 only
            if (addr->sdl_alen != MAC_ADDRESS_SIZE)  {
                continue;
            }

            // Accepting ethernet interfaces only
            switch(addr->sdl_type) {
            case IFT_ETHER:
                #ifdef IFT_IEEE80211
                    case IFT_IEEE80211:
                #endif
                break;
            default:
                continue;
            }

            // Conveerting MAC and returning
            address = MACAddress((u_int8_t *)LLADDR(addr));
            ret = 1;
            break;
        }
    }

    freeifaddrs(ifaddr);
    return ret;
}
#endif

/**
  * Loads MAC address from array of chars.
  * @param arr Array of chars where is MAC address.
  */
MACAddress::MACAddress(const u_int8_t *arr) {
    memcpy(mac, arr, MAC_ADDRESS_SIZE);
}

/**
  * Converts MAC address to string representation.
  * @return String representation of MAC address.
  */
string MACAddress::toStr() {
    return Data::toHex(mac[0]) + ":" + Data::toHex(mac[1]) + ":" +
           Data::toHex(mac[2]) + ":" + Data::toHex(mac[3]) + ":" +
           Data::toHex(mac[4]) + ":" + Data::toHex(mac[5]);
}
