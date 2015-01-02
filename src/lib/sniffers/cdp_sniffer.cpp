/*******************************************************************************
 * Projekt:         Programování síťové služby: Sniffer CDP a LLDP
 * Jméno:           Radim
 * Příjmení:        Loskot
 * Login autora:    xlosko01
 * E-mail:          xlosko01(at)stud.fit.vutbr.cz
 * Popis:           Modul definující třídu CDP sniffer.
 *
 ******************************************************************************/

/**
 * @file cdp_sniffer.cpp
 *
 * @brief Module which defines CDP sniffer class.
 * @author Radim Loskot xlosko01(at)stud.fit.vutbr.cz
 */

#include "packets/cdp_packet.h"
#include "cdp_sniffer.h"

using namespace std;

/**
  * Filter of this sniffer used for sniffing.
  */
const string CDPSniffer::FILTER = "ether multicast and ether[20:2] = 0x2000";

/**
  * Validate sniffed packet.
  * @param packet Packet to be validated.
  * @return True on validation succes else false.
  */
int CDPSniffer::validatePacket(Packet &packet) {
    return CDPPacket::isThisProtocol(&packet);
}

/**
  * Calling explicitly callback function.
  */
void CDPSniffer::callCallback(Packet *packet) {
    CDPPacket *detailedPacket = new CDPPacket(packet->getData(), packet->protocols);

    if (captureCallback) captureCallback(detailedPacket);

    delete detailedPacket;
}
