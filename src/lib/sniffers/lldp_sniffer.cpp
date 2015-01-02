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
 * @file lldp_sniffer.cpp
 *
 * @brief Module which defines CDP sniffer class.
 * @author Radim Loskot xlosko01(at)stud.fit.vutbr.cz
 */

#include "packets/lldp_packet.h"
#include "lldp_sniffer.h"

using namespace std;

/**
  * Filter of this sniffer used for sniffing.
  */
const string LLDPSniffer::FILTER = "ether proto 0x88CC";

/**
  * Validate sniffed packet.
  * @param packet Packet to be validated.
  * @return True on validation succes else false.
  */
int LLDPSniffer::validatePacket(Packet &packet) {
    return LLDPPacket::isThisProtocol(&packet);
}

/**
  * Calling explicitly callback function.
  */
void LLDPSniffer::callCallback(Packet *packet) {
    LLDPPacket *detailedPacket = new LLDPPacket(packet->getData(), packet->protocols);

    if (captureCallback) captureCallback(detailedPacket);

    delete detailedPacket;
}
