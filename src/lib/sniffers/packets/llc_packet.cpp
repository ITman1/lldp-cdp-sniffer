/*******************************************************************************
 * Projekt:         Programování síťové služby: Sniffer CDP a LLDP
 * Jméno:           Radim
 * Příjmení:        Loskot
 * Login autora:    xlosko01
 * E-mail:          xlosko01(at)stud.fit.vutbr.cz
 * Popis:           Modul definující třídu IEEE 802.2 LLC paketu.
 *
 ******************************************************************************/

/**
 * @file llc_packet.cpp
 *
 * @brief Header which defines class of IEEE 802.2 LLC and SNAP packet.
 *   http://www.networksorcery.com/enp/protocol/IEEE8022.htm
 * @author Radim Loskot xlosko01(at)stud.fit.vutbr.cz
 */

#include <pcap.h>
#include <cstring>
#include <netinet/in.h>
#include "frames/ethernet_frame.h"
#include "protocols.h"
#include "llc_packet.h"

/**
  * Checks packet whether is packet of this protocol.
  * @param packet Packet to be verified.
  * @param onSuccessAddProtocol When true then will be added to packet appropriate protocls.
  * @todo Not implemented recognition... Only first layer (datalink) is verified
  * @return True/false.
  */
int LLCPacket::isThisProtocol(Packet *packet, bool onSuccessAddProtocol) {

    // delete this constructor in future and add proprietary datalink check which is now done in vylidateSize()
    if (LLCPacket(packet->getData(), packet->protocols).validateSize()) {

        // for recognition LLDP a CDP is not necessary to implement LLC filter
        if (onSuccessAddProtocol) {
            if (packet->protocols.size() <= LAYER_2) {
                packet->protocols.push_back(LLC_PROTOCOL);
            } else {
                packet->protocols[LAYER_2] = LLC_PROTOCOL;
            }
        }
        return 1;
    }
    return 0;
}

/**
  * Returns size of CDP packet.
  * @return Size of CDP packet only, or -1 on malformed/bad packet.
  */
int LLCPacket::getSize() {
    return sizeof(LLC);
}

/**
  * Returns start position of CDP packet in data.
  * @return Start position of CDP packet in data, or -1 on malformed/bad packet.
  */
int LLCPacket::beginAt() {
    // LLC on ethernet datalink only
    if ((!protocols.empty()) && (protocols.at(DATALINK) == DLT_EN10MB)) {
        return EthernetFrame(data).getSize();
    }

    return -1;
}

/**
  * Checks whether there is enough size for LLC header.
  * @todo Remove in future. Use isThisProtocol next time.
  * @return True/false.
  */
int LLCPacket::validateSize() {
    // check whether header does not exceed data length
    return (((beginAt()) != -1) && (beginAt() + getSize() <= data.length));
}

/**
  * Returns header od LLC packet.
  * @return Header of LLC packet.
  */
LLCPacket::LLC LLCPacket::getHeader() {
    LLC header;
    memset(&header, 0, sizeof(header));

    if (validateSize()) {
        header = *(LLC *)(&data.data[beginAt()]);
        header.etherType = ntohs(header.etherType);
    } else {
        // chyba...
    }

    return header;
}

