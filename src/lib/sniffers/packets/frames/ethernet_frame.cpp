/*******************************************************************************
 * Projekt:         Programování síťové služby: Sniffer CDP a LLDP
 * Jméno:           Radim
 * Příjmení:        Loskot
 * Login autora:    xlosko01
 * E-mail:          xlosko01(at)stud.fit.vutbr.cz
 * Popis:           Modul definující třídu ethernetové hlavičky.
 *
 ******************************************************************************/

/**
 * @file ethernet_frame.cpp
 *
 * @brief Module which defines class of ethernet header.
 * @author Radim Loskot xlosko01(at)stud.fit.vutbr.cz
 */

#include <netinet/in.h>

#include "ethernet_frame.h"

/**
  * Returns ethernet header as a structure.
  * @return Returns ethernet header as a structure.
  */
EthernetFrame::Ethernet EthernetFrame::getFrame() {
    Ethernet header = *(Ethernet *)(data.data);
    header.type = ntohs(header.type);
    return header;
}

/**
  * Wraps data with this ethernet header.
  * @todo Not implemented.
  * @param data Data to be wrapped.
  * @return Wrapped data with ethernet header.
  */
Data EthernetFrame::wrapData(Data &data) {
    return data;
}

/**
  * Returns size of ethernet frame.
  * @return Size of ethernet frame.
  */
int EthernetFrame::getSize() {
    return sizeof(Ethernet);
}
