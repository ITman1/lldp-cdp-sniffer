/*******************************************************************************
 * Projekt:         Programování síťové služby: Sniffer CDP a LLDP
 * Jméno:           Radim
 * Příjmení:        Loskot
 * Login autora:    xlosko01
 * E-mail:          xlosko01(at)stud.fit.vutbr.cz
 * Popis:           Modul definující třídu paketu.
 *
 ******************************************************************************/

/**
 * @file packet.cpp
 *
 * @brief Module which defines class of the packet.
 * @author Radim Loskot xlosko01(at)stud.fit.vutbr.cz
 */

#include <pcap.h>
#include "packet.h"

/** Returns data of which is this packet made out.
  * @return Data of this packet.
  */
const Data Packet::getData() {
    return data;
}

/** Appends data to packet.
  * @return newData Data to be appended.
  */
void Packet::appendData(Data newData) {
    data.appendData(newData);
}
