/*******************************************************************************
 * Projekt:         Programování síťové služby: Sniffer CDP a LLDP
 * Jméno:           Radim
 * Příjmení:        Loskot
 * Login autora:    xlosko01
 * E-mail:          xlosko01(at)stud.fit.vutbr.cz
 * Popis:           Hlavičkový soubor daklarující třídu paketu.
 *
 ******************************************************************************/

/**
 * @file packet.h
 *
 * @brief Header file which declares class of packet.
 * @author Radim Loskot xlosko01(at)stud.fit.vutbr.cz
 */

#ifndef PACKET_H
#define PACKET_H

#include <pcap.h>
#include <vector>
#include "frames/data.h"

using namespace std;

/**
  * Class of the packet.
  * @todo Not fully implemented. Better work with data.
  */
class Packet {
public:
    typedef vector<int> Protocols;  /**< type definition of array of protocols */

    /**
      * Constructor of packet from data and protocols from which is made out.
      * @param data Source data of this packet.
      * @param protocols Protocols from which is made out this packet.
      */
    Packet(const Data data, Protocols protocols = Protocols()) : protocols(protocols), data(data) { }

    /**
      * Virtual destrutor which enables calling derived desctructors.
      */
    virtual ~Packet() {}
    //const Protocols getProtocols();

    /** Returns data of which is this packet made out.
      * @return Data of this packet.
      */
    const Data getData();

    /** Appends data to packet.
      * @return newData Data to be appended.
      */
    void appendData(Data newData);

    /** Virtual method to be overrided in derived class.
      * @return Size of this packet
      */
    virtual int getSize() { return -1; }

    Protocols protocols;    /**< Array of protocols */

protected:
    Data data;              /**< Data of packet */
};

#endif // PACKET_H
