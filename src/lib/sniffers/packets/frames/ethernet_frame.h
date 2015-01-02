/*******************************************************************************
 * Projekt:         Programování síťové služby: Sniffer CDP a LLDP
 * Jméno:           Radim
 * Příjmení:        Loskot
 * Login autora:    xlosko01
 * E-mail:          xlosko01(at)stud.fit.vutbr.cz
 * Popis:           Hlavičkový soubor deklarující třídu ethernetové hlavičky.
 *
 ******************************************************************************/

/**
 * @file ethernet_frame.h
 *
 * @brief Header file which declares class of ethernet header.
 * @author Radim Loskot xlosko01(at)stud.fit.vutbr.cz
 */

#ifndef ETHERNET_FRAME_H
#define ETHERNET_FRAME_H

#include <pcap.h>
#include "frame.h"

/**
  * Class of ethernet frame.
  */
class EthernetFrame: public Frame {
public:
    static const int ADDR_LEN = 6;      /**< Maximum of (MAC) address length */
    static const int MAX_SIZE = 1518;   /**< Maximal size of ethernet frame and appended data */

    /**
      * Struture of ethernet header
      */
    typedef struct {
        u_int8_t host[ADDR_LEN];          /**< Address of destination host */
        u_int8_t source[ADDR_LEN];        /**< Address of source */
        u_int16_t type;                   /**< Type of appended data/Length of appended data (IEEE 802.3) */
    } Ethernet;

    /**
      * Constructor which loads frame from passed data.
      * @param data Data which will be used to load and initialize this object.
      */
    EthernetFrame(const Data data):Frame(data) {}

    /**
      * Returns ethernet header as a structure.
      * @return Returns ethernet header as a structure.
      */
    Ethernet getFrame();

    /**
      * Wraps data with this ethernet header.
      * @todo Not implemented.
      * @param data Data to be wrapped.
      * @return Wrapped data with ethernet header.
      */
    Data wrapData(Data &data);

    /**
      * Returns size of ethernet frame.
      * @return Size of ethernet frame.
      */
    virtual int getSize();
};

#endif
