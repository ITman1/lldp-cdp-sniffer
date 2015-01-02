/*******************************************************************************
 * Projekt:         Programování síťové služby: Sniffer CDP a LLDP
 * Jméno:           Radim
 * Příjmení:        Loskot
 * Login autora:    xlosko01
 * E-mail:          xlosko01(at)stud.fit.vutbr.cz
 * Popis:           Hlavičkový soubor daklarující abstraktní třídu rámce
 *                  a třídu MAC adresy.
 *
 ******************************************************************************/

/**
 * @file frame.h
 *
 * @brief Header file which declares abstract class of frame and class of MAC address.
 * @author Radim Loskot xlosko01(at)stud.fit.vutbr.cz
 */

#ifndef FRAME_H
#define FRAME_H

#include <string>
#include <pcap.h>
#include "data.h"

using namespace std;

/**
  * Class holding MAC address.
  */
class MACAddress {
public:
    MACAddress() {}
    /**
      * Loads MAC address from array of chars.
      * @param arr Array of chars where is MAC address.
      */
    MACAddress(const u_int8_t *arr);

    /**
      * Converts MAC address to string representation.
      * @return String representation of MAC address.
      */
    string toStr();

    /**
      * Retrieves MAC address of interface specified by name.
      * @param interface Name of interface where to get MAC address.
      * @param  address MAC address of interface will be set here.
      * @return True on success, false on fail.
      */
    static int getInterfaceMACAddress(string interface, MACAddress &address);

    const static int MAC_ADDRESS_SIZE = 6;      /**< Maximum size of MAC address */
    u_int8_t mac[MAC_ADDRESS_SIZE];               /**< Array holding mac address. */
};

/**
  * Abstract class of frame.
  */
class Frame {
public:
    /**
      * Constructor which stores data.
      * @param data Data to be stored.
      */
    Frame(const Data data): data(data) { }

    /**
      * Wraps data with frame.
      * @param data Data to be wrapped.
      * @return Wrapped data with frame.
      */
    virtual Data wrapData(Data &data) = 0;

    /**
      * Returns size of frame.
      * @return Size of frame.
      */
    virtual int getSize() = 0;

protected:
    Data data;          /**< Holds frame or whole packet data */
};

#endif
