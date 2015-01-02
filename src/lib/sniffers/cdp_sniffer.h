/*******************************************************************************
 * Projekt:         Programování síťové služby: Sniffer CDP a LLDP
 * Jméno:           Radim
 * Příjmení:        Loskot
 * Login autora:    xlosko01
 * E-mail:          xlosko01(at)stud.fit.vutbr.cz
 * Popis:           Hlavičkový soubor deklarující třídu CDP sniffer.
 *
 ******************************************************************************/

/**
 * @file cdp_sniffer.h
 *
 * @brief Header file which declares CDP sniffer class.
 * @author Radim Loskot xlosko01(at)stud.fit.vutbr.cz
 */

#ifndef CDP_SNIFFER_H
#define CDP_SNIFFER_H

#include <string>

#include "packets/cdp_packet.h"
#include "sniffer.h"

/**
  * Class of CDP sniffer.
  * @todo Not fully implemented as a standalone sniffer.
  */
class CDPSniffer: public Sniffer {
public:
    /**
      * Defines type of callback function.
      */
    typedef void(*CaptureCallback)(const CDPPacket *);

    /**
      * Filter of this sniffer used for sniffing.
      */
    static const std::string FILTER;

    /**
      * Constructor
      */
    CDPSniffer():Sniffer(FILTER) {}

    /**
      * Validate sniffed packet.
      * @param packet Packet to be validated.
      * @return True on validation succes else false.
      */
    int validatePacket(Packet &packet);

    /**
      * Calling explicitly callback function.
      * @param packet Packet with which will be called callback function.
      */
    void callCallback(Packet *packet);

    /**
      * Capture callback function.
      */
    CaptureCallback captureCallback;
};

#endif
