/*******************************************************************************
 * Projekt:         Programování síťové služby: Sniffer CDP a LLDP
 * Jméno:           Radim
 * Příjmení:        Loskot
 * Login autora:    xlosko01
 * E-mail:          xlosko01(at)stud.fit.vutbr.cz
 * Popis:           Hlavičkový soubor deklarující bázovou třídů snifferů.
 *
 ******************************************************************************/

/**
 * @file sniffer.h
 *
 * @brief Header file which declares base class to all sniffers.
 * @author Radim Loskot xlosko01(at)stud.fit.vutbr.cz
 */

#ifndef SNIFFER_H
#define SNIFFER_H

#include <string>
#include <pcap.h>
#include "packets/packet.h"

using namespace std;

/**
  * Base class for sniffer creation.
  */
class Sniffer {
public:

    /**
      * Type of callback function.
      */
    typedef void(*CaptureCallback)(const Packet *);

    /**
      * Enumeration of errors that can occur during sniffing.
      */
    enum errors {
        EOPEN_DEVICE            = 1,        /**< Unable open device */
        EPARSE_FILTER           = 2,        /**< Bad parse filter syntax */
        EINSTALL_FILTER         = 3,        /**< Cannot install compiled filter */
        EINJECT_PACKET          = 4,        /**< Cannot inject packet on interface */
        EGET_PACKET             = 5         /**< Unable get packet during listening */
    };

    static const string DEFAULT_INTERFACE;  /**< Default interface name */
    static const string FILTER;             /**< Current filter for sniffer */

    Sniffer():captureCallback(NULL), interface(DEFAULT_INTERFACE), sessionHandle(0) {}
    virtual ~Sniffer() {}

    /**
      * Validate sniffed packet. (not implemented in base class)
      * @param packet Packet to be validated.
      * @return True on validation succes else false.
      */
    virtual int validatePacket(Packet &packet) { packet = packet; return 0; }

    /**
      * Capture callback function.  (not implemented in base class)
      * @param packet Packet with which will be called callback function.
      */
    virtual void callCallback(Packet *packet) { packet = packet; }

    /**
      * Starts listening on sniffer interface.
      * @return True on valid stop of listening else false.
      */
    int startListening();

    /**
      * Stops listening on sniffer interface.
      */
    void stopListening();

    /** Sends packet on sniffer interface.
      * @param packet Packet which will be sent.
      */
    int sendPacket(Packet *packet);

    CaptureCallback captureCallback;    /**< Capture callback function */
    string interface;                   /**< Name of interface where sniffer runs */
    string filter;                      /**< Filter which is used for sniffing */

protected:
    Sniffer(string filter):filter(filter) {}

    /**
      * Is called when new packet is captured during listening.
      * @param packet Captured packet.
      */
    virtual void newPacket(Packet *packet);

    /**
      * Listening of sniffer runs here.
      * @return True on proper stop listening else false.
      */
    int listening();

    /**
      * Opens sniffer session.
      * @return True on succes else false.
      */
    int openSession();

    /**
      * Closes opened session whether exists.
      */
    void closeSession();

    pcap_t *sessionHandle;              /**< PCAP session handle */
    struct bpf_program compiledFilter;  /**< Compiled sniffing filter */
};

#endif
