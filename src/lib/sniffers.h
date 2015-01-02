/*******************************************************************************
 * Projekt:         Programování síťové služby: Sniffer CDP a LLDP
 * Jméno:           Radim
 * Příjmení:        Loskot
 * Login autora:    xlosko01
 * E-mail:          xlosko01(at)stud.fit.vutbr.cz
 * Popis:           Hlavičkový soubor deklarující třídu nad snifferama.
 *                  Třída umožňuje přidávání a odebírání snifferů.
 *
 ******************************************************************************/

/**
 * @file sniffers.h
 *
 * @brief Header file which declares class which enables adding and removing sniffers.
 * @author Radim Loskot xlosko01(at)stud.fit.vutbr.cz
 */

#ifndef SNIFFERS_H
#define SNIFFERS_H

#include <vector>

#include "sniffers/lldp_sniffer.h"
#include "sniffers/cdp_sniffer.h"
#include "sniffers/packets/protocols.h"

using namespace std;

/**
  * Class sniffers. Declares actions above sniffers.
  */
class Sniffers :public Sniffer{
public:

    /**
      * Handled errors
      */
    enum errors {
        ERR_GENPACKET       = 1,    /**< Unable generate packet */
        ERR_SENDPACKET      = 2,    /**< Unable send packet */
        ERR_LISTEN          = 3,    /**< Unable listen - other error */
        ERR_LISTEN_DEVICE   = 4     /**< Unable listen - open error */
    };

    Sniffers():Sniffer(), sending(0), _lastCapturedPacketNumber(-1),
        _capturedBytes(0), _lastSentPacketNumber(-1), _sentBytes(0) {}
    ~Sniffers();

    /**
      * Template for adding sniffers.
      * @param SnifferType Class of one sniffer
      * @param callback Corresponding sniffer callback function
      */
    template<class SnifferType>
    void addSnifferCallback(typename SnifferType::CaptureCallback callback) {
        SnifferType *sniffer;
        // Pushing to array of sniffers
        sniffers.push_back(sniffer = new SnifferType);
        sniffer->captureCallback = callback;
    }

    /**
      * Starts listening on sniffer interface.
      * @return True on valid stop of listening else false.
      */
    int startListening();

    /**
      * Starts sending packet of corresponding protocol.
      * @param protocol Which packet will be sending.
      * @param ttl Time to live of packet
      * @param interval Duration between packet resending.
      * @return True on valid stop of sending else false.
      */
    int startSending(int protocol, int ttl = 120, int interval = 30);

    /**
      * Stops sending packets.
      */
    void stopSending();

    /**
      * Returns last number of captured packet.
      * @return Number of last captured packet
      */
    int lastCapturedPacketNumber();

    /**
      * Returns number of captured bytes.
      * @return Number of captured bytes.
      */
    int capturedBytes();

    /**
      * Returns last number of sent packet.
      * @return Number of last sent packet
      */
    int lastSentPacketNumber();

    /**
      * Returns number of sent bytes.
      * @return Number of sent bytes.
      */
    int sentBytes();

private:
    /**
      * Is called when new packet is captured during listening.
      * @param packet Captured packet.
      */
    virtual void newPacket(Packet *packet);

    vector<Sniffer *> sniffers;     /**< Array with demanded sniffers */
    int sending;                    /**< Signalizes whether is currently sending */
    int _lastCapturedPacketNumber;  /**< Last captured packet number */
    int _capturedBytes;             /**< Total captured bytes */
    int _lastSentPacketNumber;      /**< Last sent packet number */
    int _sentBytes;                 /**< Total sent bytes */
};

#endif
