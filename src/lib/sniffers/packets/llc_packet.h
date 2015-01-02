/*******************************************************************************
 * Projekt:         Programování síťové služby: Sniffer CDP a LLDP
 * Jméno:           Radim
 * Příjmení:        Loskot
 * Login autora:    xlosko01
 * E-mail:          xlosko01(at)stud.fit.vutbr.cz
 * Popis:           Hlavičkový soubor daklarující třídu IEEE 802.2 LLC paketu.
 *
 ******************************************************************************/

/**
 * @file llc_packet.h
 *
 * @brief Header file which declares class IEEE 802.2 LLC and SNAP packet.
 * @author Radim Loskot xlosko01(at)stud.fit.vutbr.cz
 */

#ifndef LLC_PACKET_H
#define LLC_PACKET_H

#include "packet.h"

/**
  * Class of LLC packet.
  */
class LLCPacket : public Packet {
public:
    static const int ORG_CODE_LEN = 3;      /**< Length of organization code in LLC */

    /**
      * LLC packet structure
      */
    typedef struct {
        u_int8_t DSAP;
        u_int8_t SSAP;
        u_int8_t control;
        u_int8_t organizationCode[ORG_CODE_LEN];
        u_int16_t etherType;
    } LLC;

    /**
      * Constructor of LLC packet from data and protocols from which is made out.
      * @todo protocols has to be specified, more correct would be auto recognition by
      *   static isThisProtocol function
      * @param data Source data of this packet.
      * @param protocols Protocols from which is made out this packet. (remove in future)
      */
    LLCPacket(const Data data, Protocols protocols) : Packet(data, protocols) { }

    /**
      * Checks packet whether is packet of this protocol.
      * @param packet Packet to be verified.
      * @param onSuccessAddProtocol When true then will be added to packet appropriate protocls.
      * @todo Not implemented recognition... Only first layer (datalink) is verified
      * @return True/false.
      */
    static int isThisProtocol(Packet *packet, bool onSuccessAddProtocol = true);

    /**
      * Returns size of CDP packet.
      * @return Size of CDP packet only, or -1 on malformed/bad packet.
      */
    int getSize();

    /**
      * Returns start position of CDP packet in data.
      * @return Start position of CDP packet in data, or -1 on malformed/bad packet.
      */
    int beginAt();

    /**
      * Returns header od LLC packet.
      * @return Header of LLC packet.
      */
    LLC getHeader();

private:

    /**
      * Checks whether there is enough size for LLC header.
      * @todo Remove in future. Use isThisProtocol next time.
      * @return True/false.
      */
    int validateSize();

};

#endif // LLC_PACKET_H
