/*******************************************************************************
 * Projekt:         Programování síťové služby: Sniffer CDP a LLDP
 * Jméno:           Radim
 * Příjmení:        Loskot
 * Login autora:    xlosko01
 * E-mail:          xlosko01(at)stud.fit.vutbr.cz
 * Popis:           Modul definující třídu nad snifferama.
 *                  Třída umožňuje přidávání a odebírání snifferů.
 *
 ******************************************************************************/

/**
 * @file sniffers.h
 *
 * @brief Module which defines class which enables adding and removing sniffers.
 * @author Radim Loskot xlosko01(at)stud.fit.vutbr.cz
 */

#include <iostream>
#include "sniffers.h"

using namespace std;

/**
  * Preparing buffer for packets. (Ethernet datalink only)
  */
u_int8_t packet_buff[EthernetFrame::MAX_SIZE];

/**
  * Desctructor
  */
Sniffers::~Sniffers() {
    vector<Sniffer *>::iterator pos;

    // all allocated TLV has to be deallocated before vector destruction
    for (pos = sniffers.begin(); pos != sniffers.end(); ++pos) {
        delete *pos;
    }
}

/**
  * Starts listening on sniffer interface.
  * @return True on valid stop of listening else false.
  */
int Sniffers::startListening() {
    int ret;
    string filter;
    vector<Sniffer *>::iterator pos;

    // creating final filter where are specified all demanded sniffer filters
    for (pos = sniffers.begin(); pos != sniffers.end(); ++pos) {
        filter += "(" + (*pos)->filter + ") or ";
    }

    filter.resize(filter.size() - 4);   // removing last "or"
    this->filter = filter;

    ret = Sniffer::startListening();    // listening

    if (ret) {                          // testing return value for errors
        switch (ret) {                  // determining error type
        case Sniffer::EOPEN_DEVICE:
            ret = ERR_LISTEN_DEVICE;
            break;
        default:
            ret = ERR_LISTEN;
        }
    }

    return ret;
}

/**
  * Is called when new packet is captured during listening.
  * @param packet Captured packet.
  */
void Sniffers::newPacket(Packet *packet) {
    vector<Sniffer *>::iterator pos;

    // Go through all sniffers and testing packet
    // One packet can be validated in more sniffers - depends on sniffer level (HTTP uses IP etc.)
    for (pos = sniffers.begin(); pos != sniffers.end(); ++pos) {
        if ((*pos)->validatePacket(*packet)) {
            (*pos)->callCallback(packet);               // calling callback
            // some additionals stats
            _lastCapturedPacketNumber++;
            _capturedBytes += packet->getData().length;
        }
    }
}

/**
  * Starts sending packet of corresponding protocol.
  * @param protocol Which packet will be sending.
  * @param ttl Time to live of packet
  * @param interval Duration between packet resending.
  * @return True on valid stop of sending else false.
  */
int Sniffers::startSending(int protocol, int ttl, int interval) {
    int ret = 0;
    Packet *packet = 0;
    Data packetData(packet_buff, 0);

    switch (protocol) {     // packet to generate
    case LLDP_PROTOCOL:
        packet = new LLDPPacket(packetData, Packet::Protocols());
        ret = LLDPPacket::generateDevicePacket(*static_cast<LLDPPacket *>(packet), interface, ttl);
        break;
    case CDP_PROTOCOL:
        packet = new CDPPacket(packetData, Packet::Protocols());
        ret = CDPPacket::generateDevicePacket(*static_cast<CDPPacket *>(packet), interface, ttl);
        break;
    }

    if (ret || !packet) {   // no packet generated
        delete packet;
        return ERR_GENPACKET;
    }

    sending = 1;
    while (sending) {       // sending
        if (sendPacket(packet)) {   // sending failed
            delete packet;
            return ERR_SENDPACKET;
        }

        // packet sent, soma additional statistics
        _lastSentPacketNumber++;
        _sentBytes += packet->getData().length;
        sleep(interval);    // sleeping for interval
    }

    delete packet;

    return 0;
}

/**
  * Stops sending packets.
  */
void Sniffers::stopSending() {
    sending = 0;
}

/**
  * Returns last number of captured packet.
  * @return Number of last captured packet
  */
int Sniffers::lastCapturedPacketNumber() {
    return _lastCapturedPacketNumber;
}

/**
  * Returns number of captured bytes.
  * @return Number of captured bytes.
  */
int Sniffers::capturedBytes() {
    return _capturedBytes;
}

/**
  * Returns last number of sent packet.
  * @return Number of last sent packet
  */
int Sniffers::lastSentPacketNumber() {
    return _lastSentPacketNumber;
}

/**
  * Returns number of sent bytes.
  * @return Number of sent bytes.
  */
int Sniffers::sentBytes() {
    return _sentBytes;
}
