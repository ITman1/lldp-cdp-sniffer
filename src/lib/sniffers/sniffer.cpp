/*******************************************************************************
 * Projekt:         Programování síťové služby: Sniffer CDP a LLDP
 * Jméno:           Radim
 * Příjmení:        Loskot
 * Login autora:    xlosko01
 * E-mail:          xlosko01(at)stud.fit.vutbr.cz
 * Popis:           Modul definující bázovou třídů snifferů.
 *
 ******************************************************************************/

/**
 * @file sniffer.cpp
 *
 * @brief Module which defines base class to all sniffers.
 * @author Radim Loskot xlosko01(at)stud.fit.vutbr.cz
 */

#include <iostream>
#include <pcap.h>
#include "sniffer.h"

using namespace std;

/**
 * Default sniffer interface name
 */
const string Sniffer::DEFAULT_INTERFACE = "em0";

/**
  * Is called when new packet is captured during listening.
  * @param packet Captured packet.
  */
void Sniffer::newPacket(Packet *packet) {
    if (captureCallback) {
        captureCallback(packet);
    }
}


/**
  * Listening of sniffer runs here.
  * @return True on proper stop listening else false.
  */
int Sniffer::listening() {
    struct pcap_pkthdr *pkt_header;
    const u_int8_t *pkt_data;
    int res;
    Data data;
    Packet *packet;

    while (true) { // Capturing packets and calling newPacket function
        res = pcap_next_ex(sessionHandle, &pkt_header, &pkt_data);

        if (res == -1) {    // Unspecified error on listening
            pcap_geterr(sessionHandle);
            return EGET_PACKET;
        }

        if (res == -2) {    // Just timeout, maybe next time
            break;
        }

        if (res == 1) {     // Got new packet
            // Storing u_int8_t data to Packet object
            data.data = pkt_data;
            data.length = pkt_header->len;
            packet = new Packet(data);
            packet->protocols.push_back(pcap_datalink(sessionHandle));

            newPacket(packet);  // calling newPacket and maybe callback
            delete packet;
        }
    }

    stopListening();            // Just for sure :)

    return 0;
}

/**
  * Starts listening on sniffer interface.
  * @return True on valid stop of listening else false.
  */
int Sniffer::startListening() {
    int ret;

    // Open session first
    if ((ret = openSession())) {
        return ret;
    }

    // Compile sniffer filter
    if (pcap_compile(sessionHandle, &compiledFilter, filter.c_str(), 0, 0) == -1) {
        pcap_geterr(sessionHandle);
        return EPARSE_FILTER;
    }

    // Set compiled filter above session
    if (pcap_setfilter(sessionHandle, &compiledFilter) == -1) {
        pcap_geterr(sessionHandle);
        return EINSTALL_FILTER;
    }

    ret = listening();              // Finally start listening

    closeSession();                 // Close session whether still opened
    pcap_freecode(&compiledFilter);

    return ret;
}

/**
  * Opens sniffer session.
  * @return True on succes else false.
  */
int Sniffer::openSession() {
    char errbuf[PCAP_ERRBUF_SIZE];

    //sessionHandle = pcap_open_offline("lldp.detailed.pcap", errbuf);
    sessionHandle = pcap_open_live(interface.c_str(), BUFSIZ, 1, 1000, errbuf);

    if (sessionHandle == NULL) {    // session not opened
        cerr << errbuf << endl;
        return EOPEN_DEVICE;
    }

    return 0;
}

/**
  * Closes opened session whether exists.
  */
void Sniffer::closeSession() {
    if (sessionHandle) {
        pcap_close(sessionHandle);
        sessionHandle = NULL;
    }
}

/**
  * Stops listening on sniffer interface.
  */
void Sniffer::stopListening() {
    if (sessionHandle) {
        pcap_breakloop(sessionHandle);
    }
}

/** Sends packet on sniffer interface.
  * @param packet Packet which will be sent.
  */
int Sniffer::sendPacket(Packet *packet) {
    int ret;
    int opened = 1;

    if (!sessionHandle) {           // open session whether is not
        opened = 0;
        if ((ret = openSession())) {
            return ret;
        }
    }

    // try inject packet on interface
    if ((pcap_inject(sessionHandle, packet->getData().data, packet->getData().length) == -1)) {
        pcap_geterr(sessionHandle);

        if (!opened) closeSession();// close session whether we opened it

        return EINJECT_PACKET;
    }

    if (!opened) closeSession();    // close session whether we opened it

    return 0;
}
