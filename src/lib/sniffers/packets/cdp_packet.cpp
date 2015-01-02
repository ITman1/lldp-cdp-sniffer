/*******************************************************************************
 * Projekt:         Programování síťové služby: Sniffer CDP a LLDP
 * Jméno:           Radim
 * Příjmení:        Loskot
 * Login autora:    xlosko01
 * E-mail:          xlosko01(at)stud.fit.vutbr.cz
 * Popis:           Modul definujicí třídu CDP paketu.
 *
 ******************************************************************************/

/**
 * @file cdp_packet.cpp
 *
 * @brief Module which defines class of CDP packet.
 * @author Radim Loskot xlosko01(at)stud.fit.vutbr.cz
 */

#include <pcap.h>
#include <iostream>
#include <netinet/in.h>
#include <vector>
#include <cstring>
#include "sysinfo.h"
#include "frames/ethernet_frame.h"
#include "protocols.h"
#include "llc_packet.h"
#include "cdp_packet.h"

class LLCPacket;

using namespace std;

/**
  * Ethernet frame to be sent in example packet
  */
const EthernetFrame::Ethernet CDPPacket::SEND_ETHERNET_FRAME = {
    /* .host = */        {0x01, 0x00, 0x0c, 0xcc, 0xcc, 0xcc},
    /* .destination = */ {0},
    /* .type = */        0
};

/**
  * LLC packet to be sent in example packet.
  */
const LLCPacket::LLC CDPPacket::SEND_LLC_PACKET = {
    /* .DSAP = */              0xaa,
    /* .SSAP = */              0xaa,
    /* .control = */           0x03,
    /* .organizationCode = */  {0x00, 0x00, 0x0c},
    /* .etherType = */         0x0000
};

/**
  * Name of device ID type.
  */
const string CDPPacket::DeviceID::tlv_type_str = "Device ID";

/**
  * Name of addresses type.
  */
const string CDPPacket::Addresses::tlv_type_str = "Addresses";

/**
  * Mapping defined protocol types to string representation.
  */
pair<int, string> Addresses_protocol_types_mapping[] = {
    std::make_pair(CDPPacket::Addresses::NLPID,        "NLPID"),
    std::make_pair(CDPPacket::Addresses::IEEE802_2,    "802.2")
};

/**
  * Initialization of protocol type mapping.
  */
const map<int, string> CDPPacket::Addresses::protocol_types_str(
    Addresses_protocol_types_mapping,
    Addresses_protocol_types_mapping + sizeof Addresses_protocol_types_mapping / sizeof Addresses_protocol_types_mapping[0]);

/**
  * Mapping defined protocols to string representation.
  */
pair<int, string> Addresses_protocols_mapping[] = {
    std::make_pair(CDPPacket::Addresses::IP,    "IP")
};

/**
  * Initialization of protocol mapping.
  */
const map<int, string> CDPPacket::Addresses::protocols_str(
    Addresses_protocols_mapping,
    Addresses_protocols_mapping + sizeof Addresses_protocols_mapping / sizeof Addresses_protocols_mapping[0]);

/**
  * Returns array addresses in string representation.
  * @return Array of address in format "%d address(es) (<addr1>, <addr2>, ...)"
  */
const string CDPPacket::Addresses::getValueStr() {
    Address addr;

    const u_int8_t *value = tlv_value.data;
    int number = ntohl(*(u_int32_t *)value); value += 4;        // getting count of address present in value

    string result;

    result = Data::toStr(number) + " address(es) (";


    while (number) {    // loop until all address are read
        // reading addres - char, char, array, short, array
        addr.protocolType = *value; value++;
        addr.protocolLength = *value; value++;
        memcpy(addr.protocol, value, addr.protocolLength); value += addr.protocolLength;
        addr.addressLength = ntohs(*(u_int16_t *)value); value += 2;
        memcpy(addr.address, value, addr.addressLength); value += addr.addressLength;

        result += addr.toStr() + ", ";
        number--;
    }

    result.erase(result.length() - 2);
    result += ")";
    return result;
}

/**
  * Converts address to string representation.
  * @return String representation of address.
  */
string CDPPacket::Addresses::Address::toStr() {

    // only IP address is supported
    if ((protocolType == NLPID) && (protocolLength == 1)
        && (*protocol == CDPPacket::Addresses::IP) && (addressLength == 4)) {
        return Data::toStr(int(address[0])) + "." + Data::toStr(int(address[1])) + "."
            + Data::toStr(int(address[2])) + "." + Data::toStr(int(address[3]));
    } else {
        return "unknown (hex) - " + Data::arrToHexStr(address, addressLength);
    }
}

/**
  * Name of port ID type.
  */
const string CDPPacket::PortID::tlv_type_str = "Port ID";

/**
  * Name of port capabilities type.
  */
const string CDPPacket::Capabilities::tlv_type_str = "Capabilities";

/**
  * Mapping defined capabilities bits to string representation.
  */
pair<int, string> Capabilities_capabilities_mapping[] = {
    std::make_pair(CDPPacket::Capabilities::router  ,           "router"),
    std::make_pair(CDPPacket::Capabilities::transparentBridge,  "transparent bridge"),
    std::make_pair(CDPPacket::Capabilities::sourceRouteBridge,  "source route bridge"),
    std::make_pair(CDPPacket::Capabilities::switchL2,           "switch"),
    std::make_pair(CDPPacket::Capabilities::host,               "host"),
    std::make_pair(CDPPacket::Capabilities::IGMPCapable,        "IGMP capable"),
    std::make_pair(CDPPacket::Capabilities::repeater,           "repeater")
};

/**
  * Initialization of capabilities mapping.
  */
const map<int, string> CDPPacket::Capabilities::capabilities_str(
    Capabilities_capabilities_mapping,
    Capabilities_capabilities_mapping + sizeof Capabilities_capabilities_mapping / sizeof Capabilities_capabilities_mapping[0]);

/**
  * Returns specified capabilities as a string delimited by comma.
  * @return Capabilities in string representation in format "<cap1>, <cap2>, ..."
  */
const string CDPPacket::Capabilities::getValueStr() {
    const int capabilities = ntohl(*(u_int32_t *)tlv_value.data);

    int mask = 0x00000001;  // test mask
    string result;

    // shifting mask and getting capabilities
    for (int i = 0; i < 32; i++) {
        if (capabilities & mask) {

            if (capabilities_str.find(mask) != capabilities_str.end()) {
                result += capabilities_str.at(mask) + ", ";
            } else { // string for this capability is not defined
                result += "(unknown: " + Data::toStr(i) + ". bit is set), ";
            }

        }
        mask <<= 1;
    }

    result.erase(result.length() - 2);

    return result;
}

/**
  * Name of software version type.
  */
const string CDPPacket::SoftwareVersion::tlv_type_str = "Software version";

/**
  * Name of platform type.
  */
const string CDPPacket::Platform::tlv_type_str = "Platform";

/**
  * Name of duplex type.
  */
const string CDPPacket::Duplex::tlv_type_str = "Duplex";

/**
  * Returns duplex in string represention.
  * @return Duplex "half" or "full".
  */
const string CDPPacket::Duplex::getValueStr() {
    return (*tlv_value.data) ? "full": "half";
}

/**
  * Name of MTU type.
  */
const string CDPPacket::MTU::tlv_type_str = "MTU";

/**
  * Returns numeric value as a string.
  * @return Converted numer number to string.
  */
const string CDPPacket::MTU::getValueStr() {
    const int mtu_value = ntohl(*(u_int32_t *)tlv_value.data);
    return Data::toStr(mtu_value);
}

/**
  * Name of system name type.
  */
const string CDPPacket::SystemName::tlv_type_str = "System name";

/**
  * Checks packet whether is packet of this protocol.
  * @param packet Packet to be verified.
  * @param onSuccessAddProtocol When true then will be added to packet appropriate protocls.
  * @return True/false.
  */
int CDPPacket::isThisProtocol(Packet *packet, bool onSuccessAddProtocol) {
    if (packet->protocols.size() > 0) {

        // Datalink verification - supported only ethernet
        if (packet->protocols.at(DATALINK) == DLT_EN10MB) {
                // LLC layer has to be present
                if (LLCPacket::isThisProtocol(packet, onSuccessAddProtocol)) {
                    // In LLC has to be set ethnernet type/PID to 0x2000
                    if (LLCPacket(packet->getData(), packet->protocols).getHeader().etherType == ETHER_TYPE) {

                        if (onSuccessAddProtocol) { // just adding CDP protocol
                            if (packet->protocols.size() <= LAYER_3) {
                                packet->protocols.push_back(CDP_PROTOCOL);
                            } else {
                                packet->protocols[LAYER_3] = LLC_PROTOCOL;
                            }
                            return 1;
                        }
                    }

                }

        }
    }
    return 0;
}

/**
  * Returns size of CDP packet.
  * @return Size of CDP packet only, or -1 on malformed/bad packet.
  */
int CDPPacket::getSize() const {
    int begin = beginAt();

    if (begin != -1) {
        return data.length - begin - 1;
    }

    return -1;
}

/**
  * Returns start position of CDP packet in data.
  * @return Start position of CDP packet in data, or -1 on malformed/bad packet.
  */
int CDPPacket::beginAt() const {
    Packet packet(data, protocols);

    int size = 0;

    // getting begin depends on specified protocols, here only ethernet and LLC layer supported
    if ((!protocols.empty()) && (protocols.at(DATALINK) == DLT_EN10MB)) {
        size = EthernetFrame(data).getSize();
        if (LLCPacket::isThisProtocol(&packet, false)) {
            size += LLCPacket(data, protocols).getSize();
            return size;
        }
    }

    return -1;
}

/**
  * Returns header od CDP packet.
  * @return Header of CDP packet.
  */
CDPPacket::Header CDPPacket::getHeader() const {
    int begin = beginAt();
    Header header;
    memset(&header, 0, sizeof(header));

    // test that packet is valid
    if ((begin != -1) && (begin + HEADER_SIZE < data.length)) {
        header = *(Header *)&data.data[begin];
        header.checksum = ntohs(header.checksum);   // folding to this architecture
    }

    return header;
}

/**
  * Checks inserted checksum with new one calculated.
  * @return Result of checksum check.
  */
int CDPPacket::testCheckSum() const {
    Header header;
    int begin = beginAt(), result;

    if ((begin != -1) && (begin + HEADER_SIZE < data.length)) {
        // backup header
        header = getHeader();
        // setting checksum field to zero before checksum calculation
        *(u_int16_t *)const_cast<u_int8_t *>(&data.data[begin + CHECKSUM_OFFSET]) = 0;
        // calculating checksum and test
        result = Data::checksum(data, begin) == header.checksum;
        // restoring checksum
        *(u_int16_t *)const_cast<u_int8_t *>(&data.data[begin + CHECKSUM_OFFSET]) = header.checksum;
        return result;
    }
    return 0;
}

/**
  * Returns array of TLV objects generated from corresponding data of CDP packet.
  * @return Array of TLV objects.
  * @see TLV
  */
TLVs CDPPacket::readPacket() const {
    TLVs tlvs;
    TLV *tlv = 0;
    Data tlv_data;
    int type = 0, length = 0;
    int position = beginAt() + HEADER_SIZE; // begin position

    if (position > 0) {
        while (position + 3 < data.length) { // type and length is on 4 octets
            type = ntohs(data.readUShort(position));
            length = ntohs(data.readUShort(position + 2));
            tlv = 0;

            // value cannont exceed the end
            if ((position + length > data.length) || (length < TL_SIZE)) {
                break;
            }

            if (length) {   // there is some value
                // getting value data
                tlv_data = Data(&data.data[position + TL_SIZE], length - TL_SIZE);

                switch (type) { // switching types of data
                    case deviceID:
                        tlv = new DeviceID(tlv_data);
                        break;
                    case addresses:
                        tlv = new Addresses(tlv_data);
                        break;
                    case portID:
                        tlv = new PortID(tlv_data);
                        break;
                    case capabilities:
                        tlv = new Capabilities(tlv_data);
                        break;
                    case softwareVersion:
                        tlv = new SoftwareVersion(tlv_data);
                        break;
                    case platform:
                        tlv = new Platform(tlv_data);
                        break;
                    case duplex:
                        tlv = new Duplex(tlv_data);
                        break;
                    case mtu:
                        tlv = new MTU(tlv_data);
                        break;
                    case systemName:
                        tlv = new SystemName(tlv_data);
                        break;
                }
            }

            if (tlv) {          // if new TLV object is created, push it into array
                tlvs.push_back(tlv);
            }

            position += length; // move position to the start of next TLV
        }
    }

    return tlvs;    // return array of TLV objects
}

/**
  * Appends new type-length-value data to packet.
  * @param tlv New TLV to be appended to packet.
  * @param packet Packet where TLV will be appended.
  */
void CDPPacket::appendTLV(TLV &tlv, vector<u_int8_t> &packet) {
    u_int16_t type, length;

    // appending type
    type = htons(tlv.tlv_type);
    packet.insert(packet.end(), (u_int8_t *)&type, (u_int8_t *)&type + sizeof(u_int16_t));

    // appending length
    length = htons(TL_SIZE + tlv.getValue().length);
    packet.insert(packet.end(), (u_int8_t *)&length, (u_int8_t *)&length + sizeof(u_int16_t));

    // appending value
    packet.insert(packet.end(), tlv.getValue().data, tlv.getValue().data +tlv.getValue().length);
}

/**
  * Generates packet example protocol packet to be sent on interface.
  * @param packet Packet where generated CDP packet is stored.
  * @param interface Which interface should be present inside example packet.
  * @param ttl Which time to live value should be present inside packet.
  * @return True/false which signs success of creating packet.
  */
int CDPPacket::generateDevicePacket(CDPPacket &packet, string interface, int ttl) {
    string computerName, description;
    u_int32_t availableCapabilities;
    MACAddress mac;
    TLV tlv;
    Header header;
    EthernetFrame::Ethernet ethernetHeader = SEND_ETHERNET_FRAME;
    LLCPacket::LLC llcHeader = SEND_LLC_PACKET;
    vector<u_int8_t> cdpPacket;

    // CREATING DATALINK LAYER/HEADER

    // retrieving source MAC address
    if (!MACAddress::getInterfaceMACAddress(interface, mac)) {
        return 1;
    }
    // adding source mac to tmp structure
    memcpy(ethernetHeader.source, mac.mac, MACAddress::MAC_ADDRESS_SIZE);

    // CREATING CDP LAYER
    
    // creating CDP header
    header.version = 0x02;
    header.timeToLive = ttl;
    header.checksum = 0x0000;
    
    // adding CDP header
    cdpPacket.insert( cdpPacket.end(), (u_int8_t *)&header, ((u_int8_t *)&header) + sizeof(Header));

    // device ID will be appended
    tlv.tlv_type = deviceID;
    computerName = System::getSystemInfo().nodename;
    tlv.setValue(Data((u_int8_t *)computerName.c_str(), computerName.length()));
    appendTLV(tlv, cdpPacket);

    // software version will be appended
    tlv.tlv_type = softwareVersion;
    description = System::getSystemDescription();
    tlv.setValue(Data((u_int8_t *)description.c_str(), description.length()));
    appendTLV(tlv, cdpPacket);

    // platform will be appended
    tlv.tlv_type = platform;
    description = System::getSystemInfo().sysname + " " + System::getSystemInfo().machine;
    tlv.setValue(Data((u_int8_t *)description.c_str(), description.length()));
    appendTLV(tlv, cdpPacket);

    // port ID will be appended
    tlv.tlv_type = portID;
    tlv.setValue(Data((u_int8_t *)interface.c_str(), interface.length()));
    appendTLV(tlv, cdpPacket);

    // capabilities will be appended
    tlv.tlv_type = capabilities;
    availableCapabilities = htonl(Capabilities::router);
    tlv.setValue(Data((u_int8_t *)&availableCapabilities, sizeof(availableCapabilities)));
    appendTLV(tlv, cdpPacket);

    // ADDING LAYERS TO PACKET
    
    // adding ethernet header to packet
    packet.protocols.push_back(DLT_EN10MB);
    ethernetHeader.type = htons(sizeof(LLCPacket::LLC) + cdpPacket.size());
    packet.appendData(Data((u_int8_t *)&ethernetHeader, sizeof(EthernetFrame::Ethernet)));
    
    // adding LLC header to packet
    packet.protocols.push_back(LLC_PROTOCOL);
    llcHeader.etherType = htons(CDPPacket::ETHER_TYPE);
    packet.appendData(Data((u_int8_t *)&llcHeader, sizeof(LLCPacket::LLC)));
    
    // adding CDP packet
    *(u_int16_t *)&cdpPacket[CHECKSUM_OFFSET] = htons(Data::checksum(Data(cdpPacket.data(), cdpPacket.size()), 0));
    packet.protocols.push_back(CDP_PROTOCOL);
    packet.appendData(Data(cdpPacket.data(), cdpPacket.size()));

    return 0;
}
