/*******************************************************************************
 * Projekt:         Programování síťové služby: Sniffer CDP a LLDP
 * Jméno:           Radim
 * Příjmení:        Loskot
 * Login autora:    xlosko01
 * E-mail:          xlosko01(at)stud.fit.vutbr.cz
 * Popis:           Modul definující třídu LLDP paketu.
 *
 ******************************************************************************/

/**
 * @file lldp_packet.cpp
 *
 * @brief Module which defines class of LLDP packet.
 * @author Radim Loskot xlosko01(at)stud.fit.vutbr.cz
 */

#include <iostream>
#include <map>
#include <cstring>
#include <pcap.h>
#include <netinet/in.h>
#include <sys/param.h>
#include "frames/ethernet_frame.h"
#include "protocols.h"
#include "lldp_packet.h"
#include "sysinfo.h"

using namespace std;

/**
  * Ethernet frame to be sent in generated packet.
  */
const EthernetFrame::Ethernet LLDPPacket::SEND_ETHERNET_FRAME = {
       /* .host = */        {0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e},
       /* .destination = */ {0},
       /* .type = */        0
};

/**
  * TLV of the end of LLPD packet.
  */
const u_int8_t LLDPPacket::END_OF_LLDPDU[LLDPPacket::END_OF_LLDPDU_SIZE] = {0x00, 0x00};

/**
  * Name of chassis ID type.
  */
const string LLDPPacket::ChassisID::tlv_type_str = "Chassis ID";

/**
  * Mapping defined chassis ID subtypes to string representation.
  */
pair<int, string> ChassisID_subtypes_mapping[] = {
    std::make_pair(LLDPPacket::ChassisID::chassisComponent, "Interface alias"),
    std::make_pair(LLDPPacket::ChassisID::interfaceAlias, "Interface alias"),
    std::make_pair(LLDPPacket::ChassisID::portComponent, "Port component"),
    std::make_pair(LLDPPacket::ChassisID::macAddress, "MAC address"),
    std::make_pair(LLDPPacket::ChassisID::networkAddress, "Network address"),
    std::make_pair(LLDPPacket::ChassisID::interfaceName, "Interface name"),
    std::make_pair(LLDPPacket::ChassisID::agentCircuitID, "Agent circuit ID"),
    std::make_pair(LLDPPacket::ChassisID::locallyAssigned, "Locally assigned")
};

/**
  * Initialization of chassis ID subtype mapping.
  */
const map<int, string> LLDPPacket::ChassisID::subtypes_str(
    ChassisID_subtypes_mapping,
    ChassisID_subtypes_mapping + sizeof ChassisID_subtypes_mapping / sizeof ChassisID_subtypes_mapping[0]);

/**
  * Constructor which parses subtype and value.
  */
LLDPPacket::ChassisID::ChassisID(const Data &data) {
    int subtype = data.readUChar(0);
    Data afterSubType(&data.data[1], data.length - 1);
    setValue(afterSubType, subtype);
}

/**
  * Returns name of chassis ID subtype.
  * @return Subtype name of chassis ID
  */
string LLDPPacket::ChassisID::getSubTypeName() {
    string value = "unknown";
    if (tlv_subType > -1) {
        // Test whether has this subtype string represation
        if (subtypes_str.find(tlv_subType) != subtypes_str.end()) {
            value = subtypes_str.at(tlv_subType);
        }
    }
    return value;
}

/**
  * Returns converted variant value in string representation.
  * @return Value of specified subtype as a string
  */
const string LLDPPacket::ChassisID::getValueStr() {
    switch (tlv_subType) {
    case macAddress:    // MAC represation
        return MACAddress(tlv_value.data).toStr();

    case interfaceAlias: case interfaceName: // string represation
        return TLV::getValueStr();
    default: // unsupported subtype
        return "unknown (hex) - " + Data::arrToHexStr(tlv_value.data, tlv_value.length);
    }
}

/**
  * Name of chassis ID type.
  */
const string LLDPPacket::PortID::tlv_type_str = "Port ID";

/**
  * Mapping defined port ID subtypes to string representation.
  */
pair<int, string> PortID_subtypes_mapping[] = {
    std::make_pair(LLDPPacket::PortID::interfaceAlias, "Interface alias"),
    std::make_pair(LLDPPacket::PortID::portComponent,  "Port component"),
    std::make_pair(LLDPPacket::PortID::macAddress,     "MAC address"),
    std::make_pair(LLDPPacket::PortID::networkAddress, "Network address"),
    std::make_pair(LLDPPacket::PortID::interfaceName,  "Interface name"),
    std::make_pair(LLDPPacket::PortID::agentCircuitID, "Agent circuit ID"),
    std::make_pair(LLDPPacket::PortID::locallyAssigned,"Locally assigned")
};

/**
  * Initialization of port ID subtype mapping.
  */
const map<int, string> LLDPPacket::PortID::subtypes_str(
    PortID_subtypes_mapping,
    PortID_subtypes_mapping + sizeof PortID_subtypes_mapping / sizeof PortID_subtypes_mapping[0]);

/**
  * Constructor which parses subtype and value.
  */
LLDPPacket::PortID::PortID(const Data &data) {
    int subtype = data.readUChar(0);
    Data afterSubType(&data.data[1], data.length - 1);
    setValue(afterSubType, subtype);
}

/**
  * Returns name of port ID subtype.
  * @return Subtype name of port ID
  */
string LLDPPacket::PortID::getSubTypeName() {
    string value = "unknown";
    if (tlv_subType > -1) {
        // Test whether has this subtype string represation
        if (subtypes_str.find(tlv_subType) != subtypes_str.end()) {
            value = subtypes_str.at(tlv_subType);
        }
    }
    return value;
}

/**
  * Returns converted variant value in string representation.
  * @return Value of specified subtype as a string
  */
const string LLDPPacket::PortID::getValueStr() {
    switch (tlv_subType) {
    case macAddress: // MAC representation
        return MACAddress(tlv_value.data).toStr();

    case interfaceAlias: case interfaceName: // string representation
        return TLV::getValueStr();
    default:// unsupported subtype
        return "unknown (hex) - " + Data::arrToHexStr(tlv_value.data, tlv_value.length);
    }
}

/**
  * Name of time to live type.
  */
const string LLDPPacket::TimeToLive::tlv_type_str = "Time To Live";

/**
  * Converts TTL number to string.
  * @return TTL number as a string
  */
const string LLDPPacket::TimeToLive::getValueStr() {
    return Data::toStr(ntohs(*(u_int16_t *) tlv_value.data))  + " s";
}

/**
  * Name of port description type.
  */
const string LLDPPacket::PortDescription::tlv_type_str = "Port description";

/**
  * Name of system name type.
  */
const string LLDPPacket::SystemName::tlv_type_str = "System name";

/**
  * Name of system description type.
  */
const string LLDPPacket::SystemDescription::tlv_type_str = "System description";

/**
  * Name of system capabilities type.
  */
const string LLDPPacket::SystemCapabilities::tlv_type_str = "System capabilities";

/**
  * Mapping defined capabilities bits to string representation.
  */
pair<int, string> SystemCapabilities_capabilities_mapping[] = {
    std::make_pair(LLDPPacket::SystemCapabilities::other,            "(other)"),
    std::make_pair(LLDPPacket::SystemCapabilities::repeater,         "repeater"),
    std::make_pair(LLDPPacket::SystemCapabilities::MACBridge,        "MAC bridge"),
    std::make_pair(LLDPPacket::SystemCapabilities::WLANAccessPoint,  "WLAN access point"),
    std::make_pair(LLDPPacket::SystemCapabilities::router,           "router"),
    std::make_pair(LLDPPacket::SystemCapabilities::telephone,        "telephone"),
    std::make_pair(LLDPPacket::SystemCapabilities::DOCSISCableDevice,"DOCSIS cable device"),
    std::make_pair(LLDPPacket::SystemCapabilities::stationOnly,      "station only"),
    std::make_pair(LLDPPacket::SystemCapabilities::CVLANofVLAN,      "C-VLAN Component of a VLAN Bridge"),
    std::make_pair(LLDPPacket::SystemCapabilities::SVLANofVLAN,      "S-VLAN Component of a VLAN Bridge"),
    std::make_pair(LLDPPacket::SystemCapabilities::TMPR,             "two-port MAC Relay (TPMR)"),
    std::make_pair(LLDPPacket::SystemCapabilities::reserved_1,       "(unknown: 11. bit is set)"),
    std::make_pair(LLDPPacket::SystemCapabilities::reserved_2,       "(unknown: 12. bit is set)"),
    std::make_pair(LLDPPacket::SystemCapabilities::reserved_3,       "(unknown: 13. bit is set)"),
    std::make_pair(LLDPPacket::SystemCapabilities::reserved_4,       "(unknown: 14. bit is set)"),
    std::make_pair(LLDPPacket::SystemCapabilities::reserved_5,       "(unknown: 15. bit is set)")
};

/**
  * Initialization of capabilities mapping.
  */
const map<int, string> LLDPPacket::SystemCapabilities::capabilities_str(
    SystemCapabilities_capabilities_mapping,
    SystemCapabilities_capabilities_mapping + sizeof SystemCapabilities_capabilities_mapping / sizeof SystemCapabilities_capabilities_mapping[0]);

/**
  * Returns specified capabilities and enabled capabilitis as a string delimited by commas.
  * @return Capabilities in string representation in format "<cap1>, <cap2>, ... (enabled: <cap1>, <cap2>, ...)"
  */
const string LLDPPacket::SystemCapabilities::getValueStr() {
    const int capabilities = ntohs(*(u_int16_t *)tlv_value.data);
    const int enabled = ntohs(*(u_int16_t *)&tlv_value.data[2]);

    u_int16_t mask = 0x0001; // test mask
    string result;

    // shifting mask and getting capabilities
    for (int i = 0; i < 16; i++) {
        if (capabilities & mask) {
            // defined is whole range, there no way,
            // that mask would not be defined in mapping array
            result += capabilities_str.at(mask) + ", ";
        }
        mask <<= 1;
    }

    result.erase(result.length() - 2); // deleting last comma

    // now getting enabled capabilities
    if (enabled > 0) {
        result += " (enabled: ";
        mask = 0x0001;
        // shifting mask and getting enabled capabilities
        for (int i = 0; i < 16; i++) {
            if (enabled & mask) {
                result += capabilities_str.at(mask) + ", ";
            }
            mask <<= 1;
        }
        result.erase(result.length() - 2); // deleting last comma
        result += ")";
    }
    return result;
}

/**
  * Name of chassis ID type.
  * http://www.iana.org/assignments/address-family-numbers/address-family-numbers.xml
  */
const string LLDPPacket::ManagementAddress::tlv_type_str = "Management address";

/**
  * Mapping defined chassis ID subtypes to string representation.
  */
pair<int, string> ManagementAddress_subtypes_mapping[] = {
    std::make_pair(LLDPPacket::ManagementAddress::IPv4, "IPv4"),
    std::make_pair(LLDPPacket::ManagementAddress::IPv6, "IPv6"),
    std::make_pair(LLDPPacket::ManagementAddress::NSAP, "NSAP"),
    std::make_pair(LLDPPacket::ManagementAddress::HDLC, "HDLC"),
    std::make_pair(LLDPPacket::ManagementAddress::BBN_1822, "BBN 1822"),
    std::make_pair(LLDPPacket::ManagementAddress::all802, "all 802"),
    std::make_pair(LLDPPacket::ManagementAddress::E_163, "E.163"),
    std::make_pair(LLDPPacket::ManagementAddress::E_164, "E.164"),
    std::make_pair(LLDPPacket::ManagementAddress::F_69, "F.69"),
    std::make_pair(LLDPPacket::ManagementAddress::X_121, "X.121"),
    std::make_pair(LLDPPacket::ManagementAddress::IPX, "IPX"),
    std::make_pair(LLDPPacket::ManagementAddress::appleTalk, "Appletalk"),
    std::make_pair(LLDPPacket::ManagementAddress::decnetIV, "Decnet IV"),
    std::make_pair(LLDPPacket::ManagementAddress::banyanVines, "Banyan Vines"),
    std::make_pair(LLDPPacket::ManagementAddress::E_164_NSAP, "E.164 with NSAP format subaddress"),
    std::make_pair(LLDPPacket::ManagementAddress::DNS, "DNS")
};

/**
  * Initialization of chassis ID subtype mapping.
  */
const map<int, string> LLDPPacket::ManagementAddress::subtypes_str(
    ManagementAddress_subtypes_mapping,
    ManagementAddress_subtypes_mapping + sizeof ManagementAddress_subtypes_mapping / sizeof ManagementAddress_subtypes_mapping[0]);

/**
  * Mapping defined chassis ID subtypes to string representation.
  */
pair<int, string> ManagementAddress_interfaceNumeringSubtype_str_mapping[] = {
    std::make_pair(LLDPPacket::ManagementAddress::unknown, "unknown"),
    std::make_pair(LLDPPacket::ManagementAddress::ifIndex, "ifIndex"),
    std::make_pair(LLDPPacket::ManagementAddress::systemPortNumer, "system port number")
};

/**
  * Initialization of chassis ID subtype mapping.
  */
const map<int, string> LLDPPacket::ManagementAddress::interfaceNumeringSubtype_str (
    ManagementAddress_interfaceNumeringSubtype_str_mapping,
    ManagementAddress_interfaceNumeringSubtype_str_mapping + sizeof ManagementAddress_interfaceNumeringSubtype_str_mapping / sizeof ManagementAddress_interfaceNumeringSubtype_str_mapping[0]);


/**
  * Constructor which parses subtype and value.
  */
LLDPPacket::ManagementAddress::ManagementAddress(const Data &data) {
    int subtype = data.readUChar(1);
    setValue(data, subtype);   // saving everything
}

/**
  * Returns name of management address subtype.
  * @return Subtype name of management address
  */
string LLDPPacket::ManagementAddress::getSubTypeName() {
    string value = "unknown";
    if (tlv_subType > -1) {
        // Test whether has this subtype string represation
        if (subtypes_str.find(tlv_subType) != subtypes_str.end()) {
            value = subtypes_str.at(tlv_subType);
        }
    }
    return value;
}

/**
  * Returns converted variant value in string representation.
  * @return Value of specified subtype as a string
  */
const string LLDPPacket::ManagementAddress::getValueStr() {
    const u_int8_t *value = tlv_value.data;
    u_int8_t mngAddrLen = *value++;
    u_int8_t subType = *value++;
    const u_int8_t *addr = value;
    string result;

    switch (subType) {
    case IPv4:    // IPv4 represation
        result = Data::toStr(int(addr[0])) + "." + Data::toStr(int(addr[1])) + "."
            + Data::toStr(int(addr[2])) + "." + Data::toStr(int(addr[3]));
        break;
    case all802: // MAC represation
        result = MACAddress(addr).toStr();
        break;
    default: // unsupported subtype
        result = "unknown (hex) - " + Data::arrToHexStr(tlv_value.data, tlv_value.length);
        break;
    }

    value += mngAddrLen - 1;
    result += " (";

        // Test whether has this interface numbering subtype string represation
    if (interfaceNumeringSubtype_str.find(*value) != interfaceNumeringSubtype_str.end()) {
        result += interfaceNumeringSubtype_str.at(*value);
    } else {
        result += "unknown";
    }

    value++;

    result += ": " + Data::toStr(ntohl(*(u_int32_t *)value)) + ")";

    return result;

}

/**
  * Checks packet whether is packet of this protocol.
  * @param packet Packet to be verified.
  * @param onSuccessAddProtocol When true then will be added to packet appropriate protocls.
  * @return True/false.
  */
int LLDPPacket::isThisProtocol(Packet *packet, bool onSuccessAddProtocol) {
    if (packet->protocols.size() > 0) {
        // LLDP on ethernet datalink only
        if (packet->protocols.at(DATALINK) == DLT_EN10MB) {
            // type of ethernet has to be set to 0x00cc
            if (EthernetFrame(packet->getData()).getFrame().type == ETHER_TYPE) {
                // adding LLDP protocol
                if (onSuccessAddProtocol) {
                    if (packet->protocols.size() <= LAYER_2) {
                        packet->protocols.push_back(LLDP_PROTOCOL);
                    } else {
                        packet->protocols[LAYER_2] = LLDP_PROTOCOL;
                    }
                }
                return 1;
            }
        }
    }
    return 0;
}

/**
  * Returns size of LLDP packet.
  * @return Size of LLDP packet only, or -1 on malformed/bad packet.
  */
int LLDPPacket::getSize() const {
    int begin = beginAt();
    if (begin != -1) {
        return data.length - begin - 1;
    }
    return -1;
}

/**
  * Returns start position of LLDP packet in data.
  * @return Start position of LLDP packet in data, or -1 on malformed/bad packet.
  */
int LLDPPacket::beginAt() const {

    // supported only ethernet datalink
    if ((!protocols.empty()) && (protocols.at(DATALINK) == DLT_EN10MB)) {
        return EthernetFrame(data).getSize(); // LLDP starts where ethernet ends
    }

    return -1;
}

/**
  * Returns array of TLV objects generated from corresponding data of LLDP packet.
  * @return Array of TLV objects.
  * @see TLV
  */
TLVs LLDPPacket::readPacket() const {
    TLVs tlvs;
    TLV *tlv = 0;
    Data tlv_data;
    int type = 0, length = 0;
    int position = beginAt();   // getting start position of TLV structures

    if (position > 0) {
        while (position + 1 < data.length) { // type-length items on 2 octets
            type = data.readUChar(position, 0, 7);      // type is on 7 bits
            length = data.readUShort(position, 7, 9);   // length is on 8 bits
            tlv = 0;

            // test whether length of TLV does not exceed the end of packet
            if (position + TL_SIZE + length >= data.length) {
                break;
            }

            // test whether is end of packet
            if (type == endOfLLPDU) {
                break;
            }

            if (length) {   // there are some data
                // getting data
                tlv_data = Data(&data.data[position + TL_SIZE], length);
                switch (type) { // switching types of data
                    case chassisID:
                        tlv = new ChassisID(tlv_data);
                        break;
                    case portID:
                        tlv = new PortID(tlv_data);
                        break;
                    case timeToLive:
                        tlv = new TimeToLive(tlv_data);
                        break;
                    case portDescription:
                        tlv = new PortDescription(tlv_data);
                        break;
                    case systemName:
                        tlv = new SystemName(tlv_data);
                        break;
                    case systemDescription:
                        tlv = new SystemDescription(tlv_data);
                        break;
                    case systemCapabilities:
                        tlv = new SystemCapabilities(tlv_data);
                        break;
                    case managementAddress:
                        tlv = new ManagementAddress(tlv_data);
                        break;
                }
            }

            if (tlv) {                    // if new TLV object is created, push it into array
                tlvs.push_back(tlv);
            }

            position += length + TL_SIZE; // move position to the start of next TLV
        }
    }

    return tlvs;
}

/**
  * Appends new type-length-value data to packet.
  * @param tlv New TLV to be appended to packet.
  * @param packet Packet where TLV will be appended.
  */
void LLDPPacket::appendTLV(TLV &tlv, LLDPPacket &packet) {
    int isSubtype = tlv.getSubType() != -1;
    int subType = tlv.getSubType();
    u_int16_t tl = htons((((tlv.tlv_type) << 9) |                    // offseting type to first octet - trimmed to only 7 bit
                 ((tlv.getValue().length + isSubtype) & 0x01FF))); // bitwise OR of 9 bit length - also trimmed by mask

    // appending type-length items to packet
    packet.appendData(Data((u_int8_t *)&tl, sizeof(u_int16_t)));
    if (isSubtype) {    // appending subtype whether is defined
        packet.appendData(Data((u_int8_t *)&subType, sizeof(u_int8_t)));
    }

    // appending data
    packet.appendData(tlv.getValue());
}

/**
  * Generates packet example protocol packet to be sent on interface.
  * @param packet Packet where generated LLDP packet is stored.
  * @param interface Which interface should be present inside example packet.
  * @param ttl Which time to live value should be present inside packet.
  * @return True/false which signs success of creating packet.
  */
int LLDPPacket::generateDevicePacket(LLDPPacket &packet, string interface, int ttl) {
    EthernetFrame::Ethernet etherneLayer = SEND_ETHERNET_FRAME;
    u_int8_t capabilities[SystemCapabilities::LENGTH];
    string description, sysName;
    MACAddress mac;
    TLV tlv;
    u_int16_t htons_numer;

    // ADDING DATALINK LAYER

    // retrieving source MAC address
    if (!MACAddress::getInterfaceMACAddress(interface, mac)) {
        return 1;
    }
    // adding source mac to tmp structure
    memcpy(etherneLayer.source, mac.mac, MACAddress::MAC_ADDRESS_SIZE);

    // appending data from tmp structure to final packet
    packet.protocols.push_back(DLT_EN10MB);
    etherneLayer.type = htons(ETHER_TYPE);
    packet.appendData(Data((u_int8_t *)&etherneLayer, sizeof(EthernetFrame::Ethernet)));

    // CREATING LLDP LAYER

    tlv.tlv_type = chassisID;  // chassisID => MACAddress
    tlv.setValue(Data(mac.mac, MACAddress::MAC_ADDRESS_SIZE), ChassisID::macAddress);
    appendTLV(tlv, packet);

    tlv.tlv_type = portID;     // portID => interfaceName
    tlv.setValue(Data((u_int8_t *)interface.c_str(), interface.length()), PortID::interfaceName);
    appendTLV(tlv, packet);

    tlv.tlv_type = timeToLive; // TTL
    ttl = htons(ttl);
    tlv.setValue(Data((u_int8_t *)&ttl, sizeof(u_int16_t)));
    appendTLV(tlv, packet);

    tlv.tlv_type = systemName;            // System Name
    sysName = System::getSystemInfo().nodename;
    tlv.setValue(Data((u_int8_t *)sysName.c_str(), sysName.length()));
    appendTLV(tlv, packet);

    tlv.tlv_type = systemDescription;     // System Description
    description = System::getSystemDescription();
    tlv.setValue(Data((u_int8_t *)description.c_str(), description.length()));
    appendTLV(tlv, packet);

    tlv.tlv_type = systemCapabilities;    // System Capabilities

    htons_numer = htons(SystemCapabilities::router);
    memcpy((u_int16_t *)capabilities, &htons_numer, sizeof(uint16_t));
    memcpy((u_int16_t *)&capabilities[sizeof(uint16_t)], &htons_numer, sizeof(uint16_t));
    tlv.setValue(Data(capabilities, SystemCapabilities::LENGTH));
    appendTLV(tlv, packet);

    // appending end of LLDP packet
    packet.appendData(Data(END_OF_LLDPDU, END_OF_LLDPDU_SIZE));

    return 0;
}
