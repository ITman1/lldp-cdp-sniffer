/*******************************************************************************
 * Projekt:         Programování síťové služby: Sniffer CDP a LLDP
 * Jméno:           Radim
 * Příjmení:        Loskot
 * Login autora:    xlosko01
 * E-mail:          xlosko01(at)stud.fit.vutbr.cz
 * Popis:           Hlavičkový soubor daklarující třídu LLDP paketu.
 *
 ******************************************************************************/

/**
 * @file lldp_packet.h
 *
 * @brief Header file which declares class of LLDP packet.
 * @author Radim Loskot xlosko01(at)stud.fit.vutbr.cz
 */

#ifndef LLDP_PACKET_H
#define LLDP_PACKET_H

#include <string>
#include <map>
#include <vector>
#include "packet.h"
#include "tlv.h"
#include "frames/ethernet_frame.h"

using namespace std;

/**
  * Class of LLDP packet
  */
class LLDPPacket: public Packet {
public:

    static const int ETHER_TYPE = 0x88CC;       /**< Ethernet type for LLDP packet */
    static const int TL_SIZE = 2;               /**< Size of type-value items */
    static const int MAX_VALUE_SIZE = 256;      /**< Max size of value item */

    /**
      * Enumeration of all TLV types of LLDP packet with correspond value in packet
      */
    enum TLV_types {
        endOfLLPDU             = 0,
        chassisID              = 1,
        portID                 = 2,
        timeToLive             = 3,
        portDescription        = 4,
        systemName             = 5,
        systemDescription      = 6,
        systemCapabilities     = 7,
        managementAddress      = 8
    };

    /**
      * Class of chassis ID value.
      * Value is variant and depends on subtype.
      * @see TLV
      */
    class ChassisID :public TLV {

    public:
        /**
          * Enum of all subtypes of chassis ID
          */
        enum subtypes {
            chassisComponent   = 1,
            interfaceAlias     = 2,
            portComponent      = 3,
            macAddress         = 4,
            networkAddress     = 5,
            interfaceName      = 6,
            agentCircuitID     = 7,
            locallyAssigned    = 8
        };

        /**
          * Constructor which parses subtype and value.
          */
        ChassisID(const Data &data);
        /**
         * @todo Pass pointer to static tlv_type_str into Base via contructor.
         *       In Base class create/change attribute tlv_type_str to pointer.
         *       see also CDPPacket::DevideID::getTypeName()
         */
        virtual string getTypeName() { return tlv_type_str; }

        /**
          * Returns name of chassis ID subtype.
          * @return Subtype name of chassis ID
          * @todo the same problem like with the method getTypeName()
          */
        virtual string getSubTypeName();

        /**
          * Returns converted variant value in string representation.
          * @return Value of specified subtype as a string
          */
        virtual const string getValueStr();

        const static int tlv_type  = LLDPPacket::managementAddress;
        const static string tlv_type_str;
        const static map<int, string> subtypes_str;
    };

    /**
      * Class of port ID value.
      * Value is variant and depends on subtype.
      * @see TLV
      */
    class PortID :public TLV {
    public:
        /**
          * Enum of all subtypes of port ID
          */
        enum subtypes {
            interfaceAlias     = 1,
            portComponent      = 2,
            macAddress         = 3,
            networkAddress     = 4,
            interfaceName      = 5,
            agentCircuitID     = 6,
            locallyAssigned    = 7
        };

        /**
          * Constructor which parses subtype and value.
          */
        PortID(const Data &data);
        virtual string getTypeName() { return tlv_type_str; }

        /**
          * Returns name of port ID subtype.
          * @return Subtype name of port ID
          */
        virtual string getSubTypeName();

        /**
          * Returns converted variant value in string representation.
          * @return Value of specified subtype as a string
          */
        virtual const string getValueStr();

        const static int tlv_type  = LLDPPacket::portID;
        const static string tlv_type_str;
        const static map<int, string> subtypes_str;
    };

    /**
      * Class of time to live value.
      * Value is numeric.
      * @see TLV
      */
    class TimeToLive :public TLV {
    public:
        TimeToLive(const Data &data) :TLV(data) {}
        virtual string getTypeName() { return tlv_type_str; }

        /**
          * Converts TTL number to string.
          * @return TTL number as a string
          */
        virtual const string getValueStr();

        const static int tlv_type  = LLDPPacket::timeToLive;
        const static string tlv_type_str;
    };

    /**
      * Class of port description.
      * Value is string.
      * @see TLV
      */
    class PortDescription :public TLV {
    public:
        PortDescription(const Data &data) :TLV(data) {}
        virtual string getTypeName() { return tlv_type_str; }

        const static int tlv_type  = LLDPPacket::portDescription;
        const static string tlv_type_str;
    };

    /**
      * Class of system name.
      * Value is string.
      * @see TLV
      */
    class SystemName :public TLV {
    public:
        SystemName(const Data &data) :TLV(data) {}
        virtual string getTypeName() { return tlv_type_str; }

        const static int tlv_type  = LLDPPacket::systemName;
        const static string tlv_type_str;
    };

    /**
      * Class of system description.
      * Value is string.
      * @see TLV
      */
    class SystemDescription :public TLV {
    public:
        SystemDescription(const Data &data) :TLV(data) {}
        virtual string getTypeName() { return tlv_type_str; }

        const static int tlv_type  = LLDPPacket::systemDescription;
        const static string tlv_type_str;
    };

    /**
      * Class of capabilities value.
      * Value is bit array.
      * @see TLV
      */
    class SystemCapabilities :public TLV {
    public:
        const static int LENGTH = 4;        /**< Length of value */

        /**
          * Enum of implemented capabilities
          */
        enum capabilities {
            other               = 0x0001,
            repeater            = 0x0002,
            MACBridge           = 0x0004,
            WLANAccessPoint     = 0x0008,
            router              = 0x0010,
            telephone           = 0x0020,
            DOCSISCableDevice   = 0x0040,
            stationOnly         = 0x0080,
            CVLANofVLAN         = 0x0100,
            SVLANofVLAN         = 0x0200,
            TMPR                = 0x0400,
            reserved_1          = 0x0800,
            reserved_2          = 0x1000,
            reserved_3          = 0x2000,
            reserved_4          = 0x4000,
            reserved_5          = 0x8000
        };

        SystemCapabilities(const Data &data) :TLV(data) {}
        virtual string getTypeName() { return tlv_type_str; }

        /**
          * Returns specified capabilities and enabled capabilitis as a string delimited by commas.
          * @return Capabilities in string representation in format "<cap1>, <cap2>, ... (enabled: <cap1>, <cap2>, ...)"
          */
        virtual const string getValueStr();

        const static int tlv_type = LLDPPacket::systemCapabilities;
        const static string tlv_type_str;
        const static map<int, string> capabilities_str;
    };

    /**
      * Class of management address value.
      * Value address structure.
      * @see TLV
      */
    class ManagementAddress :public TLV {
    public:

        /**
          * Enum of implemented address subtypes
          * http://www.iana.org/assignments/address-family-numbers/address-family-numbers.xml
          */
        enum subtypes {
            IPv4                = 0x01,
            IPv6                = 0x02,
            NSAP                = 0x03,
            HDLC                = 0x04,
            BBN_1822            = 0x05,
            all802              = 0x06,
            E_163               = 0x07,
            E_164               = 0x08,
            F_69                = 0x09,
            X_121               = 0x0A,
            IPX                 = 0x0B,
            appleTalk           = 0x0C,
            decnetIV            = 0x0D,
            banyanVines         = 0x0E,
            E_164_NSAP          = 0x0F,
            DNS                 = 0x10
            // and other
        };

        /**
          * Enum of implemented interface numbering subtypes
          */
        enum interfaceNumeringSubtype {
            unknown             = 0x01,
            ifIndex             = 0x02,
            systemPortNumer     = 0x03
        };

        /**
          * Constructor which parses subtype and value.
          */
        ManagementAddress(const Data &data);
        virtual string getTypeName() { return tlv_type_str; }

        /**
          * Returns address as a string.
          * @return Capabilities in string representation in format "<cap1>, <cap2>, ... (enabled: <cap1>, <cap2>, ...)"
          */
        virtual const string getValueStr();

        /**
          * Returns name of management address subtype.
          * @return Subtype name of management address
          */
        string getSubTypeName();

        const static int tlv_type = LLDPPacket::managementAddress;
        const static string tlv_type_str;
        const static map<int, string> subtypes_str;
        const static map<int, string> interfaceNumeringSubtype_str;
    };

    /**
      * Constructor of LLDP packet from data and protocols from which is made out.
      * @todo protocols has to be specified, more correct would be auto recognition by
      *   static isThisProtocol function
      * @param data Source data of this packet.
      * @param protocols Protocols from which is made out this packet. (remove in future)
      */
    LLDPPacket(const Data data, Protocols protocols) : Packet(data, protocols) { }

    /**
      * Checks packet whether is packet of this protocol.
      * @param packet Packet to be verified.
      * @param onSuccessAddProtocol When true then will be added to packet appropriate protocls.
      * @return True/false.
      */
    static int isThisProtocol(Packet *packet, bool onSuccessAddProtocol = true);

    /**
      * Returns array of TLV objects generated from corresponding data of LLDP packet.
      * @return Array of TLV objects.
      * @see TLV
      */
    TLVs readPacket() const;

    /**
      * Returns size of LLDP packet.
      * @return Size of LLDP packet only, or -1 on malformed/bad packet.
      */
    int getSize() const;

    /**
      * Returns start position of LLDP packet in data.
      * @return Start position of LLDP packet in data, or -1 on malformed/bad packet.
      */
    int beginAt() const;

    /**
      * Generates packet example protocol packet to be sent on interface.
      * @param packet Packet where generated LLDP packet is stored.
      * @param interface Which interface should be present inside example packet.
      * @param ttl Which time to live value should be present inside packet.
      * @return True/false which signs success of creating packet.
      */
    static int generateDevicePacket(LLDPPacket &packet, string interface = "eth0", int ttl = 180);

private:
    const static EthernetFrame::Ethernet SEND_ETHERNET_FRAME;   /**< Ethernet frame which is used to wrap LLDP packet. */
    const static int END_OF_LLDPDU_SIZE = 2;                    /**< Size of End TLV which signs end of LLDP packet */
    const static u_int8_t END_OF_LLDPDU[END_OF_LLDPDU_SIZE];      /**< TLV which signs end of LLDP packet */

    /**
      * Appends new type-length-value data to packet.
      * @param tlv New TLV to be appended to packet.
      * @param packet Packet where TLV will be appended.
      */
    static void appendTLV(TLV &tlv, LLDPPacket &packet);

};

#endif
