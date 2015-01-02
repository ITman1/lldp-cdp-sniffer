/*******************************************************************************
 * Projekt:         Programování síťové služby: Sniffer CDP a LLDP
 * Jméno:           Radim
 * Příjmení:        Loskot
 * Login autora:    xlosko01
 * E-mail:          xlosko01(at)stud.fit.vutbr.cz
 * Popis:           Hlavičkový soubor daklarující třídu CDP paketu.
 *
 ******************************************************************************/

/**
 * @file cdp_packet.h
 *
 * @brief Header file which declares class CDP packet.
 * @author Radim Loskot xlosko01(at)stud.fit.vutbr.cz
 */

#ifndef CDP_PACKET_H
#define CDP_PACKET_H

#include <string>
#include <vector>
#include <map>

#include "packet.h"
#include "frames/ethernet_frame.h"
#include "tlv.h"
#include "llc_packet.h"

using namespace std;

/**
  * Class of CDP packet.
  */
class CDPPacket: public Packet {
public:
    static const int ETHER_TYPE = 0x2000; /**< Type of ethernet frame which will be used on generating CDP packet */
    static const int HEADER_SIZE = 4;     /**< Size of header of CDP packet */
    static const int CHECKSUM_OFFSET = 2; /**< Offset of checksum item in CDP header */
    static const int TL_SIZE = 4;         /**< Size of type-value items in TLV. */

    /**
      * Struct of CDP header.
      */
    typedef struct header {
        u_int8_t version;             /**< Version of CDP protocol */
        u_int8_t timeToLive;          /**< Time to live of this packet */
        u_int16_t checksum;           /**< Checksum of whole CDP packet */
    } Header;

    /**
      * Types values which are present in CDP packet.
      */
    enum TLV_types {
        //http://www.cisco.com/univercd/cc/td/doc/product/lan/trsrb/frames.htm#35907
        reserved               = 0x00,
        deviceID               = 0x01,
        addresses              = 0x02,   // not whole set of addresses is implemented
        portID                 = 0x03,
        capabilities           = 0x04,
        softwareVersion        = 0x05,
        platform               = 0x06,
        //these types are not implemented
        //http://www.cisco.com/en/US/products/hw/switches/ps4324/products_tech_note09186a0080094713.shtml
        //http://opensource.apple.com/source/tcpdump/tcpdump-27/tcpdump/print-cdp.c
        //ipPrefix             = 0x07,
        //protocolHelloOption  = 0x08,
        //vtpManagementDomain  = 0x09,
        //nativeVLANID         = 0x0a,
        duplex                 = 0x0b,
        //not implemented      = 0x0c,
        //not implemented      = 0x0d,
        //not implemented      = 0x0e,
        //not implemented      = 0x0f,
        //not implemented      = 0x10,
        mtu                    = 0x11,
        //not implemented      = 0x12,
        //not implemented      = 0x13,
        systemName             = 0x14
        //other                = 0xXX
    };

    /**
      * Class of device ID value.
      * Value is string.
      * @see TLV
      */
    class DeviceID :public TLV {

    public:
        DeviceID(const Data &data) :TLV(data) {}
        /**
         * @note (+) Remove it and pass string into TLV class via constructor.
         *       (-) But, cannot be used static in Base. Too much
         *           memory comsuption. Every instance would have
         *           the same data. But pointer to static string in derived
         *           could solve that. :/ So then "todo".
         * @todo Pass pointer to static tlv_type_str into Base via contructor.
         *       In Base class create/change attribute tlv_type_str to pointer.
         */
        virtual string getTypeName() { return tlv_type_str; }

        const static int tlv_type  = CDPPacket::deviceID;
        const static string tlv_type_str;
    };

    /**
      * Class of Addresses value.
      * Value is array of addresses.
      * @see TLV
      */
    class Addresses :public TLV {

    public:
        /**
          * Type of protocols above addresses.
          */
        enum protocol_type {
            NLPID              = 1,
            IEEE802_2          = 2
        };

        /**
          * Type of address.
          */
        enum protocol {
            IP                 = 0xCC
            //other not implemented
        };

        /**
          * Class which holds one address.
          */
        class Address {
        public:
            /**
              * Converts address to string representation.
              * @return String representation of address.
              */
            string toStr();

            const static int MAX_PROTOCOL_LENGTH = 6;   /**< Maximal length of protocol */
            const static int MAX_ADDRESS_LENGTH = 24;   /**< Maximal length of address */

            u_int8_t protocolType;                        /**< Protocol type */
            u_int8_t protocolLength;                      /**< Protocol length */
            u_int8_t protocol[MAX_PROTOCOL_LENGTH];       /**< Protocol */
            u_int16_t addressLength;                      /**< Address length */
            u_int8_t address[MAX_ADDRESS_LENGTH];         /**< Address */
        };

        Addresses(const Data &data) :TLV(data) {}
        virtual string getTypeName() { return tlv_type_str; }

        /**
          * Returns array addresses in string representation.
          * @return Array of address in format "%d address(es) (<addr1>, <addr2>, ...)"
          */
        virtual const string getValueStr();

        const static int tlv_type  = CDPPacket::addresses;
        const static string tlv_type_str;

        /**
          * Map array with string representation of protocol types
          */
        const static map<int, string> protocol_types_str;

        /**
          * Map array with strings of protocol names.
          */
        const static map<int, string> protocols_str;
    };

    /**
      * Class of port ID value.
      * Value is string.
      * @see TLV
      */
    class PortID :public TLV {

    public:
        PortID(const Data &data) :TLV(data) {}
        virtual string getTypeName() { return tlv_type_str; }

        const static int tlv_type  = CDPPacket::portID;
        const static string tlv_type_str;
    };

    /**
      * Class of capabilities value.
      * Value is bit array.
      * @see TLV
      */
    class Capabilities :public TLV {
    public:
        /**
          * Enum of implemented capabilities
          */
        enum capabilities {
            router              = 0x01,
            transparentBridge   = 0x02,
            sourceRouteBridge   = 0x04,
            switchL2            = 0x08,
            host                = 0x10,
            IGMPCapable         = 0x20,
            repeater            = 0x40
        };

        Capabilities(const Data &data) :TLV(data) {}
        virtual string getTypeName() { return tlv_type_str; }

        /**
          * Returns specified capabilities as a string delimited by comma.
          * @return Capabilities in string representation in format "<cap1>, <cap2>, ..."
          */
        virtual const string getValueStr();

        const static int tlv_type = CDPPacket::capabilities;
        const static string tlv_type_str;
        const static map<int, string> capabilities_str;
    };

    /**
      * Class of sowtware version value.
      * Value is string.
      * @see TLV
      */
    class SoftwareVersion :public TLV {

    public:
        SoftwareVersion(const Data &data) :TLV(data) {}
        virtual string getTypeName() { return tlv_type_str; }

        const static int tlv_type  = CDPPacket::softwareVersion;
        const static string tlv_type_str;
    };

    /**
      * Class platform value.
      * Value is string.
      * @see TLV
      */
    class Platform :public TLV {

    public:
        Platform(const Data &data) :TLV(data) {}
        virtual string getTypeName() { return tlv_type_str; }

        const static int tlv_type  = CDPPacket::platform;
        const static string tlv_type_str;
    };

    /**
      * Class of duplex value. (half/full)
      * Value is boolean.
      * @see TLV
      */
    class Duplex :public TLV {

    public:
        Duplex(const Data &data) :TLV(data) {}
        virtual string getTypeName() { return tlv_type_str; }

        /**
          * Returns duplex in string represention.
          * @return Duplex "half" or "full".
          */
        virtual const string getValueStr();

        const static int tlv_type  = CDPPacket::duplex;
        const static string tlv_type_str;
    };

    /**
      * Class of MTU value.
      * Value is numeric.
      * @see TLV
      */
    class MTU :public TLV {

    public:
        MTU(const Data &data) :TLV(data) {}
        virtual string getTypeName() { return tlv_type_str; }

        /**
          * Returns numeric value as a string.
          * @return Converted numer number to string.
          */
        virtual const string getValueStr();

        const static int tlv_type  = CDPPacket::mtu;
        const static string tlv_type_str;
    };

    /**
      * Class of system name value.
      * Value is string.
      * @see TLV
      */
    class SystemName :public TLV {

    public:
        SystemName(const Data &data) :TLV(data) {}
        virtual string getTypeName() { return tlv_type_str; }

        const static int tlv_type  = CDPPacket::systemName;
        const static string tlv_type_str;
    };

    /**
      * Constructor of CDP packet from data and protocols from which is made out.
      * @todo protocols has to be specified, more correct would be auto recognition by
      *   static isThisProtocol function
      * @param data Source data of this packet.
      * @param protocols Protocols from which is made out this packet. (remove in future)
      */
    CDPPacket(const Data data, Protocols protocols) : Packet(data, protocols) { }

    /**
      * Checks packet whether is packet of this protocol.
      * @param packet Packet to be verified.
      * @param onSuccessAddProtocol When true then will be added to packet appropriate protocls.
      * @return True/false.
      */
    static int isThisProtocol(Packet *packet, bool onSuccessAddProtocol = true);

    /**
      * Returns header od CDP packet.
      * @return Header of CDP packet.
      */
    Header getHeader() const;

    /**
      * Checks inserted checksum with new one calculated.
      * @return Result of checksum check.
      */
    int testCheckSum() const;

    /**
      * Returns size of CDP packet.
      * @return Size of CDP packet only, or -1 on malformed/bad packet.
      */
    int getSize() const;

    /**
      * Returns start position of CDP packet in data.
      * @return Start position of CDP packet in data, or -1 on malformed/bad packet.
      */
    int beginAt() const;

    /**
      * Returns array of TLV objects generated from corresponding data of CDP packet.
      * @return Array of TLV objects.
      * @see TLV
      */
    TLVs readPacket() const;

    /**
      * Generates packet example protocol packet to be sent on interface.
      * @param packet Packet where generated CDP packet is stored.
      * @param interface Which interface should be present inside example packet.
      * @param ttl Which time to live value should be present inside packet.
      * @return True/false which signs success of creating packet.
      */
    static int generateDevicePacket(CDPPacket &packet, string interface = "eth0", int ttl = 180);

private:
    const static EthernetFrame::Ethernet SEND_ETHERNET_FRAME;   /**< Ethernet frame to be sent in example packet */
    const static LLCPacket::LLC SEND_LLC_PACKET;                /**< LLC packet to be sent in example packet */

    /**
      * Appends new type-length-value data to packet.
      * @param tlv New TLV to be appended to packet.
      * @param packet Packet where TLV will be appended.
      */
    static void appendTLV(TLV &tlv, vector<u_int8_t> &packet);

};

#endif
