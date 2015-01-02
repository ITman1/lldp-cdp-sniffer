/*******************************************************************************
 * Projekt:         Programování síťové služby: Sniffer CDP a LLDP
 * Jméno:           Radim
 * Příjmení:        Loskot
 * Login autora:    xlosko01
 * E-mail:          xlosko01(at)stud.fit.vutbr.cz
 * Popis:           Hlavni spustitelný program. Využívá třídy Sniffers, přes
 *                  kterou spouští sniffery, které zachytávájí pakety.
 *                  Třídá sniffers dále umožňuje generování některých paketů
 *                  a jejich odesílání na specifikované rozhraní.
 *
 ******************************************************************************/

/**
 * @file cdp_lldp_sniffer.cpp
 *
 * @brief Main runnable program. Uses Sniffers class over which runs each capture
 *        Sniffers. Class Sniffers also makes possible generating some packets and
 *        sending them on specific interface.
 * @author Radim Loskot xlosko01(at)stud.fit.vutbr.cz
 */

#include <signal.h>

#include <iostream>
#include <string>
#include <map>
#include <cstdlib>

#include "network.h"
#include "lib/sniffers.h"

using namespace std;

/**
  * Commandline flags which are possible to pass to the program.
  */
enum flags {
    SENDER                      = 's',  /**< sender mode */
    LISTENER                    = 'l',  /**< listener mode */
    INTERFACE                   = 'i',  /**< interface arguemnt is follows */
    TTL                         = 't',  /**< time to live value of packet */
    INTERVAL                    = 'r',  /**< packet generation interval */
    CDP                         = 'c'   /**< CDP sender is demanded */
};

/**
  * Some threated errors and returns codes for them.
  */
enum errors {
    ERR_ARGUMENTS               = 1,    /**< error in cmd arguments/flags */
    ERR_FORWARDING              = 2,    /**< forwarding disabled */
    ERR_GENPACKET               = 3,    /**< unable generating packet */
    ERR_SENDPACKET              = 4,    /**< unable to send packet */
    ERR_LISTEN                  = 5,    /**< error on listening */
    ERR_LISTEN_DEVICE           = 6     /**< errot on establishing of listening */
};

/**
  * Help text
  */
const string HELP =
    "ISA - Sniffer CDP a LLDP\n"
    "Použití:\n"
    "  \txlosko01 [-l|-s] -i <rozhraní> [-c] [-t <int>] [-r <int>]\n"
    "\n"
    "Přepínače:\n"
    "-i\t- název rozhraní\n"
    "-s\t- režim zasílání packetů (bez přepínače -c LLDP paketů)\n"
    "-l\t- režim naslouchání na rozhraní\n"
    "-c\t- zasílání CDP paketů\n"
    "-t\t- doba běhu programu v režimu zasílání paketů (v sekundách)\n"
    "-r\t- interval odesílání paketů (v sekundách)";

const string MSG_WRN_ARG_GARBAGE = "Upozornění: Některé parametry byly přeskočeny.";
const string MSG_WRN_UNKNOWN_OPTION = "Upozornění: Neznámý přepínač: ";
const string MSG_ERR_ARG_INTERFACE_MISSING = "Chyba: Nebylo zadáno rozhraní!";
const string MSG_WRN_MISSING_ARGUMENT = "Upozornění: Chybějící argument k přepínači: ";
const string MSG_WRN_OPTION_IGNORE = "Přepínač bude ignorován!";
const string MSG_ERR_TOO_MODES = "Chyba: Zadejte pouze jeden režim (listner|sender)!";
const string MSG_ERR_NO_MODE = "Chyba: Nebyl specifikován žádný režim!";
const string MSG_ERR_FORWARDING = "Chyba: Není povolen IPv4 nebo IPv6 forwarding!";
const string MSG_ERR_GENPACKET = "Chyba: Nebylo možné vygenerovat packet! Zkontrolujte název rozhraní.";
const string MSG_ERR_SENDPACKET = "Chyba: Nebylo možné odeslat packet!";
const string MSG_ERR_LISTEN = "Chyba: Nebylo možné spustit odposlech na zadaném zařízení!";
const string MSG_ERR_LISTEN_DEVICE = "Chyba: Odposlech na rozhraní nelze spustit! Zkontrolujte název rozhraní.";
const string MSG_WRN_INT_VALID = "Upozornění: Některý argument(y) byly vynechány kvůli neplatné konverzi na numerickou hodnotu.";

/**
  * Default time to live value.
  */
static const int DEFAULT_TTL        = 120;

/**
  * Default sending interval.
  */
static const int DEFAULT_INTERVAL   = 30;

/**
  * Default parsing parameter from command line filter
  */
static const string GETOPT_STRING = ":lsi:ct:r:";

/**
  * Global object of sniffers.
  */
Sniffers sniffers;

/**
  * Signal handler that catches termination signals.
  * @param sig Signal number
  */
void sighandler(int sig) {
    // Prepare signal action structure for ignoring signal
    struct sigaction sa;
    sa.sa_handler = SIG_IGN;
    sa.sa_flags = 0;
    sigemptyset(&sa.sa_mask);

    // Ignoring SIGINT and SIGTERM
    if ((sigaction(SIGINT, &sa, NULL) == -1) &&
        ((sigaction(SIGTERM, &sa, NULL) == -1))) {
        exit(sig);
    }

    sniffers.stopListening(); // Termination of listening whether runs
    sniffers.stopSending();   // Termination of sending whewther runs
}

/**
  * Gets flags and arguments ryped on command line.
  * @param argc number of parameters
  * @param argv Array with parameters
  * @param flags Return mapping array with flags and corresponding arguments
  */
map<char, string> &getFlags(int argc, char **argv, map<char, string> &flags) {
    char ch;
    string optargString;

    opterr = 0;
    // Processing cmd line parameters
    while ((ch = getopt(argc, argv, GETOPT_STRING.c_str())) != -1) {
        switch (ch) {
            // known parameter
            case LISTENER: case SENDER: case INTERFACE: case CDP:case TTL: case INTERVAL:
                optargString = (!optarg)? string() : optarg;        // getting argument whether has
                flags.insert(pair<char, string>(ch, optargString)); // storing to map array
                break;
            // unknown flag
            case '?':
                cerr << MSG_WRN_UNKNOWN_OPTION << char(optopt) << endl;
                break;
            // missing argument
            case ':':
                cerr << MSG_WRN_MISSING_ARGUMENT << char(optopt) << endl;
                if ((flags.count('i')) && (flags[optopt].empty())) {
                    flags.erase(optopt);
                }
                break;
        }

    }

    // there were some parameter which were skipped
    if (optind < argc) {
        cerr << MSG_WRN_ARG_GARBAGE << endl;
    }

    return flags;
}

/**
  * Prints info text about captured packet
  * @param packet Name of packet which has been captured
  */
void printCaptureInfo(string packet) {
    cout << string(80, '-') << endl;
    cout << " Captured packet: " << int(sniffers.lastCapturedPacketNumber() + 1) << " (" << packet << " packet)" << endl;
    cout << string(80, '-') << endl;
}

/**
  * Callback function for capturing of LLDP packet.
  * @param packet Captured LLDP packet
  */
void callback_LLDPPacket(const LLDPPacket *packet) {
    TLVs tlvs = packet->readPacket();
    TLVs::iterator it;

    printCaptureInfo("LLDP");               // Printing info header

    cout << "<TLV STRUCTURES>" << endl;

    // printing recognized TLV structures in format "type: value" or "type (subtype): value"
    for (it = tlvs.begin(); it != tlvs.end(); ++it) {
        if ((*it)->getSubTypeName().length()) {     // subtype is set, print type name together with subtype name + value
            cout << "\t" <<  (*it)->getTypeName() << " (" << (*it)->getSubTypeName() << "): " << (*it)->getValueStr() << endl;
        } else {                                    // subtype not set, print only type name + value
            cout << "\t" << (*it)->getTypeName() << ": " << (*it)->getValueStr() << endl;
        }
    }

    cout << endl;
}

/**
  * Callback function for capturing of CDP packet.
  * @param packet Captured CDP packet
  */
void callback_CDPPacket(const CDPPacket *packet) {
    CDPPacket::Header header = packet->getHeader();
    TLVs tlvs = packet->readPacket();
    TLVs::iterator it;

    printCaptureInfo("CDP");               // Printing info header

    // printing CDP hader informations
    cout << "<HEADER>" << endl;
    cout << "\tVersion: " << int(header.version) << endl;
    cout << "\tTime To Live: " << int(header.timeToLive) << " s" << endl;
    cout << "\tChecksum: 0x" << Data::toHex(header.checksum);
    cout << " [" << ((packet->testCheckSum())? "OK" : "BAD")  << "]" << endl << endl;

    cout << "<TLV STRUCTURES>" << endl;

    // printing TLV structures in format "type: value"
    for (it = tlvs.begin(); it != tlvs.end(); ++it) {
        cout << "\t" << (*it)->getTypeName() << ": " << (*it)->getValueStr() << endl;
    }

    cout << endl;
}

/**
  * Converts return code of startSending() method to program exit code.
  * @param result Return code from startSending() method
  * @return Corresponding exit code of this program
  */
int translateSendErrors (int result) {
    switch (result) {
    // unable generate packet
    case Sniffers::ERR_GENPACKET:
        cerr << MSG_ERR_GENPACKET << endl;
        result = ERR_GENPACKET;
        break;
    // unable send packet
    case Sniffers::ERR_SENDPACKET:
        cerr << MSG_ERR_SENDPACKET << endl;
        result = ERR_SENDPACKET;
        break;
    }

    return result;
}

/**
  * Converts return code of startListening() method to program exit code.
  * @param result Return code from startListening() method
  * @return Corresponding exit code of this program
  */
int translateListenErrors (int result) {
    switch (result) {
    // unable listen on device
    case Sniffers::ERR_LISTEN:
        cerr << MSG_ERR_LISTEN << endl;
        result = ERR_LISTEN;
        break;
    // unable listen device due to opening error
    case Sniffers::ERR_LISTEN_DEVICE:
        cerr << MSG_ERR_LISTEN_DEVICE << endl;
        result = ERR_LISTEN_DEVICE;
        break;
    }

    return result;
}

/**
  * Runs CDP and LLDP sniffer.
  * @param flags Map array with command line flags
  * @param exit code of sniffer program
  */
int runSniffer(map<char, string> &flags) {
    int result = 0;
    sniffers.interface = flags[INTERFACE];
    // getting ttl value
    int ttl = (flags.count(TTL))? Data::strToInt(flags[TTL]) : DEFAULT_TTL;
    // getting interval value
    int interval = (flags.count(INTERVAL))? Data::strToInt(flags[INTERVAL]) : DEFAULT_INTERVAL;

    if (flags.count(LISTENER)) {                // listner mode is set

        // adding LLDP and CDP sniffer and start listening
        sniffers.addSnifferCallback<LLDPSniffer>(callback_LLDPPacket);
        sniffers.addSnifferCallback<CDPSniffer>(callback_CDPPacket);
        result = sniffers.startListening();

        result = translateListenErrors(result);
    } else if (flags.count(SENDER)) {           // sender mode is set
        if (Network::forwardingEnabled()) {     // forwarding is enabled

            if (flags.count(CDP)) {             // sending CDP packet
                result = sniffers.startSending(CDP_PROTOCOL, ttl, interval);
            } else {                            // otherwise sending LLDP packet
                result = sniffers.startSending(LLDP_PROTOCOL, ttl, interval);
            }

            result = translateSendErrors(result);

        } else {                                // forwarding is disabled
            cerr << MSG_ERR_FORWARDING << endl;
            result = ERR_FORWARDING;
        }
    }

    return result;
}

/**
  * Prints sniffer statistics when program is finnishing
  * @param flags Map array which contains run parameters.
  */
void printSniffersInfo(map<char, string> &flags) {
    if (flags.count(LISTENER)) {    // listener mode finished
        cout << string(80, '=') << endl;
        cout << "Captured packets: " << int(sniffers.lastCapturedPacketNumber() + 1) << endl;
        cout << "Processed bytes [B]: " << int(sniffers.capturedBytes()) << endl;
    } else {                        // sender mode finished
        cout << "Sent packets: " << int(sniffers.lastSentPacketNumber() + 1) << endl;
        cout << "Bytes [B]: " << int(sniffers.sentBytes()) << endl;
    }
}

int main(int argc, char* argv[]) {
    map<char, string> flags;
    int ok = 1;
    int ret;

    // getting run parameters
    flags = getFlags(argc, argv, flags);

    // no params - print HELP text
    if (argc == 1) {
        cerr << HELP << endl;
        return 0;
    // missing interface name
    } else if ((!flags.count(INTERFACE)) || (flags[INTERFACE].empty())) {
        cerr << MSG_ERR_ARG_INTERFACE_MISSING << endl;
        return ERR_ARGUMENTS;
    // cannot run in two modes
    } else if (flags.count(SENDER) && flags.count(LISTENER)) {
        cerr << MSG_ERR_TOO_MODES << endl;
        return ERR_ARGUMENTS;
    // cannot run without mode
    } else if (!flags.count(SENDER) && !flags.count(LISTENER)) {
        cerr << MSG_ERR_NO_MODE << endl;
        return ERR_ARGUMENTS;
    }

    // checking correct numeric value of TTL argument
    if (flags.count(TTL)) {
        Data::strToInt(flags[TTL], &ok);
        if (!ok) {
            cerr << MSG_WRN_INT_VALID << endl;
            flags.erase(TTL);   // not valid, remove argument
        }
    }

    // checking correct numeric value of interval argument
    if (ok && flags.count(INTERVAL)) {
        Data::strToInt(flags[INTERVAL], &ok);
        if (!ok) {
            cerr << MSG_WRN_INT_VALID << endl;
            flags.erase(INTERVAL);  // not valid, remove argument
        }
    }

    // Catching SIGINT and SIGTERM for proper ending
    signal(SIGINT, sighandler);
    signal(SIGTERM, sighandler);

    ret = runSniffer(flags);        // RUN SNIFFER

    if (ret == 0) { // on succes return sniffer info text
        printSniffersInfo(flags);
    }

    return ret;
} 
