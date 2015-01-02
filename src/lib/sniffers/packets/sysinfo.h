/*******************************************************************************
 * Projekt:         Programování síťové služby: Sniffer CDP a LLDP
 * Jméno:           Radim
 * Příjmení:        Loskot
 * Login autora:    xlosko01
 * E-mail:          xlosko01(at)stud.fit.vutbr.cz
 * Popis:           Hlavičkový soubor obsahující deklaraci funkcí na
 *                  získání informací o systému.
 *
 ******************************************************************************/

/**
 * @file sysinfo.h
 *
 * @brief Header file which contains functions which retrieves informations
 *        about current system.
 * @author Radim Loskot xlosko01(at)stud.fit.vutbr.cz
 */

#ifndef SYSINFO_H
#define SYSINFO_H

#include <string>

using namespace std;

namespace System {

    /**
      * Structure that holds general description information about system.
      */
    typedef struct {
        string nodename;
        string sysname;
        string release;
        string version;
        string machine;
        string domainname;
    } SystemInfo;

    /**
      * Returns system description text.
      * @return System description text.
      */
    string getSystemDescription();

    /**
      * Returns description information about current system in structure SystemInfo.
      * @return System information in SystemInfo structure.
      */
    SystemInfo getSystemInfo();
}

#endif // SYSINFO_H
