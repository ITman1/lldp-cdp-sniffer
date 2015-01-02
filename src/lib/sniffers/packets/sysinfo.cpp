/*******************************************************************************
 * Projekt:         Programování síťové služby: Sniffer CDP a LLDP
 * Jméno:           Radim
 * Příjmení:        Loskot
 * Login autora:    xlosko01
 * E-mail:          xlosko01(at)stud.fit.vutbr.cz
 * Popis:           Modul definující funkce na získání informací o systému.
 *
 ******************************************************************************/

/**
 * @file sysinfo.cpp
 *
 * @brief Module which defines function for retrieving information about current system.
 * @author Radim Loskot xlosko01(at)stud.fit.vutbr.cz
 */

#include <sys/utsname.h>

#include "sysinfo.h"

/**
  * Structure that holds general description information about system.
  */
System::SystemInfo System::getSystemInfo() {
    struct utsname info;
    SystemInfo sysInfo;

    uname (&info);
    sysInfo.nodename = info.nodename;
    sysInfo.sysname = info.sysname;
    sysInfo.release = info.release;
    sysInfo.version = info.version;
    sysInfo.machine = info.machine;
    //sysInfo.domainname = info.domainname;
    return sysInfo;
}

/**
  * Returns system description text.
  * @return System description text.
  */
string System::getSystemDescription() {
    SystemInfo sysInfo = getSystemInfo();
    string description;

    description += sysInfo.sysname + " ";
    description += sysInfo.release + " ";
    description += sysInfo.version + " ";
    description += sysInfo.machine + " ";

    return description;
}

