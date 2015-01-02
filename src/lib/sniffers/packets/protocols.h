/*******************************************************************************
 * Projekt:         Programování síťové služby: Sniffer CDP a LLDP
 * Jméno:           Radim
 * Příjmení:        Loskot
 * Login autora:    xlosko01
 * E-mail:          xlosko01(at)stud.fit.vutbr.cz
 * Popis:           Hlavičkový soubor, který vkládá všechny hlavičkové soubory
 *                  tříd paketů a definuje jejich protokoly.
 *
 ******************************************************************************/

/**
 * @file protocols.h
 *
 * @brief Header file which includes header files which declares all
 *        implemented packets. Also defines protocol constants.
 * @author Radim Loskot xlosko01(at)stud.fit.vutbr.cz
 */

#ifndef PROTOCOLS_H
#define PROTOCOLS_H

#include "cdp_packet.h"
#include "lldp_packet.h"

// Definition of index constants of protocol array
#define DATALINK               0
#define LAYER_2                1
#define LAYER_3                2
#define LAYER_4                3

/**
  * Enum off all implemented protocols
  */
enum protocols {
    LLDP_PROTOCOL     = 0x00001000,
    CDP_PROTOCOL      = 0x00001001,
    LLC_PROTOCOL      = 0x00001002
};

#endif // PROTOCOLS_H
