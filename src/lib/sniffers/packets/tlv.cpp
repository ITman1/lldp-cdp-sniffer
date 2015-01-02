/*******************************************************************************
 * Projekt:         Programování síťové služby: Sniffer CDP a LLDP
 * Jméno:           Radim
 * Příjmení:        Loskot
 * Login autora:    xlosko01
 * E-mail:          xlosko01(at)stud.fit.vutbr.cz
 * Popis:           Modul definující bazovou třídu ke TLV třídám.
 *
 ******************************************************************************/

/**
 * @file tlv.cpp
 *
 * @brief Module which defines base class to derived TLV classes..
 * @author Radim Loskot xlosko01(at)stud.fit.vutbr.cz
 */

#include <map>
#include <string>
#include "frames/data.h"
#include "tlv.h"

using namespace std;

/**
  * Default type name-
  */
const string TLV::tlv_type_str = "(unknown)";

/**
  * Just definition of reference.
  */
const map<int, string> TLV::subtypes_str = map<int, string>();

/**
  * Constructor
  * @param data Data which will be used as a value.
  * @param default_subtype Subtype which specifies data value.
  */
TLV::TLV(const Data &data, int default_subtype):tlv_type(-1) , tlv_subType(default_subtype){
    setValue(data, default_subtype);
}

/**
  * Returns stored value.
  * @return Stored value in TLV.
  */
const Data TLV::getValue() {
    return tlv_value;
}

/**
  * Returns stored value as a string.
  * @return Stored value in TLV converted to string representation.
  */
const string TLV::getValueStr() {
    // fixes inserting extra \0 whether already presents
    if (tlv_value.length && tlv_value.data[tlv_value.length - 1] == '\0') {
        return string((char *)tlv_value.data);
    } else {
        return string((char *)tlv_value.data, tlv_value.length);
    }
}

/**
  * Returns type name.
  * @return Type name.
  */
string TLV::getTypeName() {
    return tlv_type_str;
}

/**
  * Returns subtype name of current set subtype.
  * @return Subtype name.
  */
string TLV::getSubTypeName() {
    return string();
}

/**
  * Returns current subtype.
  * @return Current subtype.
  */
int TLV::getSubType() {
    return tlv_subType;
}

/**
  * Stores new value with or without subtype.
  * @param value New value to be stored.
  * @param subtype Subtype of value.
  */
void TLV::setValue(Data value, int subtype) {
    tlv_subType = subtype;
    tlv_value = value;
}

/**
  * Destructor
  */
TLVs::~TLVs() {
    TLVs::iterator pos;

    // all allocated TLV has to be deallocated before vector destruction
    for (pos = this->begin(); pos != this->end(); ++pos) {
        delete *pos;
    }
}

