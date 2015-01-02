/*******************************************************************************
 * Projekt:         Programování síťové služby: Sniffer CDP a LLDP
 * Jméno:           Radim
 * Příjmení:        Loskot
 * Login autora:    xlosko01
 * E-mail:          xlosko01(at)stud.fit.vutbr.cz
 * Popis:           Hlavičkový soubor deklarující bazovou třídu ke TLV třídám.
 *
 ******************************************************************************/

/**
 * @file tlv.h
 *
 * @brief Header file which declares base class to derived TLV classes..
 * @author Radim Loskot xlosko01(at)stud.fit.vutbr.cz
 */

#ifndef TLV_H
#define TLV_H

#include <string>
#include <map>
#include <vector>

#include "frames/data.h"

using namespace std;

/**
  * Type length value class.
  * @todo Maybe it would be better to make virtual parsing methods fromBinary
  *       and toBinary + in Base constructor calling fromBinary. Now is parsing
  *       done in getValueStr() method. In the result whole TLV data would not
  *       be stored in the object but in appropriate attributes.
  */
class TLV {
public:
    /**
      * Constructor
      * @param data Data which will be used as a value.
      * @param default_subtype Subtype which specifies data value.
      */
    TLV(const Data &data, int default_subtype = -1);

    /**
      * Constructor
      * @param default_subtype Subtype which specifies data value.
      */
    TLV(int default_subtype = -1) : tlv_type(-1), tlv_subType(default_subtype) {}

    /**
      * Virtual destrutor which enables calling derived desctructors.
      */
    virtual ~TLV() {}

    /**
      * Returns stored value.
      * @return Stored value in TLV.
      */
    virtual const Data getValue();

    /**
      * Returns stored value as a string.
      * @return Stored value in TLV converted to string representation.
      */
    virtual const string getValueStr();

    /**
      * Returns type name.
      * @return Type name.
      */
    virtual string getTypeName();

    /**
      * Returns subtype name of current set subtype.
      * @return Subtype name.
      */
    virtual string getSubTypeName();

    /**
      * Returns current subtype.
      * @return Current subtype.
      */
    virtual int getSubType();

    /**
      * Stores new value with or without subtype.
      * @param value New value to be stored.
      * @param subtype Subtype of value.
      */
    void setValue(Data value, int subtype = -1);

    int tlv_type;                               /**< Type of value */
    const static string tlv_type_str;           /**< Type name */
    const static map<int, string> subtypes_str; /**< Array of subtype names */
    const static int NO_SUBTYPE = -1;           /**< Just constant */
protected:
    int tlv_subType;                            /**< Subtype of value */
    Data tlv_value;                             /**< Value */
};

/**
  * Class of TLV array.
  */
class TLVs: public vector<TLV *> {
public:
    /**
      * Destructor
      */
    ~TLVs();
};

#endif // TLV_H
