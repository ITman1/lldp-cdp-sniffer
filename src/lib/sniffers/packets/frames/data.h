/*******************************************************************************
 * Projekt:         Programování síťové služby: Sniffer CDP a LLDP
 * Jméno:           Radim
 * Příjmení:        Loskot
 * Login autora:    xlosko01
 * E-mail:          xlosko01(at)stud.fit.vutbr.cz
 * Popis:           Hlavičkový soubor deklarující třídu pro práci s polem znaků.
 *                  Dále obsahuje některé funkce zajišťující šablonové konverze.
 *
 ******************************************************************************/

/**
 * @file data.h
 *
 * @brief Header file which declares class for manipulation with array of chars.
 *        Contains also some other additional template conversion functions.
 * @author Radim Loskot xlosko01(at)stud.fit.vutbr.cz
 */

#ifndef DATA_H
#define DATA_H

#include <sstream>
#include <iomanip>
#include <string>
#include <pcap.h>

using namespace std;

/**
  * Declaration of class which wraps array of already allocated characters.
  * In class are also declared useful template static methods using Data namespace.
  * @note Future suggestion: Do not wrap data, but allocate them with inherited
  *       STL vector (optimalization problems vs. better work with data structure?)
  */
class Data {
public:
    Data():data(0), length(0) {}
    Data(const u_int8_t *data, int length):data(data), length(length) {}
    //~Data() { delete data; }

    /**
      * Appends new chars data. Appends only, does not allocates new space.
      * @param newData New data to be added to this object.
      */
    void appendData(Data &newData);

    /**
      * Reads unsigned short value from specific byte and bit.
      * @param position Position of start byte from where reading should be accomplished.
      * @param fromBit Start bit on defined byte.
      * @param count Count of bit which should be read.
      * @return Returns demanded unsgigned short value.
      */
    u_int16_t readUShort(int position, int fromBit, int count) const;

    /**
      * Reads unsigned short value from specific byte in data struture.
      * @param position Position of start byte from where reading should be accomplished.
      * @return Returns demanded unsgigned short value.
      */
    u_int16_t readUShort(int position) const;

    /**
      * Reads unsigned char value from specific byte and bit.
      * @param position Position of start byte from where reading should be accomplished.
      * @param fromBit Start bit on defined byte.
      * @param count Count of bit which should be read.
      * @return Returns demanded unsgigned char value.
      */
    u_int8_t readUChar(int position, int fromBit, int count) const;

    /**
      * Reads unsigned char value from specific byte in data struture.
      * @param position Position of start byte from where reading should be accomplished.
      * @return Returns demanded unsgigned char value.
      */
    u_int8_t readUChar(int position) const;

    /**
      * Counts IP checksum and returns number in host format.
      * @param data Data above which will be calculated checksum.
      * @param from Postion where checksum should be calculated.
      * @return Returns IP checksum.
      */
    static u_int16_t checksum(const Data &data, int from);

    /**
      * Converts various number type to its string representation in hexadecimal.
      * Value will be filled by zeros to corresponding data type size.
      * @param number Number to be converted.
      * @return Hex string representation of number.
      */
    template< typename Type>
    static string toHex(Type number) {
        stringstream ss;
        ss << setfill ('0') << setw(sizeof(Type) * 2) << hex << int(number);
        return ss.str();
    }

    /**
      * Converts various number type to its string representation.
      * Value will be filled to its data type size.
      * @param number Number to be converted.
      * @return String representation of number.
      */
    template< typename Type>
    static string toStr(Type variant) {
        stringstream number;
        number << variant;
        return number.str();
    }

    /**
      * Converts string number to int.
      * @param str String to be converted.
      * @param ok Is set 1 where there were not conversion errors.
      * @return Int representation string number.
      */
    static int strToInt(string str, int *ok = 0);

    /**
      * Converts array to string with hexadecimal representation.
      * @param arr Pointer to array.
      * @param len Length of array.
      * @return Converted array to hexadecimal string.
      */
    static string arrToHexStr(const u_int8_t *arr, int len);

    const u_int8_t *data;     /**< Holds pointer to allocated data  */
    int length;             /**< Holds data length */
};


#endif // DATA_H
