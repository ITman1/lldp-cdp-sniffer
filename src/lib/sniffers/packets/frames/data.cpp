/*******************************************************************************
 * Projekt:         Programování síťové služby: Sniffer CDP a LLDP
 * Jméno:           Radim
 * Příjmení:        Loskot
 * Login autora:    xlosko01
 * E-mail:          xlosko01(at)stud.fit.vutbr.cz
 * Popis:           Modul definující třídu pro práci nad polem znaků.
 *                  Dále obsahuje některé funkce zajišťující šablonové konverze.
 *
 ******************************************************************************/

/**
 * @file data.cpp
 *
 * @brief Module which defines class for manipulation with array of chars.
 *        Contains also some other additional template conversion functions.
 * @author Radim Loskot xlosko01(at)stud.fit.vutbr.cz
 */


#include <sstream>
#include <cstdlib>
#include <limits>
#include <cstring>
#include <netinet/in.h>

#include "data.h"

using namespace std;

/**
  * Appends new chars data. Appends only, does not allocates new space.
  * @param newData New data to be added to this object.
  */
void Data::appendData(Data &newData) {
    memcpy(const_cast<u_int8_t *>(&data[length]), newData.data, newData.length);
    length += newData.length;
}

/**
  * Reads unsigned short value from specific byte and bit.
  * @param position Position of start byte from where reading should be accomplished.
  * @param fromBit Start bit on defined byte.
  * @param count Count of bit which should be read.
  * @return Returns demanded unsgigned short value.
  */
u_int16_t Data::readUShort(int position, int fromBit, int count) const {
    u_int8_t *dw = const_cast<u_int8_t *>(&data[position]);
    fromBit %= 8;
    count %= 16;        // output unsigned short has only 16 bits

    return (u_int16_t)
    // Bitwise OR of shifted first byte left and second byte shifted rigth + folding left
    ((((((u_int8_t)(dw[0] << fromBit) | (u_int8_t)(dw[1] >> (8 - fromBit)))    << 8) |
    // Bitwise OR of shifted second byte left and third byte shifted rigth
        ((u_int8_t)(dw[1] << fromBit) | (u_int8_t)(dw[2] >> (8 - fromBit)))))
    // Skipping bits on the right
     >> (16 - count));
}

/**
  * Reads unsigned short value from specific byte in data struture.
  * @param position Position of start byte from where reading should be accomplished.
  * @return Returns demanded unsgigned short value.
  */
u_int16_t Data::readUShort(int position) const {
    return *(u_int16_t *)&data[position];
}

/**
  * Reads unsigned char value from specific byte and bit.
  * @param position Position of start byte from where reading should be accomplished.
  * @param fromBit Start bit on defined byte.
  * @param count Count of bit which should be read.
  * @return Returns demanded unsgigned char value.
  */
u_int8_t Data::readUChar(int position, int fromBit, int count) const {
    u_int8_t *db = const_cast<u_int8_t *>(&data[position]);
    fromBit %= 8;
    count %= 8;

    return (u_int8_t)(((u_int8_t)(*db << fromBit) | (u_int8_t)(db[1] >> (8 - fromBit))) >> (8 - count));
}

/**
  * Reads unsigned char value from specific byte in data struture.
  * @param position Position of start byte from where reading should be accomplished.
  * @return Returns demanded unsgigned char value.
  */
u_int8_t Data::readUChar(int position) const {
    return *(u_int8_t *)&data[position];
}

/**
  * Converts string number to int.
  * @param str String to be converted.
  * @param ok Is set 1 where there were not conversion errors.
  * @return Int representation string number.
  */
int Data::strToInt(string str, int *ok) {
    istringstream istream(str);
    int num, not_valid;

    not_valid = !(istream >> num); // converting and checking errors

    if (ok) { // pointer to ok is passed
        *ok = !not_valid;
    }
    return num;
}

/**
  * Converts array to string with hexadecimal representation.
  * @param arr Pointer to array.
  * @param len Length of array.
  * @return Converted array to hexadecimal string.
  */
string Data::arrToHexStr(const u_int8_t *arr, int len) {
    string result;
    stringstream ss;
    for (int i = 0; i < len; i++) {
        ss << setfill ('0') << setw(2) << hex << int(*arr++);
        result += ss.str() + ":";
        ss.str("");
    }
    result.erase(result.length() - 1);
    return result;
}

/**
  * Counts IP checksum and returns number in host format.
  * @param data Data above which will be calculated checksum.
  * @param from Postion where checksum should be calculated.
  * @return Returns IP checksum.
  */
u_int16_t Data::checksum(const Data &data, int from) {
    register u_int16_t size = data.length - from;
    register const u_int16_t *packet =  (u_int16_t *)&data.data[from];
    register u_int32_t sum = 0;

   while (size > 1) {   // sums unsigned short data
    sum += ntohs(*packet++);
    size -= 2;
   }

   if (size > 0) {      // odd byte processing
       sum += *(u_int8_t *)packet;
   }

   while (sum >> 16)  // folding to u_int8_t by adding until it is enough
     sum = (sum & 0xFFFF) + (sum >> 16);

    return ~sum;
}

