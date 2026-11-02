/**************************************************************************************************
 *
 * Filename           : bytearray.h
 *
 * Author             : Dipl. Ing. Sven Kaltschmidt
 *                      Utimaco IS GmbH
 *
 * Description        : Byte Array Object
 *
 *************************************************************************************************/
#ifndef CXI_API_BYTEARRAY_H
#define CXI_API_BYTEARRAY_H

#include <string>
#include <set>

#include "cxi.h"

namespace cxi
{
  class CXIAPI ByteArray
  {
    protected:
      int  size;
      char *buf;

    public:
      ByteArray(void);
      ByteArray(int len);
      ByteArray(const char *data, int len);
      ByteArray(const char *str);
      ByteArray(int val, int len);
      ByteArray(const ByteArray &ba);
      virtual ~ByteArray(void);

      void clear(void);
      int  length(void) const;
      char *get(void);
      const char *get(void) const;
      void set(const char *data, int len);
      void append(const char *data, int len);
      void append(const ByteArray &ba);
      void insert(const char *data, int len, int offset);
      void fill(char value, int len, int offset);

      // integer
      int  getInt(int def_val = 0) const;
      void setInt(int val, int len);
      void appendInt(int val, int len);

      // string
      void getString(char *str, int max_size) const;
      void setString(const char *str);
      void appendString(const char *str);
      std::string toString(void) const;
      std::string toHexString(void) const;

      // misc
      int compare(const ByteArray &ba) const;
      static int compare(const ByteArray &ba1, const ByteArray &ba2);
      ByteArray sub(int offset, int len = -1) const;
      ByteArray lstrip(void) const;
      ByteArray rstrip(const std::set<char> &charsToBeStripped) const;

      void read(const char *filename);
      void write(const char *filename) const;

      void xtrace(const char *text = 0) const;

      // operators
      ByteArray &operator= (const ByteArray &ba);
      const ByteArray &operator+=(const ByteArray &ba);
      const ByteArray &operator|=(const ByteArray &ba);
      const ByteArray &operator^=(const ByteArray &ba);

      char &operator[](int idx);

      CXIAPI friend bool operator==(const ByteArray &ba1, const ByteArray &ba2);
      CXIAPI friend bool operator!=(const ByteArray &ba1, const ByteArray &ba2);
      CXIAPI friend bool operator<(const ByteArray &ba1, const ByteArray &ba2);
      CXIAPI friend bool operator>(const ByteArray &ba1, const ByteArray &ba2);
      CXIAPI friend bool operator<=(const ByteArray &ba1, const ByteArray &ba2);
      CXIAPI friend bool operator>=(const ByteArray &ba1, const ByteArray &ba2);
      CXIAPI friend ByteArray operator+(const ByteArray&, const ByteArray&);
  };
}

#endif

