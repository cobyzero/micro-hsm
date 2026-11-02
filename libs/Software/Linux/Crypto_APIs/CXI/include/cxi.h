/**************************************************************************************************
 *
 * Filename           : cxi.h
 *
 * Author             : Dipl. Ing. Sven Kaltschmidt
 *                      Utimaco IS GmbH
 *
 * Description        : CryptoServer Core Interface API
 *
 *************************************************************************************************/
#ifndef CXI_API_C_CXI_H
#define CXI_API_C_CXI_H

#ifndef CXIAPI    
  #ifdef WIN32
    #ifdef CXIEXPORT
      #define CXIAPI __declspec(dllexport)    
    #else    
      #define CXIAPI __declspec(dllimport)
    #endif
    #define CXIAPI_LOCAL
  #else
    #if __GNUC__ >= 4
      #define CXIAPI __attribute__ ((visibility ("default")))
      #define CXIAPI_LOCAL  __attribute__ ((visibility ("hidden")))
    #else
      #define CXIAPI
      #define CXIAPI_LOCAL
    #endif
  #endif
#else
  #define CXIAPI_LOCAL
#endif

// Deprecated! use pointer parameters and NULL for optional parameters instead.
#define NULL_REF(cls) (*(cls*)0)

#include <vector>
#include <stdint.h>

#include <cxi/cxi_defs.h>
#include "exception.h"
#include "bytearray.h"
#include "item.h"
#include "keyblob.h"
#include "hash.h"
#include "mechparam.h"
#include "config.h"
#include "log.h"
#include "property.h"
#include "propertylist.h"
#include "key.h"
#include "keylist.h"
#include "keystore.h"
#include "util.h"

namespace cxi
{
  class CXIAPI Cxi
  {
    private:

      std::string vendCert;
      std::string operCert;
      std::string custCert;

      std::vector<std::string> user_attributes;
      std::vector<uint32_t>    user_permissions;
      uint32_t key_manager_perm;

      CXIAPI_LOCAL void init(void);
      CXIAPI_LOCAL void update_permission_cache(const char* user);
      int logon_cert(const unsigned char *user, unsigned int l_user,
              const char *key, const unsigned char *password, unsigned int l_pwd);
    
    protected:
      int  hCS;
      
      void open(const char *device, int timeout = 60000, int ctimeout = 5000);
      void open(const char **devices, int ndevs, int timeout = 60000, int ctimeout = 5000, int fallback_interval = 0);

      Key key_generate(int flags, const PropertyList &keyTemplate, const cxi::MechanismParameter &mechParam);

      bool verify_helper_deprecated_mech_param(ByteArray* cmd, ByteArray* mp, int flags, unsigned int key_len, unsigned char** pp_answ, unsigned int* p_l_answ);
      
    public:
      /**
       * \name Construction / Destruction
       */
      /*@{*/
      Cxi(std::vector<std::string> devices, int timeout, int ctimeout, int fallback_interval, cxi::ByteArray *vendorCert,
          cxi::ByteArray *operatorCert, cxi::ByteArray *customerCert);
      Cxi(const char *device, int timeout = 60000, int ctimeout = 5000);
      Cxi(const char **devices, int ndevs, int timeout = 60000, int ctimeout = 5000, int fallback_interval = 0);
      Cxi(std::vector<std::string> devices, int timeout = 60000, int ctimeout = 5000, int fallback_interval = 0);
      Cxi(Config &config);
      virtual ~Cxi(void);
      /*@}*/ 
      
      void set_msg_handler(void (*p_msg_func)(unsigned char *p_msg, int l_msg));
      void close(void);

      /** 
       * \brief Defines an additional error code/mask that causes the cluster to switch to another device instead of returning to the caller.
       *
       * The switch condition is fulfilled if:
       * \code
       * (error & mask) == code
       * \endcode
       * \see \ref Cxi::exec
       */
      typedef struct
      {
        unsigned int mask;  //!< error mask
        unsigned int code;  //!< error code
      }
      CLUSTER_ERROR;      
      
      /**    
       * \name Miscellaneous Functions
       */
      /*@{*/

      void exec(unsigned int fc, unsigned int sfc, 
                unsigned char *p_cmd, unsigned int l_cmd, 
                unsigned char **pp_answ, unsigned int *p_l_answ,
                CLUSTER_ERROR *errlist = NULL, unsigned int err_ct = 0);

      void free_answ(unsigned char *&p_answ);
      
      static int get_version(void);
      int get_fw_version(void);
      /*@}*/ 
      
      /**
       * \name Authentication
       */
      /*@{*/
      void  logon_sign(const char *user, const char *key, const char *password = 0, bool keep_alive = false);
      void  logon_pass(const char *user, const char *password, bool keep_alive = false);
      void  logoff(void);
      int   get_auth_state(void);
      int   get_auth_state(const std::string& group);
      /*@}*/

      /**
       * \name Key Management
       */
      /*@{*/
      KeyList       key_list(PropertyList *keyTemplate = NULL);
      //deprecated overload taking reference
      KeyList       key_list(PropertyList &keyTemplate);

      Key           key_generate(int flags, const PropertyList &keyTemplate);
      Key           key_generate(int flags, const PropertyList &keyTemplate, int mech);
      Key           key_open(int flags, PropertyList &keyTemplate);
      void          key_delete(const PropertyList &keyTemplate);
      void          key_delete(Key &key);      
      PropertyList  key_prop_get(const Key &key, int properties[], int nprops);
      Key           key_prop_set(const Key &key, const PropertyList &propList);
      Key           key_set_fips_usage(const Key &key, unsigned int usage);
      ByteArray     key_export(int type, Key &key, Key *exportKey, int mech = -1);
      //deprecated overload taking optional Parameter exportKey per Reference
      ByteArray     key_export(int type, Key &key, Key &exportKey, int mech = -1);
      Key           key_import(int flags, int type, const PropertyList &keyTemplate, const ByteArray &keyBlob, Key *importKey, int mech = -1);
      //deprecated overload taking optional Parameter importKey per Reference
      Key           key_import(int flags, int type, const PropertyList &keyTemplate, const ByteArray &keyBlob, Key &importKey, int mech = -1);

      PropertyList  key_dsa_xgen(int psize, int qsize = 160, int mech = -1);
      PropertyList  key_dsa_pqgen(MechanismParameter &mechParam);
      PropertyList  key_dsa_ggen(PropertyList &propList, const MechanismParameter &mechParam);
      Key           key_backup(Key &key);
      Key           key_restore(int flags, Key &key, PropertyList *keyTemplate = NULL);
      //deprecated overload taking keyTemplate per Reference
      Key           key_restore(int flags, Key &key, PropertyList &keyTemplate);

      std::vector<ByteArray> keystore_find(KeyStore &store, PropertyList* key_template = NULL);
      Key           keystore_get(KeyStore &store, ByteArray &index);
      void          keystore_insert(KeyStore &store, int flags, ByteArray *index, const Key *key);
      void          keystore_delete(KeyStore &store, const ByteArray &index);

      /*@}*/

      /**
       * \name Cryptography
       */
      /*@{*/
      ByteArray crypt (int flags, const Key &key, const MechanismParameter &mechParam, const ByteArray &data, ByteArray *iv = NULL,
                       ByteArray *tag = NULL, const ByteArray *tag_in = NULL);

      ByteArray crypt (int flags, const Key &key, const MechanismParameter &mechParam, const ByteArray &data, ByteArray &iv,
                       ByteArray &tag, const ByteArray &tag_in);
      ByteArray crypt (int flags, const Key &key, const MechanismParameter &mechParam, const ByteArray &data, ByteArray &iv,
                       ByteArray &tag);
      ByteArray crypt (int flags, const Key &key, const MechanismParameter &mechParam, const ByteArray &data, ByteArray &iv);

      unsigned int getBufferedDataSize(const ByteArray &iv);
      std::vector<ByteArray> bulk_crypt(const Key &key, const MechanismParameter &mechParam, const std::vector<ByteArray> &data);

      ByteArray sign(int flags, Key &key, const MechanismParameter &mechParam, const ByteArray &data, ByteArray *iv = NULL);
      //deprecated overload taking optional Parameter iv per Reference
      ByteArray sign(int flags, Key &key, const MechanismParameter &mechParam, const ByteArray &data, ByteArray &iv);

      std::vector<ByteArray> bulk_sign(Key &key, const MechanismParameter &mechParam, const std::vector<ByteArray> &data);

      bool verify(int flags, Key &key, const MechanismParameter &mechParam, ByteArray &data, const ByteArray *signature, ByteArray *iv = NULL);
      //deprecated overload taking optional Parameter iv per Reference
      bool verify(int flags, Key &key, const MechanismParameter &mechParam, ByteArray &data, const ByteArray &signature, ByteArray *iv = NULL);
      bool verify(int flags, Key &key, const MechanismParameter &mechParam, ByteArray &data, const ByteArray &signature, ByteArray &iv);
      bool verify(int flags, Key &key, const MechanismParameter &mechParam, ByteArray &data, const ByteArray *signature, ByteArray &iv);

      ByteArray rnd_gen(int len, int mech = -1);
      
      ByteArray hash_compute(int flags, const MechanismParameter &mechParam, const ByteArray *data, const ByteArray *info = NULL, const Key *key = NULL);
      
      //deprecated overload taking optional Parameters per Reference
      ByteArray hash_compute(int flags, const MechanismParameter &mechParam, const ByteArray &data, const ByteArray &info, const Key &key);
      ByteArray hash_compute(int flags, const MechanismParameter &mechParam, const ByteArray &data, const ByteArray *info, const Key &key);
      ByteArray hash_compute(int flags, const MechanismParameter &mechParam, const ByteArray &data, const ByteArray &info);
      ByteArray hash_compute(int flags, const MechanismParameter &mechParam, const ByteArray *data, const ByteArray &info);
      ByteArray hash_compute(int flags, const MechanismParameter &mechParam, const ByteArray &data);

      ByteArray secret_agree(int flags, const Key &privateKey, const Key &publicKey, const MechanismParameter *mechParam = NULL);
      //deprecated overload taking optional Parameter mechParam per Reference
      ByteArray secret_agree(int flags, const Key &privateKey, const Key &publicKey, const MechanismParameter &mechParam);

      /*@}*/
  };
}

// --- BEGIN ERROR CODES ---

#define E_CXI_API                       0xB920      // CryptoServer Core API Cxi

#define E_CXI_API_ALLOC                 0xB9200001  // memory allocation failed
#define E_CXI_API_PARAM                 0xB9200002  // invalid parameter
#define E_CXI_API_PARAM_LEN             0xB9200003  // invalid parameter length
#define E_CXI_API_PARAM_RANGE           0xB9200004  // parameter out of range
#define E_CXI_API_BUF_SIZE              0xB9200005  // buffer size too small
#define E_CXI_API_ANSW_LEN              0xB9200006  // invalid answer length
#define E_CXI_API_ANSW_DATA             0xB9200007  // invalid format of answer data
#define E_CXI_API_STRING_TERM           0xB9200008  // unterminated string
#define E_CXI_API_STRING_CONV           0xB9200009  // string conversion failed
#define E_CXI_API_NOT_FOUND             0xB920000A  // object/item not found
#define E_CXI_API_COMPARE               0xB920000B  // compare failed
#define E_CXI_API_ALGO                  0xB920000C  // invalid algorithm
#define E_CXI_API_STATE                 0xB920000D  // invalid state
#define E_CXI_API_FILE                  0xB920000E  // file error
#define E_CXI_API_USER_NOT_FOUND        0xB920000F  // user does not exist
#define E_CXI_API_NOT_SUPPORTED         0xB9200010  // operation not supported
#define E_CXI_API_INVALID_KEY           0xB9200011  // invalid key
#define E_CXI_API_IO                    0xB9200012  // I/O error
#define E_CXI_API_LOG                   0xB9200013  // log access error
#define E_CXI_API_DB                    0xB9200014  // database access error
#define E_CXI_API_ASN1_FORMAT           0xB9200015  // invalid ASN.1 format
#define E_CXI_API_MEM_CORR              0xB9200016  // memory corruption
#define E_CXI_API_MECHS_LENGTH          0xB9200017  // invalid number of mechs
#define E_CXI_API_PERM_DENIED           0xB9200018  // permission denied

#define E_CXI_API_SYSTEM                0xB9201     // system error

// --- END ERROR CODES ---

#define CXI_SYS_ERR(errno)              ((E_CXI_API_SYSTEM << 12) | ((errno) & 0xFFF))

#endif
