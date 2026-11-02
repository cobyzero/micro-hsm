/**************************************************************************************************
 *
 * Filename           : mechparam.h
 *
 * Author             : Dipl. Ing. Sven Kaltschmidt
 *                      Utimaco IS GmbH
 *
 * Description        : Mechanism Parameter Constructor
 *
 *************************************************************************************************/
#ifndef SW_CXIAPI_C_MECHPARAM_H
#define SW_CXIAPI_C_MECHPARAM_H

#include "cxi.h"

namespace cxi
{
  class CXIAPI Cxi;

  class CXIAPI MechanismParameter : public ByteArray
  {
    // grant Cxi::crypt access to the AAD
    friend class Cxi;

    private:
      ByteArray *aad;

    public:
      MechanismParameter(void);
      MechanismParameter(int mech);
      MechanismParameter(int mech, int mgf_algo, char *label);
      MechanismParameter(int mech, int mgf_algo, int salt_len);

      MechanismParameter(const MechanismParameter &mp);

      void removeAAD();

      void set(int mech);
      void setVDM(int vdmMech, int mode);

      void setOAEP(int mech, int mgf_algo, const char *label);

      void setPSS(int mech, int mgf_algo, int salt_len);

      void setECIES(int mech, int hash_algo,
                    int crypt_algo, int crypt_mech, int crypt_len,
                    int mac_algo, int mac_mech, int mac_len,
                    const char *p_secret1, int  l_secret1,
                    const char *p_secret2, int  l_secret2);

      void setGCM(int mech,
                  const char *p_iv_init, int l_iv_init,
                  const char *p_ad, int l_ad,
                  int tag_bits = 128,
                  int iv_gen_func = CXI_MECH_PARAM_IV_NO_GENERATE);

      void setGMAC(int mech, const char *p_iv_init, int l_iv_init,
                   int iv_gen_func = CXI_MECH_PARAM_IV_NO_GENERATE);

      void setCCM(int mech,
                  const char *p_nonce, unsigned int l_nonce,
                  const char *p_ad, unsigned int l_ad,
                  unsigned int l_data, unsigned int l_mac,
                  int nonce_gen_func = CXI_MECH_PARAM_NONCE_NO_GENERATE);

      // operators
      MechanismParameter& operator= (const MechanismParameter &src);
      void operator|=(const int mech);

      virtual ~MechanismParameter(void);
  };

  // --------------------------------------------------------------------------------

  class CXIAPI MechParam
  {
    public:
      int mech;

      MechParam(void);
      MechParam(int mech);
      MechanismParameter getEncoded(void);
  };

  class CXIAPI MechParamOAEP : public MechParam
  {
    public:
      int hash_algo;
      int mgf_algo;
      std::string label;

      MechParamOAEP(void);
      MechParamOAEP(int mech, int mgf_algo, const std::string &label);
      MechanismParameter getEncoded(void);
  };

  class CXIAPI MechParamPSS : public MechParam
  {
    public:
      int hash_algo;
      int mgf_algo;
      int salt_len;

      MechParamPSS(void);
      MechParamPSS(int mech, int mgf_algo, int salt_len);
      MechanismParameter getEncoded(void);
  };

  class CXIAPI MechParamECIES : public MechParam
  {
    public:
      int hash_algo;
      int crypt_algo;
      int crypt_mech;
      int crypt_len;
      int mac_algo;
      int mac_mech;
      int mac_len;
      ByteArray secret1;
      ByteArray secret2;

      MechParamECIES(void);
      MechParamECIES(int mech, int hash_algo,
                     int crypt_algo, int crypt_mech, int crypt_len,
                     int mac_algo, int mac_mech, int mac_len,
                     const ByteArray &secret1, const ByteArray &secret2);
      MechanismParameter getEncoded(void);
  };

  class CXIAPI MechParamGCM : public MechParam
  {
    public:
      ByteArray iv_init;
      ByteArray ad;
      int tagbits;
      int iv_gen_func;

      MechParamGCM(void);
      MechParamGCM(int mech, const ByteArray &iv_init, const ByteArray &ad, int tagbits = 128, int iv_gen_func = CXI_MECH_PARAM_IV_NO_GENERATE);
      MechanismParameter getEncoded(void);
  };

  class CXIAPI MechParamGMAC : public MechParam
  {
    public:
      ByteArray iv_init;
      int iv_gen_func;

      MechParamGMAC(void);
      MechParamGMAC(int mech, const ByteArray &iv_init, int iv_gen_func = CXI_MECH_PARAM_IV_NO_GENERATE);
      MechanismParameter getEncoded(void);
  };

  class CXIAPI MechParamCCM : public MechParam
  {
    public:
      ByteArray nonce;
      ByteArray ad;
      int datalen;
      int maclen;
      int nonce_gen_func;

      MechParamCCM(void);
      MechParamCCM(int mech, const ByteArray &nonce, const ByteArray &ad, int datalen, int maclen = 16, int nonce_gen_func = CXI_MECH_PARAM_NONCE_NO_GENERATE);
      MechanismParameter getEncoded(void);
  };
}

#endif
