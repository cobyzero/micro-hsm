/**************************************************************************************************
 *
 * $File Identification                    $
 * $Filename          : cxi_defs.h         $
 * $Module version    : x.x.x.x            $
 * $Module name       : CXI                $
 * $Release Date      : DD.MM.YYYY         $
 *
 * Author             : Dipl. Ing. Sven Kaltschmidt
 *                      Utimaco IS GmbH
 *
 * Description        : CryptoServer CXI Interface
 *                      Global Definitions
 *
 **************************************************************************************************/
#ifndef __CXI_DEFS_H
#define __CXI_DEFS_H


/******************************************************************************
 *
 * Definitions
 *
 ******************************************************************************/

/**
 *
 * \defgroup cxi_props Key Properties
 *
 * Key Properties are used to add additional information to a key.
 * Some key properties are mandatory (e.g. algorithm) and have to be set on creation of the key object (generation or import),
 * other properties are optionally (e.g. expiration date) and may be left unset.
 *
 * Some properties are allowed to be modified later (e.g. label), other properties are completely read-only on certain operations (e.g. algorithm).\n
 * Some properties, the so called 'virtual' properties, are not stored with the key object and evaluated on demand (e.g. block length, RSA modulus).
 *
 * @{
 */
// clang-format off
#define CXI_PROP_KEY_GROUP                      1   //!< Key group name (default: empty) [array<byte>]
#define CXI_PROP_KEY_NAME                       2   //!< Key name (default: empty) [array<byte>]
#define CXI_PROP_KEY_ALGO                       3   //!< Algorithm specifier, see \ref cxi_algos [int]
#define CXI_PROP_KEY_SIZE                       4   //!< Key size in bits [int]
#define CXI_PROP_KEY_EXPORT                     5   //!< Export permission (bit field), see \ref cxi_export [int]
#define CXI_PROP_KEY_USAGE                      6   //!< Key usage specifier (bit field), see \ref cxi_usage [int]
#define CXI_PROP_KEY_MECHS                      7   //!< Mechanisms allowed to be used with this key, see \ref cxi_mech_mode, \ref cxi_mech_chain, \ref cxi_mech_pad, \ref cxi_mech_hash, \ref cxi_mech_kdf [array<int>]
#define CXI_PROP_KEY_SPEC                       8   //!< Additional key specifier [int]
#define CXI_PROP_KEY_LABEL                      9   //!< Label (default: empty) [array<byte>]
#define CXI_PROP_KEY_BLEN                       10  //!< Block length of algorithm in bytes (virtual) [int]
#define CXI_PROP_KEY_UNAME                      11  //!< Unique key name / database index (virtual) [array<byte>]
#define CXI_PROP_KEY_TYPE                       12  //!< Key type, see \ref cxi_types [int]
#define CXI_PROP_KEY_DATE_GEN                   13  //!< Generation date / start of validity period (default: empty) [yymmddhhmmss]
#define CXI_PROP_KEY_CERT                       14  //!< Certificate associated with the key [array<byte>]
#define CXI_PROP_KEY_DATE_EXP                   15  //!< Expiration date / end of validity period (default: empty) [yymmddhhmmss]

#define CXI_PROP_KEY_RSA_MOD                    20  //!< RSA modulus (virtual, can't be set) (virtual) [array<byte>]
#define CXI_PROP_KEY_RSA_EXP                    21  //!< RSA public exponent (default: '010001') (virtual) [array<byte>]

#define CXI_PROP_KEY_DSA_P                      25  //!< DSA domain parameter: prime P [array<byte>]
#define CXI_PROP_KEY_DSA_Q                      26  //!< DSA domain parameter: prime Q [array<byte>]
#define CXI_PROP_KEY_DSA_G                      27  //!< DSA domain parameter: generator [array<byte>]
#define CXI_PROP_KEY_DSA_PUBKEY                 28  //!< DSA public key (virtual) [array<byte>]

#define CXI_PROP_KEY_EC_CURVE                   30  //!< Elliptic curve name (string) or domain parameter (OID or ASN.1 definition) [array<byte>]
#define CXI_PROP_KEY_EC_PUBKEY                  31  //!< Elliptic curve public key (virtual) [array<byte>]
/*@}*/

#define CXI_PROP_CNG_SECURITY_DESCRIPTOR        35  // Windows security descriptor, evaluated by CNG provider

#define CXI_PROP_PKCS11_BEGIN                   38
#ifdef CXI_PKCS11
#define CXI_PROP_TOKEN                          38
#define CXI_PROP_PRIVATE                        39
#define CXI_PROP_APPLICATION                    40
#define CXI_PROP_VALUE                          41
#define CXI_PROP_OBJECT_ID                      42
#define CXI_PROP_CERTIFICATE_TYPE               43
#define CXI_PROP_CHECK_VALUE                    44
#define CXI_PROP_ISSUER                         45
#define CXI_PROP_SERIAL_NUMBER                  46
#define CXI_PROP_AC_ISSUER                      47
#define CXI_PROP_OWNER                          48
#define CXI_PROP_ATTR_TYPES                     49
#define CXI_PROP_TRUSTED                        50
#define CXI_PROP_SUBJECT                        51
#define CXI_PROP_ID                             52
#define CXI_PROP_SENSITIVE                      53
#define CXI_PROP_ENCRYPT                        54
#define CXI_PROP_DECRYPT                        55
#define CXI_PROP_WRAP                           56
#define CXI_PROP_UNWRAP                         57
#define CXI_PROP_SIGN                           58
#define CXI_PROP_SIGN_RECOVER                   59
#define CXI_PROP_VERIFY                         60
#define CXI_PROP_VERIFY_RECOVER                 61
#define CXI_PROP_DERIVE                         62
#define CXI_PROP_KEY_RSA_EXP2                   63
#define CXI_PROP_KEY_RSA_P                      64
#define CXI_PROP_KEY_RSA_Q                      65
#define CXI_PROP_KEY_RSA_DP                     66
#define CXI_PROP_KEY_RSA_DQ                     67
#define CXI_PROP_KEY_RSA_U                      68
#define CXI_PROP_KEY_DSA_P_BITS                 69
#define CXI_PROP_KEY_DSA_Q_BITS                 70
#define CXI_PROP_VALUE_BITS                     71
#define CXI_PROP_VALUE_LEN                      72
#define CXI_PROP_EXTRACTABLE                    73
#define CXI_PROP_LOCAL                          74
#define CXI_PROP_NEVER_EXTRACTABLE              75
#define CXI_PROP_ALWAYS_SENSITIVE               76
#define CXI_PROP_KEY_GEN_MECHANISM              77
#define CXI_PROP_MODIFIABLE                     78
#define CXI_PROP_WRAP_WITH_TRUSTED              79
#define CXI_PROP_ALWAYS_AUTHENTICATE            80
#define CXI_PROP_HW_FEATURE_TYPE                81
#define CXI_PROP_WRAP_TEMPLATE                  82
#define CXI_PROP_UNWRAP_TEMPLATE                83
#define CXI_PROP_CERTIFICATE_CATEGORY           84
#define CXI_PROP_JAVA_MIDP_SECURITY_DOMAIN      85
#define CXI_PROP_URL                            86
#define CXI_PROP_HASH_OF_SUBJECT_PUBLIC_KEY     87
#define CXI_PROP_HASH_OF_ISSUER_PUBLIC_KEY      88
#define CXI_PROP_PUBLIC_VDM_DATA                89
#endif
#define CXI_PROP_PKCS11_END                     89

#define CXI_PROP_CFG_ALLOW_GROUPS               90
#define CXI_PROP_CFG_CHECK_VALIDITY_PERIOD      91
#define CXI_PROP_CFG_AUTH_PLAIN                 92
#define CXI_PROP_CFG_WRAP_POLICY                93
// added as of 2.0.9.0
#define CXI_PROP_CFG_AUTH_KEYM                  94
#define CXI_PROP_CFG_AUTH_USER                  95
#define CXI_PROP_CFG_SECURE_DERIVATION          96
#define CXI_PROP_CFG_SECURE_IMPORT              97
#define CXI_PROP_CFG_SECURE_RSA_COMPONENTS      98
#define CXI_PROP_CFG_P11R2_BACKWARDS_COMPATIBLE 99
// added as of 2.1.12.2
#define CXI_PROP_CFG_ENFORCE_BLINDING           100

#define CXI_PROP_CFG_SECURE_GROUP_BACKUP        101
#define CXI_PROP_CFG_GROUP_BACKUP_PASS_HASH     102


// added for CC key authorisation
#define CXI_PROP_CC_KRAD                        103     // [Protocl ID][ 0xC0 ][VRSA_KC_PUB][ l_mod ][ mod ][ l_exp ][ exp ]
                                                        // [  1 Byte  ][1 Byte][   1 Byte  ][2 Byte ][l_mod][2 Byte ][l_exp]

#define CXI_PROP_CC_ASSIGNED                    104     // not set: key is not initialised | true: key is assigned | false: key is general
#define CXI_PROP_CC_AUTH_FAIL_COUNTER           105
#define CXI_PROP_CC_AUTH_COUNTER                106     // (virtual, can't be set) authorisation counter

#define CXI_PROP_CFG_ENFORCE_EXT_KEYS           107
#define CXI_PROP_CFG_ALLOW_WEAK_DES_KEYS        108

// added for FIPS specific checks
#define CXI_PROP_FIPS_KEY_USAGE_PADDING         109  //!< Key usage / padding property (bit field) for FIPS, see \ref cxi_fips_usage [int]

// added for KSV signature counter
#define CXI_PROP_COUNTER_SIGNATURES             110

// added unique ID as property
#define CXI_PROP_UNIQUE_ID                      111

// added for CC specific checks
#define CXI_PROP_CC_KEY_USAGE                   112  //!< Key usage property (bit field) for CC, see \ref cxi_cc_usage [int]

#define CXI_PROP_PARAMETER_SET                  113

#define CXI_PROP_MAX                            114

#define CXI_PROP_MAX_STR                        ( 257 ) // maximum string size including terminating zero
#define CXI_PROP_MAX_STR_UNICODE                ( CXI_PROP_MAX_STR + 3 ) // maximum string size including terminating zero and {U} tag for UTF-16 encoded strings
// clang-format on

/**
 * \ingroup cxi_props
 * \defgroup cxi_algos Algorithm Specifier
 * @{
 */
#define CXI_KEY_ALGO_RAW   0                  //!< Raw data object
#define CXI_KEY_ALGO_DES   1                  //!< DES
#define CXI_KEY_ALGO_AES   2                  //!< AES
#define CXI_KEY_ALGO_RSA   3                  //!< RSA
#define CXI_KEY_ALGO_ECDSA 4                  //!< ECDSA
#define CXI_KEY_ALGO_EC    CXI_KEY_ALGO_ECDSA //!< == CXI_KEY_ALGO_ECDSA
#define CXI_KEY_ALGO_DSA   5                  //!< DSA
#define CXI_KEY_ALGO_ECDH  6                  //!< EC Diffie-Hellman
#define CXI_KEY_ALGO_DH    7                  //!< Diffie-Hellman according to X9.42 (domain parameter P,Q,G)
#ifdef CXI_PKCS11
#define CXI_KEY_ALGO_DH_PKCS    8          //!< Diffie-Hellman according to PKCS#11 (domain parameter P,G)
#define CXI_KEY_ALGO_X509       9          //!< X509 certificate
#define CXI_KEY_ALGO_X509_ATT   10         //!< X509 attribute certificate
#define CXI_KEY_ALGO_EC_EDWARDS 11         //!< EC key on edwads curve
#define CXI_KEY_ALGO_SLH_DSA    12         //!< SLH-DSA (FIPS 205)
#define CXI_KEY_ALGO_CUSTOM     0x80000000 //!< Custom type for VDM use
#endif
/*@}*/


/**
* \ingroup cxi_props
* \defgroup cxi_limits Key Size Limitations
* @{
*/
#define CXI_KEY_RAW_SIZE_MIN 8 * 4    //!< Minimum raw data object size in bits
#define CXI_KEY_RAW_SIZE_MAX 8 * 1024 //!< Maximum raw data object size in bits
/*@}*/

/**
 * \ingroup cxi_props
 * \defgroup cxi_export Export Policy Specifier
 * \note bit field
 * @{
 */
#define CXI_KEY_EXPORT_DENY        0x00000000 //!< Deny key export (default)
#define CXI_KEY_EXPORT_ALLOW       0x00000001 //!< Allow wrapped key export
#define CXI_KEY_EXPORT_ALLOW_PLAIN 0x00000002 //!< Allow clear text key export
#define CXI_KEY_EXPORT_DENY_BACKUP 0x00010000 //!< Deny key backup (wrapped key export with MBK)
/*@}*/

/**
 * \ingroup cxi_props
 * \defgroup cxi_usage Usage Specifier
 * \note bit field
 * @{
 */
#define CXI_KEY_USAGE_DECRYPT        0x00000001 //!< Allow decryption
#define CXI_KEY_USAGE_SIGN           0x00000002 //!< Allow signature creation
#define CXI_KEY_USAGE_DERIVE         0x00000004 //!< Allow key derivation
#define CXI_KEY_USAGE_WRAP           0x00000008 //!< Allow key wrapping (export)
#define CXI_KEY_USAGE_ENCRYPT        0x00000010 //!< Allow encryption
#define CXI_KEY_USAGE_VERIFY         0x00000020 //!< Allow signature verification
#define CXI_KEY_USAGE_UNWRAP         0x00000080 //!< Allow key unwrapping (import)
#define CXI_KEY_USAGE_VERIFY_RECOVER 0x00000200 //!< Allow signature verification where original data can be restored

#define CXI_KEY_USAGE_ALL 0xFFFFFFFF //!< Allow all usages
/*@}*/

/**
* \ingroup cxi_props
* \defgroup cxi_fips_usage Usage / Padding Specifier for FIPS
* \note bit field
* @{
*/
#define CXI_KEY_FIPS_USAGE_NO_SIGN  0x00000000
#define CXI_KEY_FIPS_USAGE_RSA_PKCS 0x00000001
#define CXI_KEY_FIPS_USAGE_RSA_PSS  0x00000002
#define CXI_KEY_FIPS_USAGE_RSA_X_31 0x00000003
#define CXI_KEY_FIPS_USAGE_OTHER    0xFFFFFFFF
/*@}*/

/**
* \ingroup cxi_props
* \defgroup cxi_cc_usage Usage Specifier for CC
* \note bit field
* @{
*/
#define CXI_KEY_CC_USAGE_SIGN   0x00000000
#define CXI_KEY_CC_USAGE_CRYPT  0x00000001
#define CXI_KEY_CC_USAGE_WRAP   0x00000002
#define CXI_KEY_CC_USAGE_DERIVE 0x00000003
#define CXI_KEY_CC_USAGE_OTHER  0xFFFFFFFF
/*@}*/

/**
 * \ingroup cxi_props
 * \defgroup cxi_types Key Types
 * @{
 */
#define CXI_KEY_TYPE_PUBLIC       0x00000001 //!< Public key object
#define CXI_KEY_TYPE_PRIVATE_ONLY 0x00000002 //!< Private key object (without public components)
#define CXI_KEY_TYPE_PRIVATE      0x00000003 //!< Private key object (contains also public components)
#define CXI_KEY_TYPE_PRIVATE_FULL 0x00000007 //!< rfu
#define CXI_KEY_TYPE_SECRET       0x00000008 //!< Secrect key object
#define CXI_KEY_TYPE_PLAINTEXT    0x00000010 //!< Secret key object in plain (only used as type parameter on key export)
#ifdef CXI_PKCS11
#define CXI_KEY_TYPE_DATA             0x00000020 //!< Data object
#define CXI_KEY_TYPE_CERT             0x00000021 //!< Certificate object
#define CXI_KEY_TYPE_DOMAIN_PARAMETER 0x00000022 //!< DSA Domain parameter
#endif
#define CXI_KEY_TYPE_CONFIG 0x00000030 //!< Configuration object

#define CXI_KEY_TYPE_MASK 0x000000FF
/*@}*/

/**
 * \ingroup cxi_props
 * \defgroup cxi_blobs Blob Types
 * @{
 */
#define CXI_KEY_BLOB_SIMPLE    0x00010000 //!< Simple blob format (Utimaco)
#define CXI_KEY_BLOB_MS_BCRYPT 0x00020000 //!< CNG blob format (Microsoft)
#define CXI_KEY_BLOB_MS_LEGACY 0x00030000 //!< CSP blob format (Microsoft)

#define CXI_KEY_BLOB_MASK 0x00FF0000
/*@}*/

/**
 *
 * \defgroup cxi_mechs Mechanism Parameter
 * \note bit field
 *
 */

/**
 * \ingroup cxi_mechs
 * \defgroup cxi_mech_kdf Key Derivation Functions
 * @{
 */
#define CXI_MECH_KDF_HASH 0x10000000 //!< Derive key using result of hash calculation
#define CXI_MECH_KDF_HMAC 0x20000000 // no longer used

#define CXI_MECH_KDF_ENC_DATA             0x40000000 //!< Derive key using result of data encryption
#define CXI_MECH_KDF_ECDH                 0x50000000 //!< Derive key using result of hash calculation over shared secret
#define CXI_MECH_KDF_ECDH_COF             0x60000000 //!< Same as CXI_MECH_KDF_ECDH but include curve cofactor into hash calculation
#define CXI_MECH_KDF_DH                   0x70000000 //!< Derive key using result of hash calculation over shared secret
#define CXI_MECH_KDF_XOR_BASE_AND_DATA    0x80000000 //!< XOR a base key and given data to derive key
#define CXI_MECH_KDF_CAT_BASE_AND_KEY     0x90000000 //!< Concatenate a base key with a second key to derive key
#define CXI_MECH_KDF_CAT_BASE_AND_DATA    0xA0000000 //!< Concatenate a base key with given data to derive key
#define CXI_MECH_KDF_CAT_DATA_AND_BASE    0xB0000000 //!< Concatenate given data with a base key to derive key
#define CXI_MECH_KDF_EXTRACT_KEY_FROM_KEY 0xC0000000 //!< Extract part of a base key to derive key
#define CXI_MECH_KDF_TLS12_PRF            0xD0000000 //!< Derive key as defined in RFC 5246 section 5

#define CXI_MECH_KDF_MASK    0xF0000000
#define CXI_MECH_KDF_INVALID CXI_MECH_KDF_MASK
/*@}*/

/**
 * \ingroup cxi_mechs
 * \defgroup cxi_mech_mode Mode Parameter
 * @{
 */
#define CXI_MECH_MODE_HASH 0x00000000 //!< calculate HASH
#define CXI_MECH_MODE_HMAC 0x01000000 //!< calculate HMAC

#define CXI_MECH_MODE_ENCRYPT 0x02000000 //!< Encryption mode
#define CXI_MECH_MODE_DECRYPT 0x03000000 //!< Decryption mode

#define CXI_MECH_MODE_MAC_SINGLE 0x04000000 //!< Calculate MAC in a single operation
#define CXI_MECH_MODE_MAC1       0x05000000 //!< Calculate ECIES MAC1

#define CXI_MECH_MODE_MASK    0x0F000000
#define CXI_MECH_MODE_INVALID CXI_MECH_MODE_MASK
/*@}*/

/**
* \ingroup cxi_mechs
* \defgroup cxi_mech_ecdsa_mode ECDSA Mode
* @{
*/
#define CXI_MECH_ECDSA_MODE_DCC 0x00100000 //!< Enables ECDSA signature DCC like

#define CXI_MECH_ECDSA_MODE_MASK    0x00F00000
#define CXI_MECH_ECDSA_MODE_INVALID CXI_MECH_ECDSA_MODE_MASK
/*@}*/

/**
 * \ingroup cxi_mechs
 * \defgroup cxi_mech_chain Chaining Modes
 * @{
 */
#define CXI_MECH_CHAIN_ECB        0x00000000 //!< Electronic Codebook chaining
#define CXI_MECH_CHAIN_CBC        0x00100000 //!< Cipher Block Chaining
#define CXI_MECH_CHAIN_CBC_RETAIL 0x00200000 //!< CBC Retail MAC (DES)
#define CXI_MECH_CHAIN_CMAC       0x00300000 //!< AES CMAC
#define CXI_MECH_CHAIN_CFB_RETAIL 0x00400000 //!< CFB Retail MAC (DES)
#define CXI_MECH_CHAIN_CTR        0x00500000 //!< Counter block chaining (AES)
#define CXI_MECH_CHAIN_GCM        0x00600000 //!< Galois Counter Mode (AES)
#define CXI_MECH_CHAIN_OFB        0x00700000 //!< Output Feedback Mode (AES)
#define CXI_MECH_CHAIN_CCM        0x00800000 //!< CTR with CBC-MAC (AES)
#define CXI_MECH_CHAIN_KEY_WRAP   0x00900000 //!< Key Wrap NIST SP800-38F (AES)

#define CXI_MECH_CHAIN_MASK    0x00F00000
#define CXI_MECH_CHAIN_INVALID CXI_MECH_CHAIN_MASK
/*@}*/

/**
* \ingroup cxi_mechs
* \defgroup cxi_mech_invalid invalid mechanism flag (used to mark breaking change)
* @{
*/
#define CXI_MECH_INVALID_FLAG \
    0x000D0000 //!< Invalid mechanism flag, should not be used as single flag as well as result of other flags

#define CXI_MECH_INVALID_MASK 0x000D0000
/*@}*/

/**
* \ingroup cxi_mechs
* \defgroup cxi_mech_ext mechanism extension flag
* @{
*/
#define CXI_MECH_EXT_FLAG 0x00080000 //!< Use extended cxi mechanism parameter (RFU)

#define CXI_MECH_EXT_MASK 0x00080000
/*@}*/

/**
* \ingroup cxi_mechs
* \defgroup cxi_mech_vdm vendor defined mechanism flag
* @{
*/
#define CXI_MECH_VDM_FLAG 0x00010000 //!< Vendor defined mechanism, defined by next byte, rest of this byte is ignored

#define CXI_MECH_VDM_MASK 0x00010000
/*@}*/

/**
 * \ingroup cxi_mechs
 * \defgroup cxi_mech_pad Padding Modes
 * @{
 */
#define CXI_MECH_PAD_NONE    0x00000000 //!< Don't apply padding
#define CXI_MECH_PAD_PKCS5   0x00001000 //!< Apply padding according to PKCS#5
#define CXI_MECH_PAD_RANDOM  0x00002000 //!< Apply random padding
#define CXI_MECH_PAD_ISO7816 0x00003000 //!< Apply padding according to ISO7816
#define CXI_MECH_PAD_PKCS1   0x00004000 //!< Apply padding according to PKCS#1_v1.5
#define CXI_MECH_PAD_OAEP    0x00005000 //!< Apply padding according to PKCS#1_v2.1 RSAES-OAEP
#define CXI_MECH_PAD_PSS     0x00006000 //!< Apply padding according to PKCS#1_v2.1 RSASSA-PSS
#define CXI_MECH_PAD_X9_31   0x00007000 //!< Apply padding according to ANSI X9.31
#define CXI_MECH_PAD_ZERO    0x00008000 //!< Pad with zeros up to block length
#define CXI_MECH_PAD_KWP     0x00009000 //!< Pad for key wrap NIST SP800-38F (AES)

#define CXI_MECH_PAD_MASK    0x0000F000
#define CXI_MECH_PAD_INVALID CXI_MECH_PAD_MASK
/*@}*/

/**
 * \ingroup cxi_mechs
 * \defgroup cxi_mech_dpgen Domain Generation Parameter
 * @{
 */
#define CXI_MECH_DPGEN_DP            0x00000000 //!< Create DSA domain parameters
#define CXI_MECH_DPGEN_DP_FIPS_186_4 0x00000100 //!< Create DSA domain parameters conform to FIPS 186-4
#define CXI_MECH_DPGEN_DP_FIPS186_4  (CXI_MECH_DPGEN_DP_FIPS_186_4)

#define CXI_MECH_DPGEN_MASK         0x00000100
#define CXI_MECH_DPGEN_MASK_INVALID CXI_MECH_DPGEN_MASK
/*@}*/

/**
 * \ingroup cxi_mechs
 * \defgroup cxi_mech_nist_sp800 Apply NIST SP800-56A
 * @{
 */
#define CXI_MECH_NIST_SP800_56A 0x00000200 //!< Apply NIST SP800-56A

#define CXI_MECH_NIST_SP800_56A_MASK         0x00000200
#define CXI_MECH_NIST_SP800_56A_MASK_INVALID CXI_MECH_NIST_SP800_56A_MASK
/*@}*/


/**
 * \ingroup cxi_mechs
 * \defgroup cxi_mech_format Format Parameter
 * @{
 */
#define CXI_MECH_FORMAT_ASN1            0x00000400 //!< Create ASN1 format
#define CXI_MECH_FORMAT_STRIP_LEAD_ZERO 0x00000000 //!< Strip leading zeros
#define CXI_MECH_FORMAT_KEEP_LEAD_ZERO  0x00000800 //!< Keep leading zeros
#define CXI_MECH_FORMAT_X               0x00000800 //!< x coordinate only

#define CXI_MECH_FORMAT_MASK         0x00000C00
#define CXI_MECH_FORMAT_MASK_INVALID CXI_MECH_FORMAT_MASK
/*@}*/

/**
 * \ingroup cxi_mechs
 * \defgroup cxi_mech_hash Hash Algorithms
 * @{
 */
#define CXI_MECH_HASH_ALGO_NONE       0x00000000 //!< Don't hash
#define CXI_MECH_HASH_ALGO_SHA1       0x00000010 //!< SHA1
#define CXI_MECH_HASH_ALGO_RMD160     0x00000020 //!< RipeMD160
#define CXI_MECH_HASH_ALGO_SHA224     0x00000030 //!< SHA224
#define CXI_MECH_HASH_ALGO_SHA256     0x00000040 //!< SHA256
#define CXI_MECH_HASH_ALGO_MD5        0x00000050 //!< MD5
#define CXI_MECH_HASH_ALGO_SHA384     0x00000060 //!< SHA384
#define CXI_MECH_HASH_ALGO_SHA512     0x00000070 //!< SHA512
#define CXI_MECH_HASH_ALGO_SHA3_224   0x00000080 //!< SHA3-224
#define CXI_MECH_HASH_ALGO_SHA3_256   0x00000090 //!< SHA3-256
#define CXI_MECH_HASH_ALGO_SHA3_384   0x000000A0 //!< SHA3-384
#define CXI_MECH_HASH_ALGO_SHA3_512   0x000000B0 //!< SHA3-512
#define CXI_MECH_HASH_ALGO_SHA512_224 0x000000C0 //!< SHA512-224
#define CXI_MECH_HASH_ALGO_SHA512_256 0x000000D0 //!< SHA512-256
#define CXI_MECH_HASH_ALGO_SHAKE128   0x00000002 //!< SHAKE128
#define CXI_MECH_HASH_ALGO_SHAKE256   0x00000004 //!< SHAKE256

#define CXI_MECH_HASH_ALGO_MASK    0x000000FE
#define CXI_MECH_HASH_ALGO_INVALID CXI_MECH_HASH_ALGO_MASK
/*@}*/

/**
 * \ingroup cxi_mechs
 * \defgroup cxi_mech_rnd Random Generation Parameter
 * @{
 */
#define CXI_MECH_RND_REAL   0x00000000 //!< Use hybrid random number generator in 'Real' mode
#define CXI_MECH_RND_PSEUDO 0x00000001 //!< Use hybrid random number generator in 'Pseudo' mode

#define CXI_MECH_RND_MASK         0x00000001
#define CXI_MECH_RND_MASK_INVALID CXI_MECH_RND_MASK
/*@}*/

/**
 * \ingroup cxi_mechs
 * \defgroup cxi_mech_keygen Key Generation Parameter
 * @{
 */
#define CXI_MECH_KEYGEN_PROB_PRIME      0x00000000 //!< Create probable prime numbers according to Miller-Rabin
#define CXI_MECH_KEYGEN_PROV_PRIME      0x00000002 //!< Create proven prime numbers according to Maurer
#define CXI_MECH_KEYGEN_ANSI_PRIME      0x00000004 //!< Create prime numbers according to ANSI
#define CXI_MECH_KEYGEN_FIPS_PRIME      0x00000006 //!< Create prime numbers according to FIPS 186 (currently FIPS 186-5)
#define CXI_MECH_KEYGEN_FIPS1864_PRIME  (CXI_MECH_KEYGEN_FIPS_PRIME) //!< deprecated, use CXI_MECH_KEYGEN_FIPS_PRIME
#define CXI_MECH_KEYGEN_FIPS186_4_PRIME (CXI_MECH_KEYGEN_FIPS_PRIME) //!< deprecated, use CXI_MECH_KEYGEN_FIPS_PRIME

#define CXI_MECH_KEYGEN_COMP   0x00000002 //!< Public key in compressed form
#define CXI_MECH_KEYGEN_UNCOMP 0x00000004 //!< Public key in uncompressed form
#define CXI_MECH_KEYGEN_HYBRID 0x00000006 //!< Public key in hybrid form

#define CXI_MECH_KEYGEN_MASK 0x00000006
/*@}*/

/**
 * \ingroup cxi_ext
 * \defgroup cxi_flags Function Flags
 * @{
 */
#define CXI_FLAG_KEY_OVERWRITE  0x00000001 //!< Overwrite key if already existing
#define CXI_FLAG_KEY_EXTERNAL   0x00000002 //!< Don't store key on CryptoServer but return MBK encrypted Backup Blob
#define CXI_FLAG_KEY_VOLATILE   0x00000004 //!< Store key volatile (until next restart)
#define CXI_FLAG_VERIFY_RECOVER 0x00000010 //!< Recover decrypted signature
#define CXI_FLAG_HASH_PART      0x00000020 //!< Don't finalize hash, return hash digest info instead
#define CXI_FLAG_HASH_DATA      0x00000040 //!< Given data has to be hashed
#define CXI_FLAG_ENCRYPT_SECRET 0x00000080 //!< Encrypt shared secret with MBK

#define CXI_FLAG_CRYPT_INIT        0x00000100 //!< Initialize En/Decryption Operation
#define CXI_FLAG_CRYPT_FINAL       0x00000200 //!< Finalize En/Decryption Operation
#define CXI_FLAG_CRYPT_SINGLE_CALL (CXI_FLAG_CRYPT_INIT | CXI_FLAG_CRYPT_FINAL)
#define CXI_FLAG_CRYPT_INTERNAL    0x00000400 //!< Reserved for internal use

// for backward compatibility
#define CXI_KEY_FLAG_OVERWRITE CXI_FLAG_KEY_OVERWRITE
#define CXI_KEY_FLAG_EXTERNAL  CXI_FLAG_KEY_EXTERNAL
#define CXI_KEY_FLAG_VOLATILE  CXI_FLAG_KEY_VOLATILE
/*@}*/


/**
 * \defgroup cxi_ext External Interface
 * @{
 */
#define CXI_MDL_ID 0x68 //!< Module ID of CXI firmware module
/*@}*/

/**
 * \ingroup cxi_ext
 * \defgroup cxi_sfc Sub Function Codes
 * @{
 */
#define CXI_SFC_CHECK_GENUINENESS 0 //!< deprecated, use Secure Messaging with Mutual Authentication instead
#define CXI_SFC_GET_INFO          1 //!< Retrieve some information about the CXI firmware module
#define CXI_SFC_GET_PERSKEY       2 //!< deprecated, use Secure Messaging with Mutual Authentication instead

#define CXI_SFC_KEY_INIT     5  //!< Delete all keys for a given group
#define CXI_SFC_KEY_HASH_GET 6  //!< deprecated, use CXI_SFC_HASH_COMPUTE instead
#define CXI_SFC_KEY_DSA_XGEN 7  //!< Generate DSA domain parameter (P,Q,G)
#define CXI_SFC_KEY_BACKUP   8  //!< Backup key as Backup Blob
#define CXI_SFC_KEY_RESTORE  9  //!< Restore key from Backup Blob
#define CXI_SFC_KEY_LIST     10 //!< List Keys stored on CryptoServer
#define CXI_SFC_KEY_GENERATE 11 //!< Generate a key
#define CXI_SFC_KEY_OPEN     12 //!< Find a named key on the CryptoServer and return reference (Key Handle)
#define CXI_SFC_KEY_DELETE   13 //!< Delete a key on the CryptoServer
#define CXI_SFC_KEY_PROP_GET 14 //!< Retrieve a key property
#define CXI_SFC_KEY_PROP_SET 15 //!< Set a key property
#define CXI_SFC_KEY_EXPORT   16 //!< Export key components
#define CXI_SFC_KEY_IMPORT   17 //!< Import key components
#define CXI_SFC_HASH_COMPUTE 18 //!< Compute a hash over given data

#define CXI_SFC_CRYPT        20 //!< Encrypt or Decrypt data
#define CXI_SFC_SIGN         21 //!< Create a digital signature
#define CXI_SFC_VERIFY       22 //!< Verify a digital signature
#define CXI_SFC_RND_GEN      23 //!< Generate random bytes
#define CXI_SFC_SECRET_AGREE 24 //!< Secret Agreement according to TR-03111

#define CXI_SFC_OBJ_CREATE    25 //!< Create key or data object
#define CXI_SFC_KEY_PAIR_GEN  26 //!< Generate a key pair create public and private object
#define CXI_SFC_OBJ_COPY      27 //!< Copy key or data object
#define CXI_SFC_KEY_DERIVE    28 //!< Derive key from a base key
#define CXI_SFC_KEY_WRAP      29 //!< Export key wrapped with a key encryption key
#define CXI_SFC_KEY_UNWRAP    30 //!< Import key wrapped with a key encryption key
#define CXI_SFC_USER_ADD      33 //!< Create user or key manager
#define CXI_SFC_USER_DELETE   34 //!< Delete user or key manager
#define CXI_SFC_KEY_DSA_PQGEN 35 //!< Generate DSA domain parameter (P,Q)
#define CXI_SFC_KEY_DSA_GGEN  36 //!< Generate DSA domain parameter (G)

#define CXI_SFC_P11_PERMISSIONS 42 //!< P11 permissions for a given group
                                   /*@}*/

/**
 * \defgroup Attribute types
 * @{
 */
#define CXI_ATD_BOOL   (1) //!< Attribute is of type BOOL
#define CXI_ATD_INT    (2) //!< Attribute is of type INT
#define CXI_ATD_CHAR   (3) //!< Attribute is of type byte buffer
#define CXI_ATD_DATE   (4) //!< Attribute is of type DATE
#define CXI_ATD_INTA   (5) //!< Attribute is of type INT ARRAY
#define CXI_ATD_TEMP   (6) //!< internal. do not use.
#define CXI_ATD_STRING (7) //!< Attribute is of STRING

/*@}*/

/**
 * \ingroup cxi_mech_param
 * \defgroup cxi_mech_param IV/Nonce Generation functions
 * @{
 */
#define CXI_MECH_PARAM_IV_NO_GENERATE    (0)
#define CXI_MECH_PARAM_IV_GENERATE       (1)
#define CXI_MECH_PARAM_NONCE_NO_GENERATE CXI_MECH_PARAM_IV_NO_GENERATE
#define CXI_MECH_PARAM_NONCE_GENERATE    CXI_MECH_PARAM_IV_GENERATE


#endif
