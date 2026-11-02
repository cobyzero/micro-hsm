/**************************************************************************************************
 *
 * Filename           : cxi_demo.cpp
 *
 * Author             : Dipl. Ing. Sven Kaltschmidt
 *                      Utimaco IS GmbH
 *
 * Description        : CXI API demo application
 *                      
 * Last modified      : 23.05.2019
 *
 *
 *************************************************************************************************/
#include <stdio.h>
#ifdef WIN32
#include <windows.h>
#include <io.h>
#include <conio.h>
#include <direct.h>

#define strcasecmp  _stricmp
#define strncasecmp _strnicmp
#ifndef snprintf
#define snprintf _snprintf
#endif
#define mkdir(a, b) _mkdir((a))
#define access      _access

#pragma warning(disable : 4786)

#else
#include <errno.h>
#include <dlfcn.h>
#include <unistd.h>
#include <strings.h>
#include <sys/stat.h>

#define MAX_PATH 260
#endif

#include <stdlib.h>
#include <string.h>
#ifndef NOHAVE_MALLOC_H
#include <malloc.h>
#endif
#include <time.h>
#include <iostream>

#include <cxi.h>

using namespace cxi;
using namespace std;

/******************************************************************************
 *
 * Version
 *
 ******************************************************************************/
#define CXI_DEMO_VERSION "1.0.9"
#define CXI_DEMO_DATE    __DATE__

/******************************************************************************
 *
 * Macros
 *
 ******************************************************************************/
#define CLEANUP(e)    \
    {                 \
        err = (e);    \
        goto cleanup; \
    }
#define DIM(x) (sizeof((x)) / sizeof((x[0])))

#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

#ifndef MAX
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#endif

/******************************************************************************
 *
 * Globals 
 *
 ******************************************************************************/
static char* AlgoNames[] =
  {(char*)"RAW", (char*)"DES", (char*)"AES", (char*)"RSA", (char*)"ECDSA", (char*)"DSA", (char*)"ECDH", (char*)"DH"};

static char* Group = NULL;

/******************************************************************************
*
* cxi_demo_aes_mac
*
******************************************************************************/
void cxi_demo_aes_mac(Cxi* cxi)
{
    printf("AES_CBC MAC demo...\n");

    PropertyList keyTemplate;
    keyTemplate.setAlgo(CXI_KEY_ALGO_AES);
    keyTemplate.setSize(128);
    keyTemplate.setName("test key");

    // Generate the key
    Key key = cxi->key_generate(CXI_FLAG_KEY_OVERWRITE, keyTemplate);

    // Make two mechanisms. One with zero padding and one with PKCS5 padding
    MechanismParameter mechParamZeroPadding  = MechanismParameter(CXI_MECH_CHAIN_CBC | CXI_MECH_PAD_ZERO);
    MechanismParameter mechParamPKCS5Padding = MechanismParameter(CXI_MECH_CHAIN_CBC | CXI_MECH_PAD_PKCS5);

    // Generate a ByteArray with 1.5 blocks of all zeros
    const int dataLength               = 8 * 2;
    const int dataNeedingPaddingLength = dataLength - 4;
    ByteArray zerosNotAlignedWithBlock(0, dataNeedingPaddingLength);
    zerosNotAlignedWithBlock.fill(0, dataNeedingPaddingLength, 0);

    // Zero/PKCS#5 padding MAC calculations

    ByteArray zero_mac  = cxi->sign(CXI_FLAG_CRYPT_FINAL, key, mechParamZeroPadding, zerosNotAlignedWithBlock);
    // use CXI_FLAG_CRYPT_FINAL flag in the final call of MAC operation
    ByteArray pkcs5_mac = cxi->sign(CXI_FLAG_CRYPT_FINAL, key, mechParamPKCS5Padding, zerosNotAlignedWithBlock);

    zero_mac.xtrace("Zero padded MAC");
    pkcs5_mac.xtrace("PKCS#5 padded MAC");

    // compare MACs
    if (zero_mac == pkcs5_mac) {
        printf("no difference between Zero padding and PKCS#5 padding\n");
        throw(Exception("cxi_demo_aes_mac", E_CXI_API_COMPARE));
    }

    // compare verification results
    int zero_result  = cxi->verify(CXI_FLAG_CRYPT_FINAL, key, mechParamZeroPadding, zerosNotAlignedWithBlock, zero_mac);
    int pkcs5_result = cxi->verify(
      CXI_FLAG_CRYPT_FINAL, key, mechParamPKCS5Padding, zerosNotAlignedWithBlock, pkcs5_mac);

    // vertify MACs
    if (zero_result != 1 || pkcs5_result != 1) {
        printf("verification of Zero padding or PKCS#5 padding MAC not successful\n");
        throw(Exception("cxi_demo_aes_mac", E_CXI_API_COMPARE));
    }

    printf("OK\n");
}

/******************************************************************************
 *
 * cxi_demo_list_keys
 *
 ******************************************************************************/
void cxi_demo_list_keys(Cxi* cxi)
{
    printf("listing all keys in group: %s ...\n", Group);

    PropertyList keyTemplate;
    keyTemplate.setGroup(Group);

    KeyList keyList = cxi->key_list(keyTemplate);

    keyList.sort();

    printf("\n");
    printf("%-3s %-5s %-4s %-4s %-24s %-24s %s\n", "idx", "algo", "size", "type", "group", "name", "spec");
    printf("--------------------------------------------------------------------------------\n");

    for (int i = 0; i < keyList.size(); i++) {
        printf("%-3d %-5s %-4d %-4x %-24s %-24s %-d\n",
               i,
               AlgoNames[keyList[i].getAlgo() % DIM(AlgoNames)],
               keyList[i].getSize(),
               keyList[i].getType(),
               keyList[i].getGroup(),
               keyList[i].getName(),
               keyList[i].getSpecifier());
    }
    printf("OK\n");
}

/******************************************************************************
 *
 * cxi_demo_delete_all_keys
 *
 ******************************************************************************/
void cxi_demo_delete_all_keys(Cxi* cxi)
{
    printf("deleting all keys in group: %s...\n", Group);

    PropertyList keyTemplate;
    keyTemplate.setGroup(Group);

    KeyList keyList = cxi->key_list(keyTemplate);

    for (int i = 0; i < keyList.size(); i++) {
        cxi->key_delete(keyList[i]);
    }

    printf("OK\n");
}

/******************************************************************************
 *
 * cxi_demo_des_crypt
 *
 ******************************************************************************/
void cxi_demo_des_crypt(Cxi* cxi)
{
    printf("DES crypt demo...\n");

    // create plain key blob
    Blob keyBlob;
    keyBlob.setDES((char*)"\x1\x2\x3\x4\x5\x6\x7\x8\x9\x0\xA\xB\xC\xD\xE\xF", 16);

    // import plain key into CryptoServer
    PropertyList keyTemplate;

    keyTemplate.setGroup(Group);
    keyTemplate.setName("DES test key");
    keyTemplate.setExport(CXI_KEY_EXPORT_ALLOW_PLAIN); // don't do this in reality
    keyTemplate.setTimeGen(time(NULL));

    Key desKey = cxi->key_import(
      CXI_FLAG_KEY_OVERWRITE, CXI_KEY_BLOB_SIMPLE | CXI_KEY_TYPE_SECRET, keyTemplate, keyBlob, NULL);

    // encrypt data
    ByteArray          data      = "Change, we can believe in";
    MechanismParameter mechParam = MechanismParameter(CXI_MECH_MODE_ENCRYPT | CXI_MECH_CHAIN_ECB
                                                      | CXI_MECH_PAD_ISO7816);
    ByteArray          crypt     = cxi->crypt(0, desKey, mechParam, data);

    // export key in plain (educational purposes only!)
    keyBlob = cxi->key_export(CXI_KEY_BLOB_SIMPLE | CXI_KEY_TYPE_SECRET, desKey, NULL);

    // delete key on CryptoServer
    cxi->key_delete(desKey);

    // reimport key
    keyTemplate.clear();
    keyTemplate.setGroup(Group);
    keyTemplate.setName("DES test key");
    keyTemplate.setTimeGen(time(NULL));
    keyTemplate.setLabel((char*)"reimported");

    desKey = cxi->key_import(
      CXI_FLAG_KEY_OVERWRITE, CXI_KEY_BLOB_SIMPLE | CXI_KEY_TYPE_SECRET, keyTemplate, keyBlob, NULL);

    // decrypt data with reimported key
    mechParam.set(CXI_MECH_MODE_DECRYPT | CXI_MECH_CHAIN_ECB | CXI_MECH_PAD_ISO7816);
    ByteArray plain = cxi->crypt(0, desKey, mechParam, crypt);

    // compare decrypted data with original data
    if (plain != data) {
        printf("compare of decrypted and original data failed\n");
        throw(Exception("cxi_demo_des_crypt", E_CXI_API_COMPARE));
    }

    printf("OK\n");
}

/******************************************************************************
 *
 * cxi_demo_aes_crypt
 *
 ******************************************************************************/
void cxi_demo_aes_crypt(Cxi* cxi)
{
    printf("AES crypt demo...\n");

    // create AES key on CryptoServer
    PropertyList keyTemplate;

    keyTemplate.setAlgo(CXI_KEY_ALGO_AES);
    keyTemplate.setSize(256);
    keyTemplate.setGroup(Group);
    keyTemplate.setName("{U}AES test key"); // Unicode
    keyTemplate.setExport(CXI_KEY_EXPORT_ALLOW);
    keyTemplate.setTime(time(NULL));
    keyTemplate.setUsage(CXI_KEY_USAGE_ENCRYPT);

    Key aesKey = cxi->key_generate(CXI_FLAG_KEY_OVERWRITE, keyTemplate, CXI_MECH_RND_REAL);

    // open previously generated DES key
    keyTemplate.clear();
    keyTemplate.setGroup(Group);
    keyTemplate.setName("DES test key");

    Key desKey = cxi->key_open(CXI_FLAG_KEY_EXTERNAL, keyTemplate);

    // export AES key wrapped with DES key
    Blob keyBlob = cxi->key_export(CXI_KEY_BLOB_SIMPLE | CXI_KEY_TYPE_SECRET, aesKey, desKey);

    // encrypt data (this example encrypts chunks of data to demonstrate chaining)
    ByteArray data = cxi->rnd_gen(100);
    //data.xtrace("data");

    MechanismParameter mechParam = MechanismParameter(CXI_MECH_MODE_ENCRYPT | CXI_MECH_CHAIN_CBC | CXI_MECH_PAD_NONE);
    ByteArray          chunk;
    ByteArray          iv;
    ByteArray          crypt;

    int len    = data.length();
    int offset = 0;

    while (len > 0) {
        int l_chunk = MIN(len, 16);

        if (l_chunk % 16) {
            mechParam.set(CXI_MECH_MODE_ENCRYPT | CXI_MECH_CHAIN_CBC | CXI_MECH_PAD_PKCS5);
        }

        chunk = data.sub(offset, l_chunk);
        crypt += cxi->crypt(0, aesKey, mechParam, chunk, iv);

        offset += l_chunk;
        len -= l_chunk;
    }

    //crypt.xtrace("encrypted data");

    // delete AES key
    cxi->key_delete(aesKey);

    // reimport AES key
    keyTemplate.clear();
    keyTemplate.setGroup(Group);
    keyTemplate.setName("{U}AES test key"); // Unicode
    keyTemplate.setExport(CXI_KEY_EXPORT_ALLOW);
    //keyTemplate.setUsage(CXI_KEY_USAGE_DECRYPT);

    aesKey = cxi->key_import(
      CXI_FLAG_KEY_OVERWRITE, CXI_KEY_BLOB_SIMPLE | CXI_KEY_TYPE_SECRET, keyTemplate, keyBlob, desKey);

    // decrypt data (in one shot)
    mechParam.set(CXI_MECH_MODE_DECRYPT | CXI_MECH_CHAIN_CBC | CXI_MECH_PAD_PKCS5);

    ByteArray plain = cxi->crypt(0, aesKey, mechParam, crypt);
    //plain.xtrace("decrypted data");

    // compare decrypted data with original data
    if (plain != data) {
        printf("compare of decrypted and original data failed\n");
        throw(Exception("cxi_demo_aes_crypt", E_CXI_API_COMPARE));
    }

    printf("OK\n");
}

/******************************************************************************
 *
 * cxi_demo_rsa_crypt
 *
 ******************************************************************************/
void cxi_demo_rsa_crypt(Cxi* cxi)
{
    printf("RSA crypt demo...\n");

    // create RSA key
    PropertyList keyTemplate;

    keyTemplate.setAlgo(CXI_KEY_ALGO_RSA);
    keyTemplate.setSize(1024);
    keyTemplate.setGroup(Group);
    keyTemplate.setName("RSA test key");
    keyTemplate.setExport(CXI_KEY_EXPORT_ALLOW);

    Key rsaKey = cxi->key_generate(CXI_FLAG_KEY_OVERWRITE, keyTemplate);

    // export public key
    Blob keyBlob = cxi->key_export(CXI_KEY_BLOB_SIMPLE | CXI_KEY_TYPE_PUBLIC, rsaKey, NULL);
    //keyBlob.getKeyComp("MO").xtrace("Modulus");
    //keyBlob.getKeyComp("PE").xtrace("Public Exponent");

    // open previously created AES key
    keyTemplate.clear();
    keyTemplate.setGroup(Group);
    keyTemplate.setName("{U}AES test key");

    Key aesKey = cxi->key_open(CXI_FLAG_KEY_EXTERNAL, keyTemplate);

    // export private key (encrypted with previously generated AES key)
    keyBlob = cxi->key_export(CXI_KEY_BLOB_SIMPLE | CXI_KEY_TYPE_PRIVATE, rsaKey, aesKey);

    // encrypt data
    MechanismParameter mechParam = MechanismParameter(CXI_MECH_MODE_ENCRYPT | CXI_MECH_PAD_PKCS1
                                                      | CXI_MECH_HASH_ALGO_SHA256);

    ByteArray data  = ByteArray("Yes, we can");
    ByteArray crypt = cxi->crypt(0, rsaKey, mechParam, data);
    //crypt.xtrace("encrypted data");

    // (re)import private key (with a modified key name)
    keyTemplate.clear();
    keyTemplate.setGroup(Group);
    keyTemplate.setName("RSA test key (copy)");

    rsaKey = cxi->key_import(CXI_FLAG_KEY_OVERWRITE, CXI_KEY_BLOB_SIMPLE, keyTemplate, keyBlob, aesKey);

    // decrypt data
    mechParam.set(CXI_MECH_MODE_DECRYPT | CXI_MECH_PAD_PKCS1 | CXI_MECH_HASH_ALGO_SHA256);

    ByteArray plain = cxi->crypt(0, rsaKey, mechParam, crypt);
    //plain.xtrace("decrypted data");

    // compare decrypted data with original data
    if (plain != data) {
        printf("compare of decrypted and original data failed\n");
        plain.xtrace("decrypted data");
        data.xtrace("data");
        throw(Exception("cxi_demo_rsa_crypt", E_CXI_API_COMPARE));
    }

    printf("OK\n");
}

/******************************************************************************
 *
 * cxi_demo_rsa_crypt_bulk
 *
 ******************************************************************************/
void cxi_demo_rsa_crypt_bulk(Cxi* cxi)
{
    printf("RSA bulk crypt demo...\n");

    // create RSA key
    PropertyList keyTemplate;
    keyTemplate.setAlgo(CXI_KEY_ALGO_RSA);
    keyTemplate.setSize(1024);
    keyTemplate.setGroup(Group);
    keyTemplate.setName("RSA test key");
    keyTemplate.setExport(CXI_KEY_EXPORT_ALLOW);

    Key rsaKey = cxi->key_generate(CXI_FLAG_KEY_OVERWRITE, keyTemplate);

    // create random data
    vector<ByteArray> data_items;

    for (int i = 0; i < 16; i++) {
        ByteArray item = cxi->rnd_gen(128);

        char* p_x = item.get();
        *p_x &= 0x3F; // data size < key size
        *p_x |= 0x01; // first byte != 0

        data_items.push_back(item);
    }

    // encrypt
    MechanismParameter mechParam   = MechanismParameter(CXI_MECH_MODE_ENCRYPT);
    vector<ByteArray>  crypt_items = cxi->bulk_crypt(rsaKey, mechParam, data_items);

    // decrypt
    mechParam.set(CXI_MECH_MODE_DECRYPT);
    vector<ByteArray> plain_items = cxi->bulk_crypt(rsaKey, mechParam, crypt_items);

    for (int j = 0; j < (int)data_items.size(); j++) {
        if (plain_items[j] != data_items[j]) {
            printf("compare of decrypted and original data failed\n");
            plain_items[j].xtrace("plain");
            data_items[j].xtrace("data");
            throw(Exception("cxi_demo_rsa_crypt_bulk", E_CXI_API_COMPARE));
        }
    }

    printf("OK\n");
}

/******************************************************************************
 *
 * cxi_demo_rsa_sign
 *
 ******************************************************************************/
void cxi_demo_rsa_sign(Cxi* cxi)
{
    printf("RSA sign demo...\n");

    // create RSA key
    PropertyList keyTemplate;
    keyTemplate.setAlgo(CXI_KEY_ALGO_RSA);
    keyTemplate.setSize(2048);
    keyTemplate.setGroup(Group);
    keyTemplate.setName("RSA test key");

    Key rsaKey = cxi->key_generate(CXI_FLAG_KEY_OVERWRITE, keyTemplate);

    // create hash
    Hash hash;
    hash.init(CXI_MECH_HASH_ALGO_SHA512);
    hash.update((char*)"We are what we ", 15);
    hash.update((char*)"were waiting for", 16);
    hash.final();
    //hash.xtrace("hash");

    // sign data
    MechanismParameter mechParam = MechanismParameter(CXI_MECH_PAD_PKCS1 | CXI_MECH_HASH_ALGO_SHA512);

    ByteArray sign = cxi->sign(0, rsaKey, mechParam, hash);
    //sign.xtrace("sign");

    // verify signature
    cxi->verify(0, rsaKey, mechParam, hash, sign);

    printf("OK\n");
}

/******************************************************************************
 *
 * cxi_demo_rsa_sign_bulk
 *
 ******************************************************************************/
void cxi_demo_rsa_sign_bulk(Cxi* cxi)
{
    printf("RSA bulk sign demo...\n");

    // create RSA key
    PropertyList keyTemplate;
    keyTemplate.setAlgo(CXI_KEY_ALGO_RSA);
    keyTemplate.setSize(2048);
    keyTemplate.setGroup(Group);
    keyTemplate.setName("RSA test key");

    Key rsaKey = cxi->key_generate(CXI_FLAG_KEY_OVERWRITE, keyTemplate);

    // create hash
    vector<ByteArray> data_items;

    for (int i = 0; i < 16; i++) {
        ByteArray item = cxi->rnd_gen(250);

        Hash hash;
        hash.init(CXI_MECH_HASH_ALGO_SHA512);
        hash.update(item.get(), item.length());
        hash.final();

        data_items.push_back(hash);
    }

    // sign data
    MechanismParameter mechParam = MechanismParameter(CXI_MECH_PAD_PKCS1 | CXI_MECH_HASH_ALGO_SHA512);

    vector<ByteArray> sign_items = cxi->bulk_sign(rsaKey, mechParam, data_items);

    // verify signatures
    for (int j = 0; j < 16; j++) {
        cxi->verify(0, rsaKey, mechParam, data_items[j], sign_items[j]);
    }

    printf("OK\n");
}

/******************************************************************************
 *
 * cxi_demo_ecdsa_sign
 *
 ******************************************************************************/
void cxi_demo_ecdsa_sign(Cxi* cxi)
{
    printf("ECDSA sign demo...\n");

    // create ECDSA key
    PropertyList keyTemplate;
    keyTemplate.setAlgo(CXI_KEY_ALGO_ECDSA);
    keyTemplate.set(CXI_PROP_KEY_EC_CURVE, Property("NIST-P192"));
    keyTemplate.setGroup(Group);
    keyTemplate.setName("EC test key");

    Key ecKey = cxi->key_generate(CXI_FLAG_KEY_OVERWRITE, keyTemplate, 0);

    // export public key
    Blob keyBlob = cxi->key_export(CXI_KEY_BLOB_SIMPLE | CXI_KEY_TYPE_PUBLIC, ecKey, NULL, 0);
    keyBlob.getPublic().xtrace("Public Key");

    // backup ECDSA key
    Key backupKey = cxi->key_backup(ecKey);

    // restore ECDSA key
    keyTemplate.clear();
    keyTemplate.setName("EC test key (copy)");

    cxi->key_restore(CXI_FLAG_KEY_OVERWRITE, backupKey, keyTemplate);

    ByteArray data = "Hope!Progress!";

    // create hash
    Hash hash;
    hash.init(CXI_MECH_HASH_ALGO_SHA256);
    hash.update(data);
    hash.final();
    hash.xtrace("hash");

    // sign locally created hash
    MechanismParameter mechParam = MechanismParameter(0);
    ByteArray          sign      = cxi->sign(0, ecKey, mechParam, hash);
    sign.xtrace("sign");

    // verify signature
    cxi->verify(0, ecKey, mechParam, hash, sign);

    // hash and sign data
    mechParam = MechanismParameter(CXI_MECH_HASH_ALGO_SHA256);
    sign      = cxi->sign(CXI_FLAG_HASH_DATA, ecKey, mechParam, data);
    sign.xtrace("sign");

    // verify signature
    bool result = cxi->verify(CXI_FLAG_HASH_DATA, ecKey, mechParam, data, sign);

    if (result == false) {
        printf("signature verification failed\n");
    }

    printf("OK\n");
}

/******************************************************************************
 *
 * cxi_demo_dsa_sign
 *
 ******************************************************************************/
void cxi_demo_dsa_sign(Cxi* cxi)
{
    printf("DSA sign demo...\n");

    // create DSA key
    PropertyList keyTemplate;
    keyTemplate.setAlgo(CXI_KEY_ALGO_DSA);
    keyTemplate.setGroup(Group);
    keyTemplate.setName("DSA test key");
    keyTemplate |= cxi->key_dsa_xgen(1024, 320);
    keyTemplate.setTime(time(NULL));

    Key dsaKey = cxi->key_generate(CXI_FLAG_KEY_OVERWRITE, keyTemplate, 0);

    // query some key properties
    int properties[] = {CXI_PROP_KEY_GROUP,
                        CXI_PROP_KEY_NAME,
                        CXI_PROP_KEY_SPEC,
                        CXI_PROP_KEY_ALGO,
                        CXI_PROP_KEY_SIZE,
                        CXI_PROP_KEY_LABEL,
                        CXI_PROP_KEY_EXPORT,
                        CXI_PROP_KEY_USAGE,
                        CXI_PROP_KEY_BLEN,
                        CXI_PROP_KEY_TYPE,
                        CXI_PROP_KEY_DSA_PUBKEY};

    PropertyList propList = cxi->key_prop_get(dsaKey, properties, DIM(properties));

#if 0  
  printf("\nProperty List:\n");
  printf("Group     : %s\n", propList.getGroup());
  printf("Name      : %s\n", propList.getName());
  printf("Specifier : %d\n", propList.getSpecifier());
  printf("Label     : %s\n", propList.getLabel());
  printf("Algo      : %s\n", AlgoNames[propList.getAlgo() % DIM(AlgoNames)]);
  printf("Size      : %d\n", propList.getSize());
  printf("Export    : %d\n", propList.getExport());
  printf("Usage     : %d\n", propList.getUsage());
  printf("BlockLen  : %d\n", propList.getBlockLength());
  printf("Type      : %d\n", propList.getType());
#endif

    // get public key from property list
    Property prop = propList.get(CXI_PROP_KEY_DSA_PUBKEY);
    //prop.xtrace("Public key");

    printf("OK\n");
}

/******************************************************************************
 *
 * cxi_demo_hmac
 *
 ******************************************************************************/
void cxi_demo_hmac(Cxi* cxi)
{
    printf("HMAC demo...\n");

    // create AES key on CryptoServer
    PropertyList keyTemplate;

    keyTemplate.setAlgo(CXI_KEY_ALGO_RAW);
    keyTemplate.setSize(256);
    keyTemplate.setType(CXI_KEY_TYPE_SECRET);
    keyTemplate.setGroup(Group);
    keyTemplate.setName("RAW test key");

    Key key = cxi->key_generate(CXI_FLAG_KEY_OVERWRITE, keyTemplate);

    ByteArray          chunk;
    ByteArray          data;
    ByteArray          iv;
    ByteArray          sign;
    MechanismParameter mechParam = MechanismParameter(CXI_MECH_MODE_HMAC | CXI_MECH_HASH_ALGO_SHA1);

    // sign (chunked)
    int nparts = 3;

    while (nparts--) {
        int       len   = *(unsigned char*)cxi->rnd_gen(1).get();
        ByteArray chunk = cxi->rnd_gen(len + 1);

        if (nparts > 0) {
            cxi->sign(CXI_FLAG_HASH_PART, key, mechParam, chunk, iv);
        } else {
            sign = cxi->sign(0, key, mechParam, chunk, iv);
        }

        data.append(chunk);
    }

    // verify
    cxi->verify(0, key, mechParam, data, sign);

    // recalculate HMAC
    ByteArray hmac = cxi->hash_compute(0, mechParam, &data, NULL, &key);

    if (sign.compare(hmac) != 0) {
        printf("recalculated HMAC doesn't match\n");
        sign.xtrace("sign");
        hmac.xtrace("hmac");
        throw(Exception("cxi_demo_hmac", E_CXI_API_COMPARE));
    }

    // sign
    mechParam = MechanismParameter(CXI_MECH_MODE_HMAC | CXI_MECH_HASH_ALGO_SHA512);

    data = cxi->rnd_gen(666);
    sign = cxi->sign(0, key, mechParam, data);

    // verify (chunked)
    int ofs  = 0;
    int rlen = data.length();

    iv.clear();

    while (rlen) {
        int size = rand() % 66;
        int len  = MIN(size, rlen);

        chunk = data.sub(ofs, len);
        rlen -= len;
        ofs += len;

        if (rlen) {
            cxi->verify(CXI_FLAG_HASH_PART, key, mechParam, chunk, NULL, &iv);
        } else {
            cxi->verify(0, key, mechParam, chunk, &sign, &iv);
        }
    }

    // recalculate HMAC
    hmac = cxi->hash_compute(0, mechParam, &data, NULL, &key);

    if (sign.compare(hmac) != 0) {
        printf("recalculated HMAC doesn't match\n");
        sign.xtrace("sign");
        hmac.xtrace("hmac");
        throw(Exception("cxi_demo_hmac", E_CXI_API_COMPARE));
    }

    printf("OK\n");
}

/******************************************************************************
 *
 * cxi_demo_hash
 *
 ******************************************************************************/
void cxi_demo_hash(Cxi* cxi)
{
    printf("HASH computation demo...\n");

    int                nparts = 10;
    ByteArray          data;
    ByteArray          hash;
    ByteArray          hash2;
    MechanismParameter mechParam = MechanismParameter(CXI_MECH_MODE_HASH | CXI_MECH_HASH_ALGO_SHA256);

    // chunked calculation
    while (nparts--) {
        int       len   = (unsigned char)*cxi->rnd_gen(1).get();
        ByteArray chunk = cxi->rnd_gen(len + 1);

        // compute hash
        int flags = (nparts == 0) ? 0 : CXI_FLAG_HASH_PART;
        hash      = cxi->hash_compute(flags, mechParam, chunk, hash);

        data += chunk;
    }

    // recalculate in one shot
    hash2 = cxi->hash_compute(0, mechParam, data);

    if (hash.compare(hash2) != 0) {
        printf("hash doesn't match reference hash\n");
        hash.xtrace("hash");
        hash2.xtrace("hash2");
        throw(Exception("cxi_demo_hash", E_CXI_API_COMPARE));
    }

    // recalculate locally
    Hash rhash;
    rhash.init(CXI_MECH_HASH_ALGO_SHA256);
    rhash.update(data);
    rhash.final();

    if (hash.compare(rhash) != 0) {
        printf("hash doesn't match reference hash\n");
        hash.xtrace("hash");
        rhash.xtrace("rhash");
    }

    printf("OK\n");
}


/******************************************************************************
 *
 * cxi_demo_keystore
 *
 ******************************************************************************/
void cxi_demo_keystore(Cxi* cxi, char* cfgfile)
{
    KeyStore* ks = NULL;

    printf("Keystore demo...\n");

    try {
        // open / create key store (index length is 16 bytes)
        if (cfgfile != NULL) {
            Config config = Config(cfgfile);
            ks            = new KeyStore(config, 16);
        } else {
            ks = new KeyStore((char*)"cxi.ks", 16);
        }

        // open previously generated AES key
        PropertyList keyTemplate;
        keyTemplate.setGroup(Group);
        keyTemplate.setName("{U}AES test key");

        Key key = cxi->key_open(CXI_FLAG_KEY_EXTERNAL, keyTemplate);

        // insert key into external key store
        ByteArray index = key.getUName();
        ks->insertKey(CXI_FLAG_KEY_OVERWRITE, index, key);

        // open previously generated RSA key
        keyTemplate.clear();
        keyTemplate.setGroup(Group);
        keyTemplate.setName("RSA test key");

        key = cxi->key_open(CXI_FLAG_KEY_EXTERNAL, keyTemplate);

        // insert key into external key store
        index = key.getUName();
        ks->insertKey(CXI_FLAG_KEY_OVERWRITE, index, key);

        // list all keys with a specified property
        printf("listing all keys with specified property...\n");
        keyTemplate.clear();
        keyTemplate.setGroup(Group);
        //keyTemplate.setName("RSA test key");

        index.clear();
        int mode = KeyStore::MODE_GTEQ;

        printf("%-33s %-16s %-16s %s\n", "index", "group", "name", "spec");
        printf("--------------------------------------------------------------------------------\n");

        while (ks->findKey(index, mode, keyTemplate) == true) {
            //index.xtrace("index");

            Key key = ks->getKey(index);

            if (key.getType() == Key::TYPE_BLOB) {
                PropertyList propList = key.getProplist();
                printf("%-33s %-16s %-16s %d\n",
                       index.toHexString().c_str(),
                       propList.getGroup(),
                       propList.getName(),
                       propList.getSpecifier());
            }

            mode = KeyStore::MODE_GREATER;
        }

        printf("OK\n");

        // delete all keys
        printf("listing all keys...\n");
        index.clear();
        mode = KeyStore::MODE_GTEQ;

        while (ks->findKey(index, mode) == true) {
            //index.xtrace("index");

            Key key = ks->getKey(index);

            if (key.getType() == Key::TYPE_BLOB) {
                PropertyList propList = key.getProplist();
            }

            ks->deleteKey(index);
            mode = KeyStore::MODE_GREATER;
        }

        // check
        index.clear();
        if (ks->findKey(index, KeyStore::MODE_GTEQ) == true) {
            printf("deleting key failed\n");
            throw(Exception("cxi_demo_keystore", -1));
        }

        delete ks;
        printf("OK\n");
    } catch (const Exception&) {
        delete ks;
        throw;
    }
}

/******************************************************************************
 *
 * main
 *
 ******************************************************************************/
int main(int argc, char** argv)
{
    int   err     = 0;
    char* device  = NULL;
    char* cfgfile = NULL;
    char* user    = NULL;
    char* key     = NULL;
    char* pwd     = NULL;

    Cxi* cxi = NULL;
    Log& log = Log::getInstance();

    for (int i = 1; i < argc; i++) {
        if (strncasecmp(argv[i], (char*)"version", 6) == 0) {
            printf("cxidemo %s\n", CXI_DEMO_VERSION);
            return 0;
        } else if (strncasecmp(argv[i], (char*)"dev=", 4) == 0) {
            device = argv[i] + 4;
        } else if (strncasecmp(argv[i], (char*)"cfg=", 4) == 0) {
            cfgfile = argv[i] + 4;
        } else if (strncasecmp(argv[i], (char*)"user=", 5) == 0) {
            char* x;

            user = argv[i] + 5;

            if ((x = strchr(user, ',')) != NULL) {
                *x++ = 0;
                key  = x;

                if ((x = strchr(key, '#')) != NULL) {
                    *x++ = 0;
                    pwd  = x;
                } else {
                    pwd = key;
                    key = NULL;
                }
            }
        } else {
            printf("invalid argument: %s\n", argv[i]);
            CLEANUP(-1);
        }
    }

    if (device == NULL) {
        device = getenv("CRYPTOSERVER");
    }

    if (device == NULL) {
        device = (char*)"3001@127.0.0.1";
    }
    //device = (char*)"192.168.4.59";
    //device = (char*)"PCI:0";


    if (cfgfile == NULL) {
        cfgfile = access((char*)"cxi.cfg", 0) == 0 ? (char*)"cxi.cfg" : (char*)"../../etc/cxi.cfg";
    }

    if (user == NULL) {
        user = (char*)"CXI_USER";
    }

    if (pwd == NULL) {
        pwd = (char*)"12345678";
    }

    if (Group == NULL) {
        Group = (char*)"test";
    }

    printf("CXI library version : %08x\n", Cxi::get_version());

    try {
        for (int i = 0; i < 2; i++) {
            switch (i) {
            case 0:
                // open dedicated CryptoServer (e.g. for key management)
                printf("CryptoServer: %s\n", device);

                log.init((char*)"cxi.log", Log::LEVEL_INFO, 100000);
                cxi = new Cxi(device, 60000);
                break;

            case 1:
                // open CryptoServer cluster
                Config config = Config(cfgfile);
                printf("CryptoServer Cluster: %s\n", config.getString("Device", "").c_str());

                log.init(config);

                cxi = new Cxi(config);
                break;
            }

            printf("CXI firmware module version: %08x\n", cxi->get_fw_version());

            // authenticate / logon to CryptoServer
            printf("Logon user: %s\n", user);

            if (key != NULL) {
                cxi->logon_sign(user, key, pwd, true);
            } else {
                cxi->logon_pass(user, pwd, true);
            }

            printf("Authentication state: 0x%08x\n", cxi->get_auth_state());

            // perform tests
            cxi_demo_aes_mac(cxi);
            cxi_demo_des_crypt(cxi);
            cxi_demo_aes_crypt(cxi);
            cxi_demo_rsa_crypt(cxi);
            cxi_demo_rsa_crypt_bulk(cxi);
            cxi_demo_rsa_sign(cxi);
            cxi_demo_rsa_sign_bulk(cxi);
            cxi_demo_ecdsa_sign(cxi);
            cxi_demo_dsa_sign(cxi);
            cxi_demo_hmac(cxi);
            cxi_demo_hash(cxi);
            cxi_demo_keystore(cxi, cfgfile);
            cxi_demo_list_keys(cxi);
            cxi_demo_delete_all_keys(cxi);

            cxi->logoff();
            cxi->close();
        }
    } catch (const Exception& ex) {
        printf("%sat %s [%d]\n", ex.err_str, ex.where, ex.line);

        cout << "\7\npress <ENTER>\n";
        while (cin.get() != 10)
            ;

        CLEANUP(ex.err);
    }

cleanup:
    delete cxi;

    return err;
}
