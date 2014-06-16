#ifndef SAM_H_INCLUDED
#define SAM_H_INCLUDED

#ifdef __cplusplus
extern "C" {
#endif

#include <daplug/DaplugDongle.h>
#include <daplug/comm.h>

/**
* \enum sam_options
* \brief SAM options
*/
typedef enum{

    SAM_1_DIV = 0x01,
    SAM_2_DIV = 0x02,
    SAM_GEN_DEK = 0x04,
    SAM_GEN_RMAC = 0x08,
    SAM_GEN_RENC = 0x10,
    SAM_MAX_CIPHER_BLOCK_SIZE = 0xD4,
    SAM_MAX_SIGNATURE_BLOCK_SIZE = 0xD4,

} sam_options;

/**
* \enum sam_operations
* \brief SAM operations
*/
typedef enum{

    SAM_ENCRYPT = 0x01,
    SAM_DECRYPT = 0x02,

    SAM_CMAC = 0x03,
    SAM_RMAC = 0x04,

    SAM_HOST_CRYPTOGRAM = 0x01,
    SAM_CARD_CRYPTOGRAM = 0x02,

} sam_operations;

int encryptDek(DaplugDongle *daplugSAM, int ctxKeyVersion, int ctxKeyId, char *DEKSessionSAM, int isLastBlock, char *inData,
                      char *encData);

//Compute retail MAC using SAM: CMAC/RMAC
//use session SAM CMAC/RMAC Key for CMAC/RMAC
//Expects a char[8*2+1] initialized to "" for retailMac
int SAM_computeRetailMac(DaplugDongle *daplugSAM, int ctxKeyVersion, int ctxKeyId, char *sessionSAMKey,
                       char *inData, char *oldRetailMac, int cmac, char *retailMac);

//Encrypt/decrypt Apdu data using SAM
//use session SAM CENC/RENC Key for ENCRYPT/DECRYPT
//Expects a char[(APDU_D_MAXLEN+8)*2+1] initialized to "" for outData
int SAM_dataEncryption(DaplugDongle *daplugSAM, int ctxKeyVersion, int ctxKeyId, char *sessionSAMKey,
                       char *inData, int enc, char *outData);

//Compute Host/Card Cryptogram
//Use session SAM CENC Key
//Expects a char[8*2+1] initialized to "" for cryptogram
int SAM_computeCryptogram(DaplugDongle *daplugSAM, int ctxKeyVersion, int ctxKeyId, char *CENCSessionSAMKey,
                          char *hostChallenge, char *cardChallenge, char *counter, int cryptogramType, char *cryptogram);

//Compute session keys SAM material
//The returned five char* keys and the char** must be freed later
char** SAM_computeSessionKeys(DaplugDongle *daplugSAM, int SAMCtxKeyVersion, int SAMCtxKeyId, int SAMGPUsableKeyVersion,
                               int flag, int counter, char *div1, char *div2);


/*
Prepare a put key command using a SAM
*/
int SAM_createPutKeyCommand(DaplugDongle *daplugSAM, int SAMCtxKeyVersion, int SAMCtxKeyId,
                            int SAMProvisionableKeyVersion, char *DEKSessionSAMKey, char *div1, char *div2,
                            char *numKeyset, char *mode, char *keyUsage, char *keyAccess, char *putKeyCommand);

//Compute cleartext diversified version of SAM exportable keyset
char** SAM_computeDiversifiedKey(DaplugDongle *daplugSAM, int SAMExportableKeyVersion, int flag, char *div1, char *div2);

#ifdef __cplusplus
}
#endif

#endif // SAM_H_INCLUDED
