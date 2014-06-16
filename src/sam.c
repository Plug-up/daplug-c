/**
 * \file sam.c
 * \brief
 * \author S.BENAMAR s.benamar@plug-up.com
 * \version 1.2
 * \date 09/06/2014
 * \warning Functions are not documented
 *
 * Helps to do SAM functions. (SAM license required)
 *
 */

#include <daplug/sam.h>

//=== SAM DIVERSIFY KEYS

//Returns the encrypted sessions keys SAM material.
static char** diversifyGP(DaplugDongle *daplugSAM, int SAMCtxKeyVersion, int SAMCtxKeyId, int GPUsableKeyVersion, int flag, int counter, char *div1, char *div2){

    char    SAMCtxKeyVersion_str[1*2+1]="",
            SAMCtxKeyId_str[1*2+1]="",
            GPUsableKeyVersion_str[1*2+1]="",
            flag_str[1*2+1]="",
            counter_str[2*2+1]="";

    sprintf(SAMCtxKeyVersion_str,"%02X",SAMCtxKeyVersion);
    sprintf(SAMCtxKeyId_str,"%02X",SAMCtxKeyId);
    sprintf(GPUsableKeyVersion_str,"%02X",GPUsableKeyVersion);
    sprintf(flag_str,"%02X",flag);
    sprintf(counter_str,"%04X",counter);

    int lc = 6; // = 1+1+1+1+2

    //Diversifiers

    char    div1_[16*2+1]="",
            div2_[16*2+1]="";

    if(flag & SAM_1_DIV || flag & SAM_2_DIV){
        if(div1 == NULL || strlen(div1) != 16*2 || !isHexInput(div1)){
            fprintf(stderr,"\ndiversifyGP() - Wrong value for parameter div1 !\n");
            return NULL;
        }else{
            strcpy(div1_,div1);
            lc = lc + 16;
        }
    }

    if(flag & SAM_2_DIV){
        if(div2 == NULL || strlen(div2) != 16*2 || !isHexInput(div2)){
            fprintf(stderr,"\ndiversifyGP() - Wrong value for parameter div2 !\n");
            return NULL;
        }else{
            strcpy(div2_,div2);
            lc = lc + 16;
        }
    }

    char lc_s[1*2+1]="";
    sprintf(lc_s,"%02X",lc);

    //Form the apdu
    char apdu_str[APDU_CMD_MAXLEN*2+1]="";
    strcat(apdu_str,"D0700010");
    strcat(apdu_str, lc_s);
    strcat(apdu_str,SAMCtxKeyVersion_str);
    strcat(apdu_str,SAMCtxKeyId_str);
    strcat(apdu_str,GPUsableKeyVersion_str);
    strcat(apdu_str,flag_str);
    strcat(apdu_str,counter_str);
    strcat(apdu_str,div1_);
    strcat(apdu_str,div2_);

    //Set to apdu cde
    Apdu apdu;
    if(!setApduCmd(apdu_str,&apdu)){
        fprintf(stderr,"\ndiversifyGP() - An error occured when setting the Apdu !\n");
        return NULL;
    }

    //exchange it
    if(!exchangeApdu(daplugSAM,&apdu)){
        fprintf(stderr,"\ndiversifyGP() - An error occured when exchanging the Apdu !\n");
        return NULL;
    }

    if(strcmp(apdu.sw_str,"9000")){
        fprintf(stderr,"\ndiversifyGP() - Apdu command ended abnormally !\n");
        return NULL;
    }

    //Session SAM keys (DEK, RMAC & RENC are optional)

    char **sessionSAMKeys = (char**) calloc(5, sizeof(char*));

    if(sessionSAMKeys == NULL){
        fprintf(stderr,"\ndiversifyGP() - Memory problem !\n");
        return NULL;
    }

    int i;
    char *tmp = NULL;
    for(i=0;i<5;i++){

        if((sessionSAMKeys[i] = (char*) calloc(24*2+1, sizeof(char))) == NULL){
            fprintf(stderr,"\ndiversifyGP() - Memory problem !\n");
            free(sessionSAMKeys);
            return NULL;
        }

        if(((i == 2) && !(flag & SAM_GEN_DEK)) || ((i == 3) && !(flag & SAM_GEN_RMAC)) || ((i == 4) && !(flag & SAM_GEN_RENC))){
            strcpy(sessionSAMKeys[i], "");
        }else{
            strcpy(sessionSAMKeys[i], tmp = str_sub(apdu.r_str, i*24*2, (i+1)*24*2-1));
            free(tmp);
        }
    }

    return sessionSAMKeys;

}

/*
Returns the three wrapped keys and the three KCVs.
Returned keys and kcvs must be freed later
*/
static int diversifyForPutkey(DaplugDongle *daplugSAM, int SAMCtxKeyVersion, int SAMCtxKeyId, int provisionableKeyVersion, int flag, char *DEKSessionSAM, char *div1, char *div2,
                              char ***wrappedKeys, char ***kcvs){

    char    SAMCtxKeyVersion_str[1*2+1]="",
            SAMCtxKeyId_str[1*2+1]="",
            provisionableKeyVersion_str[1*2+1]="",
            flag_str[1*2+1]="";

    sprintf(SAMCtxKeyVersion_str,"%02X",SAMCtxKeyVersion);
    sprintf(SAMCtxKeyId_str,"%02X",SAMCtxKeyId);
    sprintf(provisionableKeyVersion_str,"%02X",provisionableKeyVersion);
    sprintf(flag_str,"%02X",flag);

    int lc = 28; // = 1+1+1+1+24

    //Diversifiers

    char    div1_[16*2+1]="",
            div2_[16*2+1]="";

    if(flag & SAM_1_DIV || flag & SAM_2_DIV){
        if(div1 == NULL || strlen(div1) != 16*2 || !isHexInput(div1)){
            fprintf(stderr,"\ndiversifyForPutkey() - Wrong value for parameter div1 !\n");
            return 0;
        }else{
            strcpy(div1_,div1);
            lc = lc + 16;
        }
    }

    if(flag & SAM_2_DIV){
        if(div2 == NULL || strlen(div2) != 16*2 || !isHexInput(div2)){
            fprintf(stderr,"\ndiversifyForPutkey() - Wrong value for parameter div2 !\n");
            return 0;
        }else{
            strcpy(div2_,div2);
            lc = lc + 16;
        }
    }

    //DEK Session Key
    if(strlen(DEKSessionSAM) != 24*2 || !isHexInput(DEKSessionSAM)){
        fprintf(stderr,"\ndiversifyForPutkey() - Wrong value for parameter DEKSessionSAM !\n");
        return 0;
    }

    char lc_s[1*2+1]="";
    sprintf(lc_s,"%02X",lc);

    //Form the apdu
    char apdu_str[APDU_CMD_MAXLEN*2+1]="";
    strcat(apdu_str,"D0700020");
    strcat(apdu_str, lc_s);
    strcat(apdu_str,SAMCtxKeyVersion_str);
    strcat(apdu_str,SAMCtxKeyId_str);
    strcat(apdu_str,provisionableKeyVersion_str);
    strcat(apdu_str,flag_str);
    strcat(apdu_str,DEKSessionSAM);
    strcat(apdu_str,div1_);
    strcat(apdu_str,div2_);

    //Set to apdu cde
    Apdu apdu;
    if(!setApduCmd(apdu_str,&apdu)){
        fprintf(stderr,"\ndiversifyForPutkey() - An error occured when setting the Apdu !\n");
        return 0;
    }

    //exchange it
    if(!exchangeApdu(daplugSAM,&apdu)){
        fprintf(stderr,"\ndiversifyForPutkey() - An error occured when exchanging the Apdu !\n");
        return 0;
    }

    if(strcmp(apdu.sw_str,"9000")){
        fprintf(stderr,"\ndiversifyForPutkey() - Apdu command ended abnormally !\n");
        return 0;
    }

    //Wrapped keys & KCVs
    int i;
    char *tmp = NULL, *tmp1 = NULL, *tmp2 = NULL;

    (*wrappedKeys) = (char**) calloc(3, sizeof(char*));
    (*kcvs) = (char**) calloc(3, sizeof(char*));

    if(!(*wrappedKeys)){
        fprintf(stderr,"\ndiversifyForPutkey() - Memory problem !\n");
        return 0;
    }
    if(!(*kcvs)){
        fprintf(stderr,"\ndiversifyForPutkey() - Memory problem !\n");
        return 0;
    }

    for(i=0;i<3;i++){

        (*wrappedKeys)[i] = (char*) calloc((GP_KEY_SIZE*2+1), sizeof(char));
        (*kcvs)[i] = (char*) calloc((3*2+1), sizeof(char));

        if(!(*wrappedKeys)[i]){
            fprintf(stderr,"\ndiversifyForPutkey() - Memory problem !\n");
            free(*wrappedKeys);
            return 0;
        }
        if(!(*kcvs)[i]){
            fprintf(stderr,"\ndiversifyForPutkey() - Memory problem !\n");
            free(*kcvs);
            return 0;
        }

        tmp = str_sub(apdu.r_str, i*(16+3)*2, (i+1)*(16+3)*2-1);
        strcpy((*wrappedKeys)[i], tmp1 = str_sub(tmp, 0, 16*2-1));
        strcpy((*kcvs)[i], tmp2 = str_sub(tmp, 16*2, (16+3)*2-1));
        free(tmp);
        free(tmp1);
        free(tmp2);
    }

    return 1;

}

/*
Returns the cleartext diversified keys of the given SAM cleartext exportable keyset.
*/
char** diversifyCleartext(DaplugDongle *daplugSAM, int cleartextExportableKeyVersion, int flag, char *div1, char *div2){

    char    cleartextExportableKeyVersion_str[1*2+1]="",
            flag_str[1*2+1]="";

    sprintf(cleartextExportableKeyVersion_str,"%02X",cleartextExportableKeyVersion);
    sprintf(flag_str,"%02X",flag);

    int lc = 4; // = 1+1+1+1

    //Diversifiers

    char    div1_[16*2+1]="",
            div2_[16*2+1]="";

    if(flag & SAM_1_DIV || flag & SAM_2_DIV){
        if(div1 == NULL || strlen(div1) != 16*2 || !isHexInput(div1)){
            fprintf(stderr,"\ndiversifyCleartext() - Wrong value for parameter div1 !\n");
            return NULL;
        }else{
            strcpy(div1_,div1);
            lc = lc + 16;
        }
    }

    if(flag & SAM_2_DIV){
        if(div2 == NULL || strlen(div2) != 16*2 || !isHexInput(div2)){
            fprintf(stderr,"\ndiversifyCleartext() - Wrong value for parameter div2 !\n");
            return NULL;
        }else{
            strcpy(div2_,div2);
            lc = lc + 16;
        }
    }

    char lc_s[1*2+1]="";
    sprintf(lc_s,"%02X",lc);

    //Form the apdu
    char apdu_str[APDU_CMD_MAXLEN*2+1]="";
    strcat(apdu_str,"D0700030");
    strcat(apdu_str, lc_s);
    strcat(apdu_str,"0000");
    strcat(apdu_str,cleartextExportableKeyVersion_str);
    strcat(apdu_str,flag_str);
    strcat(apdu_str,div1_);
    strcat(apdu_str,div2_);

    //Set to apdu cde
    Apdu apdu;
    if(!setApduCmd(apdu_str,&apdu)){
        fprintf(stderr,"\ndiversifyCleartext() - An error occured when setting the Apdu !\n");
        return NULL;
    }

    //exchange it
    if(!exchangeApdu(daplugSAM,&apdu)){
        fprintf(stderr,"\ndiversifyCleartext() - An error occured when exchanging the Apdu !\n");
        return NULL;
    }

    if(strcmp(apdu.sw_str,"9000")){
        fprintf(stderr,"\ndiversifyCleartext() - Apdu command ended abnormally !\n");
        return NULL;
    }

    //Cleartext keys

    char **cleartextKeys = (char**) calloc(3, sizeof(char*));

    if(cleartextKeys == NULL){
        fprintf(stderr,"\ndiversifyCleartext() - Memory problem !\n");
        return NULL;
    }

    int i;
    char *tmp = NULL;
    for(i=0;i<3;i++){

        if((cleartextKeys[i] = (char*) calloc(GP_KEY_SIZE*2+1, sizeof(char))) == NULL){
            fprintf(stderr,"\ndiversifyCleartext() - Memory problem !\n");
            free(cleartextKeys);
            return NULL;
        }

        strcpy(cleartextKeys[i], tmp = str_sub(apdu.r_str, i*GP_KEY_SIZE*2, (i+1)*GP_KEY_SIZE*2-1));
        free(tmp);
    }

    return cleartextKeys;

}

//=== SAM ENCRYPT/DECRYPT

/*
Returns the inData encrypted using a Triple DES CBC encryption with the provided C-ENC session SAM material.
The inData is padded using the ISO 9797 M2 method.
Expects: a char[8*2+1] initialized to "" for outIv, a char[9*2+1] initialized to "" for outContext
and a char[(SAM_MAX_CIPHER_BLOCK_SIZE+8)*2+1] initialized to "" for encData (+8 for padding)
*/
static int encryptEnc(DaplugDongle *daplugSAM, int SAMCtxKeyVersion, int SAMCtxKeyId, char *CENCSessionSAM, char *iv,
                      char *context, int isLastBlock, char *inData, char *outIv, char *outContext, char *encData){

    char    SAMCtxKeyVersion_str[1*2+1]="",
            SAMCtxKeyId_str[1*2+1]="";

    sprintf(SAMCtxKeyVersion_str,"%02X",SAMCtxKeyVersion);
    sprintf(SAMCtxKeyId_str,"%02X",SAMCtxKeyId);

    //Check C-ENC session SAM key
    if(strlen(CENCSessionSAM) != 24*2 || !isHexInput(CENCSessionSAM)){
        fprintf(stderr,"\nencryptEnc() - Wrong value for parameter CENCSessionSAM !\n");
        return 0;
    }

    //Check IV
    if(strlen(iv) != 8*2 || !isHexInput(iv)){
        fprintf(stderr,"\nencryptEnc() - Wrong value for parameter iv !\n");
        return 0;
    }

    //Check Context
    if(strlen(context) != 9*2 || !isHexInput(context)){
        fprintf(stderr,"\nencryptEnc() - Wrong value for parameter context !\n");
        return 0;
    }

    int lc = 43; // = 1+1+24+8+9

    //Check inData
    if(strlen(inData)/2 > SAM_MAX_CIPHER_BLOCK_SIZE || !isHexInput(inData)){
        fprintf(stderr,"\nencryptEnc() - Wrong value for parameter inData !\n");
        return 0;
    }

    lc = lc + strlen(inData)/2;

    char lc_s[1*2+1]="";
    sprintf(lc_s,"%02X",lc);

    //Form the apdu
    char apdu_str[APDU_CMD_MAXLEN*2+1]="";
    strcat(apdu_str,"D072");
    if(!isLastBlock){
        strcat(apdu_str,"0010");
    }else{
        strcat(apdu_str,"8010");
    }
    strcat(apdu_str, lc_s);
    strcat(apdu_str,SAMCtxKeyVersion_str);
    strcat(apdu_str,SAMCtxKeyId_str);
    strcat(apdu_str,CENCSessionSAM);
    strcat(apdu_str,iv);
    strcat(apdu_str,context);
    strcat(apdu_str, inData);

    //Set to apdu cde
    Apdu apdu;
    if(!setApduCmd(apdu_str,&apdu)){
        fprintf(stderr,"\nencryptEnc() - An error occured when setting the Apdu !\n");
        return 0;
    }

    //exchange it
    if(!exchangeApdu(daplugSAM,&apdu)){
        fprintf(stderr,"\nencryptEnc() - An error occured when exchanging the Apdu !\n");
        return 0;
    }

    if(strcmp(apdu.sw_str,"9000")){
        fprintf(stderr,"\nencryptEnc() - Apdu command ended abnormally !\n");
        return 0;
    }

    //pad size
    int paddedDataSize = strlen(inData)/2 + 1;
    while(paddedDataSize%8 != 0){
        paddedDataSize++;
    }

    //Encrypted Data
    char *tmp = NULL;
    if(!isLastBlock){
        strcpy(outIv, tmp = str_sub(apdu.r_str, 0, 8*2-1));
        free(tmp);
        strcpy(outContext, tmp = str_sub(apdu.r_str, 8*2, (8+9)*2-1));
        free(tmp);
        strcpy(encData, tmp = str_sub(apdu.r_str, (8+9)*2, (8+9+paddedDataSize)*2-1));
        free(tmp);
    }else{
        strcpy(outIv, "");
        strcpy(outContext, "");
        strcpy(encData, tmp = str_sub(apdu.r_str, 0, paddedDataSize*2-1));
        free(tmp);
    }

    return 1;
}

/*
Returns inData encrypted using a Triple DES ECB encryption with the provided DEK session SAM material.
The data is not padded and must be a multiple of 8 bytes.
Expects: a char[SAM_MAX_CIPHER_BLOCK_SIZE*2+1] initialized to "" for encData
*/
int encryptDek(DaplugDongle *daplugSAM, int SAMCtxKeyVersion, int SAMCtxKeyId, char *DEKSessionSAM, int isLastBlock, char *inData,
                      char *encData){

    char    SAMCtxKeyVersion_str[1*2+1]="",
            SAMCtxKeyId_str[1*2+1]="";

    sprintf(SAMCtxKeyVersion_str,"%02X",SAMCtxKeyVersion);
    sprintf(SAMCtxKeyId_str,"%02X",SAMCtxKeyId);

    //Check DEK session SAM key
    if(strlen(DEKSessionSAM) != 24*2 || !isHexInput(DEKSessionSAM)){
        fprintf(stderr,"\nencryptDek() - Wrong value for parameter DEKSessionSAM !\n");
        return 0;
    }

    int lc = 43; // = 1+1+24+8+9

    //Check inData
    if(((strlen(inData)/2)%8 != 0) || strlen(inData)/2 > SAM_MAX_CIPHER_BLOCK_SIZE || !isHexInput(inData)){
        fprintf(stderr,"\nencryptDek() - Wrong value for parameter inData !\n");
        return 0;
    }

    lc = lc + strlen(inData)/2;

    char lc_s[1*2+1]="";
    sprintf(lc_s,"%02X",lc);

    //Form the apdu
    char apdu_str[APDU_CMD_MAXLEN*2+1]="";
    strcat(apdu_str,"D072");
    if(!isLastBlock){
        strcat(apdu_str,"0020");
    }else{
        strcat(apdu_str,"8020");
    }
    strcat(apdu_str, lc_s);
    strcat(apdu_str,SAMCtxKeyVersion_str);
    strcat(apdu_str,SAMCtxKeyId_str);
    strcat(apdu_str,DEKSessionSAM);
    strcat(apdu_str,"0000000000000000000000000000000000");
    strcat(apdu_str, inData);

    //Set to apdu cde
    Apdu apdu;
    if(!setApduCmd(apdu_str,&apdu)){
        fprintf(stderr,"\nencryptDek() - An error occured when setting the Apdu !\n");
        return 0;
    }

    //exchange it
    if(!exchangeApdu(daplugSAM,&apdu)){
        fprintf(stderr,"\nencryptDek() - An error occured when exchanging the Apdu !\n");
        return 0;
    }

    if(strcmp(apdu.sw_str,"9000")){
        fprintf(stderr,"\nencryptDek() - Apdu command ended abnormally !\n");
        return 0;
    }

    int dataSize = strlen(inData)/2;

    //Encrypted Data
    char *tmp = NULL;
    if(!isLastBlock){
        strcpy(encData, tmp = str_sub(apdu.r_str, (8+9)*2, (8+9+dataSize)*2-1));
    }else{
        strcpy(encData, tmp = str_sub(apdu.r_str, 0, dataSize*2-1));
    }

    free(tmp);

    return 1;
}

/*
Returns encrypted inData decrypted using a Triple DES CBC decryption with the provided R-ENC session SAM material.
The inData is expected to be padded using the ISO 9797 M2 method.
Expects: a char[8*2+1] initialized to "" for outIv, a char[9*2+1] initialized to "" for outContext
and a char[SAM_MAX_CIPHER_BLOCK_SIZE*2+1] initialized to "" for decData
*/
static int decryptREnc(DaplugDongle *daplugSAM, int SAMCtxKeyVersion, int SAMCtxKeyId, char *RENCSessionSAM, char *iv,
                      char *context, int isLastBlock, char *inData, char *outIv, char *outContext, char *decData){

    char    SAMCtxKeyVersion_str[1*2+1]="",
            SAMCtxKeyId_str[1*2+1]="";

    sprintf(SAMCtxKeyVersion_str,"%02X",SAMCtxKeyVersion);
    sprintf(SAMCtxKeyId_str,"%02X",SAMCtxKeyId);

    //Check R-ENC session SAM key
    if(strlen(RENCSessionSAM) != 24*2 || !isHexInput(RENCSessionSAM)){
        fprintf(stderr,"\ndecryptRmac() - Wrong value for parameter RENCSessionSAM !\n");
        return 0;
    }

    //Check IV
    if(strlen(iv) != 8*2 || !isHexInput(iv)){
        fprintf(stderr,"\ndecryptRmac() - Wrong value for parameter iv !\n");
        return 0;
    }

    //Check Context
    if(strlen(context) != 9*2 || !isHexInput(context)){
        fprintf(stderr,"\ndecryptRmac() - Wrong value for parameter context !\n");
        return 0;
    }

    int lc = 43; // = 1+1+24+8+9

    //Check inData
    if(strlen(inData) == 0 || strlen(inData)/2 > SAM_MAX_CIPHER_BLOCK_SIZE || !isHexInput(inData)){
        fprintf(stderr,"\ndecryptRmac() - Wrong value for parameter inData !\n");
        return 0;
    }

    lc = lc + strlen(inData)/2;

    char lc_s[1*2+1]="";
    sprintf(lc_s,"%02X",lc);

    //Form the apdu
    char apdu_str[APDU_CMD_MAXLEN*2+1]="";
    strcat(apdu_str,"D072");
    if(!isLastBlock){
        strcat(apdu_str,"0030");
    }else{
        strcat(apdu_str,"8030");
    }
    strcat(apdu_str, lc_s);
    strcat(apdu_str,SAMCtxKeyVersion_str);
    strcat(apdu_str,SAMCtxKeyId_str);
    strcat(apdu_str,RENCSessionSAM);
    strcat(apdu_str,iv);
    strcat(apdu_str,context);
    strcat(apdu_str, inData);

    //Set to apdu cde
    Apdu apdu;
    if(!setApduCmd(apdu_str,&apdu)){
        fprintf(stderr,"\ndecryptRmac() - An error occured when setting the Apdu !\n");
        return 0;
    }

    //exchange it
    if(!exchangeApdu(daplugSAM,&apdu)){
        fprintf(stderr,"\ndecryptRmac() - An error occured when exchanging the Apdu !\n");
        return 0;
    }

    if(strcmp(apdu.sw_str,"9000")){
        fprintf(stderr,"\ndecryptRmac() - Apdu command ended abnormally !\n");
        return 0;
    }

    int clearDataSize = 0;

    //Decrypted Data
    char *tmp = NULL;
    if(!isLastBlock){
        clearDataSize = apdu.rep_data_len - (8+9);
        strcpy(outIv, tmp = str_sub(apdu.r_str, 0, 8*2-1));
        free(tmp);
        strcpy(outContext, tmp = str_sub(apdu.r_str, 8*2, (8+9)*2-1));
        free(tmp);
        strcpy(decData, tmp = str_sub(apdu.r_str, (8+9)*2, (8+9+clearDataSize)*2-1));
        free(tmp);
    }else{
        clearDataSize = apdu.rep_data_len;
        strcpy(outIv, "");
        strcpy(outContext, "");
        strcpy(decData, tmp = str_sub(apdu.r_str, 0, clearDataSize*2-1));
        free(tmp);
    }

    return 1;
}

//=== SAM SIGN

/*
Returns inData signature using a Triple DES CBC encryption with the provided C-ENC session SAM material.
This signature is used to compute the Host cryptogram or the Card Cryptogram
*/
static int signEnc(DaplugDongle *daplugSAM, int SAMCtxKeyVersion, int SAMCtxKeyId, char *CENCSessionSAM, char *iv,
                      char *context, int isLastBlock, char *inData, char *outIv, char *outContext, char *signature){

    char    SAMCtxKeyVersion_str[1*2+1]="",
            SAMCtxKeyId_str[1*2+1]="";

    sprintf(SAMCtxKeyVersion_str,"%02X",SAMCtxKeyVersion);
    sprintf(SAMCtxKeyId_str,"%02X",SAMCtxKeyId);

    //Check C-ENC session SAM key
    if(strlen(CENCSessionSAM) != 24*2 || !isHexInput(CENCSessionSAM)){
        fprintf(stderr,"\nsignEnc() - Wrong value for parameter CENCSessionSAM !\n");
        return 0;
    }

    //Check IV
    if(strlen(iv) != 8*2 || !isHexInput(iv)){
        fprintf(stderr,"\nsignEnc() - Wrong value for parameter iv !\n");
        return 0;
    }

    //Check Context
    if(strlen(context) != 9*2 || !isHexInput(context)){
        fprintf(stderr,"\nsignEnc() - Wrong value for parameter context !\n");
        return 0;
    }

    int lc = 43; // = 1+1+24+8+9

    //Check inData
    if(strlen(inData) == 0 || strlen(inData)/2 > SAM_MAX_SIGNATURE_BLOCK_SIZE || !isHexInput(inData)){
        fprintf(stderr,"\nsignEnc() - Wrong value for parameter inData !\n");
        return 0;
    }

    lc = lc + strlen(inData)/2;

    char lc_s[1*2+1]="";
    sprintf(lc_s,"%02X",lc);

    //Form the apdu
    char apdu_str[APDU_CMD_MAXLEN*2+1]="";
    strcat(apdu_str,"D074");
    if(!isLastBlock){
        strcat(apdu_str,"0010");
    }else{
        strcat(apdu_str,"8010");
    }
    strcat(apdu_str, lc_s);
    strcat(apdu_str,SAMCtxKeyVersion_str);
    strcat(apdu_str,SAMCtxKeyId_str);
    strcat(apdu_str,CENCSessionSAM);
    strcat(apdu_str,iv);
    strcat(apdu_str,context);
    strcat(apdu_str, inData);

    //Set to apdu cde
    Apdu apdu;
    if(!setApduCmd(apdu_str,&apdu)){
        fprintf(stderr,"\nsignEnc() - An error occured when setting the Apdu !\n");
        return 0;
    }

    //exchange it
    if(!exchangeApdu(daplugSAM,&apdu)){
        fprintf(stderr,"\nsignEnc() - An error occured when exchanging the Apdu !\n");
        return 0;
    }

    if(strcmp(apdu.sw_str,"9000")){
        fprintf(stderr,"\nsignEnc() - Apdu command ended abnormally !\n");
        return 0;
    }

    //Encrypted Data
    char *tmp = NULL;
    if(!isLastBlock){
        strcpy(outIv, tmp = str_sub(apdu.r_str, 0, 8*2-1));
        free(tmp);
        strcpy(outContext, tmp = str_sub(apdu.r_str, 8*2, (8+9)*2-1));
        free(tmp);
        strcpy(signature, "");
    }else{
        strcpy(outIv, "");
        strcpy(outContext, "");
        strcpy(signature, apdu.r_str);
    }

    return 1;

}

/*
Returns the inData signature using a retail MAC with the provided C-MAC session SAM material
*/
static int signRetailCmac(DaplugDongle *daplugSAM, int SAMCtxKeyVersion, int SAMCtxKeyId, char *CMACSessionSAM, char *iv,
                      char *context, int isLastBlock, char *inData, char *outIv, char *outContext, char *signature){

    char    SAMCtxKeyVersion_str[1*2+1]="",
            SAMCtxKeyId_str[1*2+1]="";

    sprintf(SAMCtxKeyVersion_str,"%02X",SAMCtxKeyVersion);
    sprintf(SAMCtxKeyId_str,"%02X",SAMCtxKeyId);

    //Check C-ENC session SAM key
    if(strlen(CMACSessionSAM) != 24*2 || !isHexInput(CMACSessionSAM)){
        fprintf(stderr,"\nsignRetailCmac() - Wrong value for parameter CMACSessionSAM !\n");
        return 0;
    }

    //Check IV
    if(strlen(iv) != 8*2 || !isHexInput(iv)){
        fprintf(stderr,"\nsignRetailCmac() - Wrong value for parameter iv !\n");
        return 0;
    }

    //Check Context
    if(strlen(context) != 9*2 || !isHexInput(context)){
        fprintf(stderr,"\nsignRetailCmac() - Wrong value for parameter context !\n");
        return 0;
    }

    int lc = 43; // = 1+1+24+8+9

    //Check inData
    if(strlen(inData) == 0 || strlen(inData)/2 > SAM_MAX_SIGNATURE_BLOCK_SIZE || !isHexInput(inData)){
        fprintf(stderr,"\nsignRetailCmac() - Wrong value for parameter inData !\n");
        return 0;
    }

    lc = lc + strlen(inData)/2;

    char lc_s[1*2+1]="";
    sprintf(lc_s,"%02X",lc);

    //Form the apdu
    char apdu_str[APDU_CMD_MAXLEN*2+1]="";
    strcat(apdu_str,"D074");
    if(!isLastBlock){
        strcat(apdu_str,"0020");
    }else{
        strcat(apdu_str,"8020");
    }
    strcat(apdu_str, lc_s);
    strcat(apdu_str,SAMCtxKeyVersion_str);
    strcat(apdu_str,SAMCtxKeyId_str);
    strcat(apdu_str,CMACSessionSAM);
    strcat(apdu_str,iv);
    strcat(apdu_str,context);
    strcat(apdu_str, inData);

    //Set to apdu cde
    Apdu apdu;
    if(!setApduCmd(apdu_str,&apdu)){
        fprintf(stderr,"\nsignRetailCmac() - An error occured when setting the Apdu !\n");
        return 0;
    }

    //exchange it
    if(!exchangeApdu(daplugSAM,&apdu)){
        fprintf(stderr,"\nsignRetailCmac() - An error occured when exchanging the Apdu !\n");
        return 0;
    }

    if(strcmp(apdu.sw_str,"9000")){
        fprintf(stderr,"\nsignRetailCmac() - Apdu command ended abnormally !\n");
        return 0;
    }

    //Signature
    char *tmp = NULL;
    if(!isLastBlock){
        strcpy(outIv, tmp = str_sub(apdu.r_str, 0, 8*2-1));
        free(tmp);
        strcpy(outContext, tmp = str_sub(apdu.r_str, 8*2, (8+9)*2-1));
        free(tmp);
        strcpy(signature, "");
    }else{
        strcpy(outIv, "");
        strcpy(outContext, "");
        strcpy(signature, apdu.r_str);
    }

    return 1;
}

/*
Returns the inData signature using a retail MAC with the provided R-MAC session SAM material
*/
static int signRetailRmac(DaplugDongle *daplugSAM, int SAMCtxKeyVersion, int SAMCtxKeyId, char *RMACSessionSAM, char *iv,
                      char *context, int isLastBlock, char *inData, char *outIv, char *outContext, char *signature){

    char    SAMCtxKeyVersion_str[1*2+1]="",
            SAMCtxKeyId_str[1*2+1]="";

    sprintf(SAMCtxKeyVersion_str,"%02X",SAMCtxKeyVersion);
    sprintf(SAMCtxKeyId_str,"%02X",SAMCtxKeyId);

    //Check C-ENC session SAM key
    if(strlen(RMACSessionSAM) != 24*2 || !isHexInput(RMACSessionSAM)){
        fprintf(stderr,"\nsignRetailRmac() - Wrong value for parameter RMACSessionSAM !\n");
        return 0;
    }

    //Check IV
    if(strlen(iv) != 8*2 || !isHexInput(iv)){
        fprintf(stderr,"\nsignRetailRmac() - Wrong value for parameter iv !\n");
        return 0;
    }

    //Check Context
    if(strlen(context) != 9*2 || !isHexInput(context)){
        fprintf(stderr,"\nsignRetailRmac() - Wrong value for parameter context !\n");
        return 0;
    }

    int lc = 43; // = 1+1+24+8+9

    //Check inData
    if(strlen(inData) == 0 || strlen(inData)/2 > SAM_MAX_SIGNATURE_BLOCK_SIZE || !isHexInput(inData)){
        fprintf(stderr,"\nsignRetailRmac() - Wrong value for parameter inData !\n");
        return 0;
    }

    lc = lc + strlen(inData)/2;

    char lc_s[1*2+1]="";
    sprintf(lc_s,"%02X",lc);

    //Form the apdu
    char apdu_str[APDU_CMD_MAXLEN*2+1]="";
    strcat(apdu_str,"D074");
    if(!isLastBlock){
        strcat(apdu_str,"0030");
    }else{
        strcat(apdu_str,"8030");
    }
    strcat(apdu_str, lc_s);
    strcat(apdu_str,SAMCtxKeyVersion_str);
    strcat(apdu_str,SAMCtxKeyId_str);
    strcat(apdu_str,RMACSessionSAM);
    strcat(apdu_str,iv);
    strcat(apdu_str,context);
    strcat(apdu_str, inData);

    //Set to apdu cde
    Apdu apdu;
    if(!setApduCmd(apdu_str,&apdu)){
        fprintf(stderr,"\nsignRetailRmac() - An error occured when setting the Apdu !\n");
        return 0;
    }

    //exchange it
    if(!exchangeApdu(daplugSAM,&apdu)){
        fprintf(stderr,"\nsignRetailRmac() - An error occured when exchanging the Apdu !\n");
        return 0;
    }

    if(strcmp(apdu.sw_str,"9000")){
        fprintf(stderr,"\nsignRetailRmac() - Apdu command ended abnormally !\n");
        return 0;
    }

    //Signature
    char *tmp = NULL;
    if(!isLastBlock){
        strcpy(outIv, tmp = str_sub(apdu.r_str, 0, 8*2-1));
        free(tmp);
        strcpy(outContext, tmp = str_sub(apdu.r_str, 8*2, (8+9)*2-1));
        free(tmp);
        strcpy(signature, "");
    }else{
        strcpy(outIv, "");
        strcpy(outContext, "");
        strcpy(signature, apdu.r_str);
    }

    return 1;
}

//Encrypt/decrypt Apdu data using SAM
int SAM_dataEncryption(DaplugDongle *daplugSAM, int SAMCtxKeyVersion, int SAMCtxKeyId, char *sessionSAMKey,
                       char *inData, int enc, char *outData){

    char    iv[8*2+1]="0000000000000000",
            context[9*2+1]="000000000000000000",
            nextIv[8*2+1]="",
            nextContext[9*2+1]="",
            tempOutData[APDU_D_MAXLEN*2+1]="";

    int isLastBlock = 0;

    int     inDataLen = strlen(inData) / 2,
            lastPartLen = inDataLen % SAM_MAX_CIPHER_BLOCK_SIZE;

    //Some checks
    if((enc != SAM_ENCRYPT) && (enc != SAM_DECRYPT)){
        fprintf(stderr,"\nSAM_dataEncryption() - Invalid value for parameter enc : %d", enc);
        return 0;
    }

    if(inDataLen > APDU_D_MAXLEN){
        fprintf(stderr,"\nSAM_dataEncryption() - Max authorized data length is %d bytes !\n", APDU_D_MAXLEN);
        return 0;
    }

    int nb = (lastPartLen == 0) ? (inDataLen / SAM_MAX_CIPHER_BLOCK_SIZE) :
                                  ((inDataLen / SAM_MAX_CIPHER_BLOCK_SIZE) + 1);

    if(nb == 0) nb = 1; //Use case when no data : we pad anyway and we encrypt

    char *dataPart = NULL;
    char processedData[(SAM_MAX_CIPHER_BLOCK_SIZE+8)*2+1]=""; //+8 : max possible padding
    int offset = 0;
    while(nb){
        //Is it the last block?
        if(nb == 1) isLastBlock = 1; else isLastBlock = 0;

        //Data part
        if((nb > 1) || (lastPartLen == 0)){
             dataPart = str_sub(inData, offset * 2, (offset + SAM_MAX_CIPHER_BLOCK_SIZE) * 2 - 1);
        }
        if((nb == 1) && (lastPartLen != 0)){
             dataPart = str_sub(inData, offset * 2, (offset + lastPartLen) * 2 - 1);
        }

        //process data
        if(enc == SAM_ENCRYPT){
            if(!encryptEnc(daplugSAM, SAMCtxKeyVersion,SAMCtxKeyId, sessionSAMKey, iv, context, isLastBlock, dataPart,
                           nextIv, nextContext, processedData)){
                fprintf(stderr,"\nSAM_dataEncryption() - An error occured when processing data !");
                return 0;
            }
        }
        if(enc == SAM_DECRYPT){
            if(!decryptREnc(daplugSAM, SAMCtxKeyVersion,SAMCtxKeyId, sessionSAMKey, iv, context, isLastBlock, dataPart,
                           nextIv, nextContext, processedData)){
                fprintf(stderr,"\nSAM_dataEncryption() - An error occured when processing data !");
                return 0;
            }
        }

        //update data
        strcat(tempOutData, processedData);
        strcpy(processedData, "");

        strcpy(iv, nextIv);
        strcpy(context, nextContext);
        offset = offset + SAM_MAX_CIPHER_BLOCK_SIZE;
        nb--;

        free(dataPart);
        dataPart = NULL;
    }

    strcpy(outData, tempOutData);

    return 1;

}

//compute retail mac using SAM
int SAM_computeRetailMac(DaplugDongle *daplugSAM, int SAMCtxKeyVersion, int SAMCtxKeyId, char *sessionSAMKey,
                       char *data, char *oldRetailMac, int cmac, char *retailMac){

    char    iv[8*2+1]="",
            context[9*2+1]="000000000000000000",
            nextIv[8*2+1]="",
            nextContext[9*2+1]="",
            signature[8*2+1]="",
            inData[(5+255+1+255+2+8+8)*2+1]= ""; //max_apdu_len + 1 + max_rep_data_len + sw_len + any_pad_len + any_previous_mac_len

    //Some checks
    if((cmac != SAM_CMAC) && (cmac != SAM_RMAC)){
        fprintf(stderr,"\nSAM_computeRetailMac() - Invalid value for parameter cmac : %d", cmac);
        return 0;
    }

    if(cmac == SAM_CMAC){
        strcpy(iv, "0000000000000000");
    }else{
        strcpy(iv, oldRetailMac);
    }

    //Data to sign
    if(cmac == SAM_CMAC){
        strcpy(inData, oldRetailMac);
    }
    strcat(inData, data);

    //Process
    int     inDataLen = strlen(inData) / 2,
            lastPartLen = inDataLen % SAM_MAX_SIGNATURE_BLOCK_SIZE;

    int nb = (lastPartLen == 0) ? (inDataLen / SAM_MAX_SIGNATURE_BLOCK_SIZE) :
                                  ((inDataLen / SAM_MAX_SIGNATURE_BLOCK_SIZE) + 1);

    char *dataPart = NULL;
    int offset = 0;
    int isLastBlock = 0;

    while(nb){
        //Is it the last block?
        if(nb == 1) isLastBlock = 1; else isLastBlock = 0;

        //Data part
        if((nb > 1) || (lastPartLen == 0)){
             dataPart = str_sub(inData, offset * 2, (offset + SAM_MAX_SIGNATURE_BLOCK_SIZE) * 2 - 1);
        }
        if((nb == 1) && (lastPartLen != 0)){
             dataPart = str_sub(inData, offset * 2, (offset + lastPartLen) * 2 - 1);
        }

        //process data
        if(cmac == SAM_CMAC){
            if(!signRetailCmac(daplugSAM, SAMCtxKeyVersion,SAMCtxKeyId, sessionSAMKey, iv, context, isLastBlock, dataPart,
                           nextIv, nextContext, signature)){
                fprintf(stderr,"\nSAM_computeRetailMac() - An error occured when processing data !");
                return 0;
            }
        }
        if(cmac == SAM_RMAC){
            if(!signRetailRmac(daplugSAM, SAMCtxKeyVersion,SAMCtxKeyId, sessionSAMKey, iv, context, isLastBlock, dataPart,
                           nextIv, nextContext, signature)){
                fprintf(stderr,"\nSAM_computeRetailMac() - An error occured when processing data !");
                return 0;
            }
        }

        //update data
        strcpy(iv, nextIv);
        strcpy(context, nextContext);
        offset = offset + SAM_MAX_SIGNATURE_BLOCK_SIZE;
        nb--;

        free(dataPart);
        dataPart = NULL;
    }

    strcpy(retailMac, signature);

    return 1;

}

//compute card/host cryptogram using SAM
int SAM_computeCryptogram(DaplugDongle *daplugSAM, int SAMCtxKeyVersion, int SAMCtxKeyId, char *CENCSessionSAMKey,
                          char *hostChallenge, char *cardChallenge, char *counter, int cryptogramType, char *cryptogram){

    char    outIv[8*2+1]="",
            outContext[9*2+1]="",
            inData[24*2+1] = "",
            type[5]="";

    if(cryptogramType == SAM_CARD_CRYPTOGRAM){

        strcpy(type, "card");

        strcat(inData,hostChallenge);
        strcat(inData,counter);
        strcat(inData,cardChallenge);

    }else if(cryptogramType == SAM_HOST_CRYPTOGRAM){

        strcpy(type, "host");

        strcat(inData,counter);
        strcat(inData,cardChallenge);
        strcat(inData,hostChallenge);
    }else{
        fprintf(stderr,"\nSAM_computeCryptogram() - Invalid value for parameter cryptogramType : %d", cryptogramType);
        return 0;
    }

    if(!signEnc(daplugSAM, SAMCtxKeyVersion, SAMCtxKeyId, CENCSessionSAMKey,
            "0000000000000000", "000000000000000000", 1, inData, outIv, outContext, cryptogram)){

        fprintf(stderr,"\nSAM_computeCryptogram() - Cannot compute %s cryptogram !", type);
        return 0;
    }

    return 1;
}

//compute SAM material session keys
char **SAM_computeSessionKeys(DaplugDongle *daplugSAM, int SAMCtxKeyVersion, int SAMCtxKeyId, int SAMGPUsableKeyVersion,
                               int flag, int counter, char *div1, char *div2){

    //Compute session keys SAM material
    char **sessionSAMKeys = diversifyGP(daplugSAM, SAMCtxKeyVersion, SAMCtxKeyId, SAMGPUsableKeyVersion, flag, counter, div1, div2);

    if(sessionSAMKeys == NULL){
        fprintf(stderr,"\nSAM_computeSessionKeys(): Cannot compute session keys SAM material !\n");
        return NULL;
    }

    return sessionSAMKeys;

}

//create putkey command using SAM
int SAM_createPutKeyCommand(DaplugDongle *daplugSAM, int SAMCtxKeyVersion, int SAMCtxKeyId,
                            int SAMProvisionableKeyVersion, char *DEKSessionSAMKey, char *div1, char *div2,
                            char *numKeyset, char *mode, char *keyUsage, char *keyAccess, char *putKeyCommand){

    char putKeyCommand_temp[(255+5)*2+1]="",
         element1[2*2+1]="80d8",
         element2[1*2+1]="", //numKeyset
         element3[1*2+1]="", //mode
         element4[1*2+1]="55", //"58", //Lc
         element5[3*2+1]="ff8010", //key type + key length
         element6[16*2+1]="", //(GP-ENC) value, wrapped by session DEK
         element7[1*2+1]="03", //KCV length
         element8[3*2+1]="", //Key1 KCV
         element9[1*2+1]="01", //key usage length
         element10[1*2+1]="", //key usage
         element11[1*2+1]="02", //key access length
         element12[2*2+1]="", //key access
         element13[16*2+1]="", //(GP-MAC) value, wrapped by session DEK
         element14[3*2+1]="", //Key2 KCV
         element15[16*2+1]="", //(GP-DEK) value, wrapped by session DEK
         element16[3*2+1]="", //Key3 KCV
         element17[10*2+1]=""; //Keyset diversifier value for a GlobalPlatform Keyset

    strcpy(element2,numKeyset);
    strcpy(element3,mode);
    strcpy(element10,keyUsage);
    strcpy(element12,keyAccess);

    //Wrapped keys and KCVs using SAM

    char    **wrappedKeys = NULL,
            **kcvs = NULL;

    //Diversifiers
    int flag = 0;
    if((div1 != NULL) && (div2 != NULL)){
        flag = SAM_2_DIV;
    }else if(div1 != NULL){
        flag = SAM_1_DIV;
    }

    if(!diversifyForPutkey(daplugSAM, SAMCtxKeyVersion, SAMCtxKeyId, SAMProvisionableKeyVersion,
                           flag, DEKSessionSAMKey, div1, div2, &wrappedKeys, &kcvs)){
        fprintf(stderr,"\nSAM_createPutKeyCommand(): Cannot create putkey command !\n");
        return 0;
    }

    strcpy(element6, wrappedKeys[0]);
    strcpy(element13, wrappedKeys[1]);
    strcpy(element15, wrappedKeys[2]);

    strcpy(element8, kcvs[0]);
    strcpy(element14, kcvs[1]);
    strcpy(element16, kcvs[2]);

    //free allocated memory
    int i;
    for(i=0;i<3;i++){
        free(wrappedKeys[i]);
        free(kcvs[i]);
    }
    free(wrappedKeys);
    free(kcvs);

    //form the put key command
    strcat(putKeyCommand_temp,element1);
    strcat(putKeyCommand_temp,element2);
    strcat(putKeyCommand_temp,element3);
    strcat(putKeyCommand_temp,element4);
    strcat(putKeyCommand_temp,element2);
    strcat(putKeyCommand_temp,element5);
    strcat(putKeyCommand_temp,element6);
    strcat(putKeyCommand_temp,element7);
    strcat(putKeyCommand_temp,element8);
    strcat(putKeyCommand_temp,element9);
    strcat(putKeyCommand_temp,element10);
    strcat(putKeyCommand_temp,element11);
    strcat(putKeyCommand_temp,element12);
    strcat(putKeyCommand_temp,element5);
    strcat(putKeyCommand_temp,element13);
    strcat(putKeyCommand_temp,element7);
    strcat(putKeyCommand_temp,element14);
    strcat(putKeyCommand_temp,element9);
    strcat(putKeyCommand_temp,element10);
    strcat(putKeyCommand_temp,element11);
    strcat(putKeyCommand_temp,element12);
    strcat(putKeyCommand_temp,element5);
    strcat(putKeyCommand_temp,element15);
    strcat(putKeyCommand_temp,element7);
    strcat(putKeyCommand_temp,element16);
    strcat(putKeyCommand_temp,element9);
    strcat(putKeyCommand_temp,element10);
    strcat(putKeyCommand_temp,element11);
    strcat(putKeyCommand_temp,element12);
    strcat(putKeyCommand_temp,element17);

    strcpy(putKeyCommand,putKeyCommand_temp);

    return 1;
}

char** SAM_computeDiversifiedKey(DaplugDongle *daplugSAM, int SAMExportableKeyVersion, int flag, char *div1, char *div2){

    return diversifyCleartext(daplugSAM, SAMExportableKeyVersion, flag, div1, div2);

}
