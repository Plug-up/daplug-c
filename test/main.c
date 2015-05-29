/**
 * \file main.c
 * \brief
 * \author S.BENAMAR s.benamar@plug-up.com
 * \
 * \version 1.0
 * \date 09/06/2014
 *
 * Different sets of tests to understand how the C Daplug API works and what we can do with.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <daplug/keyboard.h>
#include <daplug/DaplugDongle.h>

#define TRUE 1
#define FALSE 0

DaplugDongle *card, *sam;

extern FILE *flog_apdu;

int counterFileId = 0xc01d,
    kbFileId = 0x0800,
    modhexFileId = 0x0001,

    //For testing SAM with community keyset
    SAMCtxKeyVersion = 0xFC,
    SAMCtxKeyId = 1,
    SAMGPKeyVersion = 0x66,
    TargetKeyVersion = 0x42;

Keyset keyset01, newKeyset, SAMProvisionnableKeyset,
       transientKeyset, encDecKeyset,
       hmacSha1Keyset, hotpKeyset, totpKeyset,
       TimeSrcKeyset;
char *diversifier1 = "0123456789abcdeffedcba9876543210",
     *diversifier2 = "fedcba98765432100123456789abcdef";


int testModeSwitching(DaplugDongle *dpdCard, int mode){

    if(mode == 0 ){
        fprintf(stderr,"\n+Switch to hid mode...");
        if(!Daplug_winusbToHid(dpdCard)){
            fprintf(stderr, "\n***** An error occured during the test ! *****\n");
            return 0;
        }
    }

    if(mode == 1){
        fprintf(stderr,"\n+Switch to winusb mode...");
        if(!Daplug_hidToWinusb(dpdCard)){
            fprintf(stderr, "\n***** An error occured during the test ! *****\n");
            return 0;
        }
    }

    fprintf(stderr, "\n**************************************************************");
    fprintf(stderr, "\n********** \"testModeSwitching\" terminated with success *******\n");
    fprintf(stderr, "**************************************************************\n");

    return 1;

}

int testAuthentication(DaplugDongle *dpdCard, int level){

    switch(level){
        case 1 :
            if(!Daplug_authenticate(dpdCard, keyset01,C_MAC,NULL,NULL)){
                fprintf(stderr, "\n***** An error occured during the test ! *****\n");
                return 0;
            }
            break;
        case 2 :
            if(!Daplug_authenticate(dpdCard, keyset01,C_MAC+C_DEC,NULL,NULL)){
                fprintf(stderr, "\n***** An error occured during the test ! *****\n");
                return 0;
            }
            break;
        case 3 :
            if(!Daplug_authenticate(dpdCard, keyset01,C_MAC+R_MAC,NULL,NULL)){
                fprintf(stderr, "\n***** An error occured during the test ! *****\n");
                return 0;
            }
            break;
        case 4 :
            if(!Daplug_authenticate(dpdCard, keyset01,C_MAC+R_ENC,NULL,NULL)){
                fprintf(stderr, "\n***** An error occured during the test ! *****\n");
                return 0;
            }
            break;
        case 5 :
            if(!Daplug_authenticate(dpdCard, keyset01,C_MAC+C_DEC+R_MAC,NULL,NULL)){
                fprintf(stderr, "\n***** An error occured during the test ! *****\n");
                return 0;
            }
            break;
        case 6 :
            if(!Daplug_authenticate(dpdCard, keyset01,C_MAC+C_DEC+R_ENC,NULL,NULL)){
                fprintf(stderr, "\n***** An error occured during the test ! *****\n");
                return 0;
            }
            break;
        case 7 :
            if(!Daplug_authenticate(dpdCard, keyset01,C_MAC+R_MAC+R_ENC,NULL,NULL)){
                fprintf(stderr, "\n***** An error occured during the test ! *****\n");
                return 0;
            }
            break;
        case 8 :
            if(!Daplug_authenticate(dpdCard, keyset01,C_MAC+C_DEC+R_MAC+R_ENC,NULL,NULL)){
                fprintf(stderr, "\n***** An error occured during the test ! *****\n");
                return 0;
            }
            break;
        default :
            if(!Daplug_authenticate(dpdCard, keyset01,C_MAC,NULL,NULL)){
                fprintf(stderr, "\n***** An error occured during the test ! *****\n");
                return 0;
            }
    }

    fprintf(stderr, "\n***************************************************************");
    fprintf(stderr, "\n********** \"testAuthentication\" terminated with success *******\n");
    fprintf(stderr, "***************************************************************\n");

    return 1;

}

int testDivAuthentication(DaplugDongle *dpdCard, int level){

    fprintf(stderr,"\n+Authentication using diversified keys...");

    //Keyset 01 with diversified keys
    Keyset divk;
    divk.version = keyset01.version;
    Daplug_computeDiversifiedKeys(dpdCard, keyset01,&divk,diversifier1);

    switch(level){
        case 1 :
            if(!Daplug_authenticate(dpdCard, divk,C_MAC,NULL,NULL)){
                fprintf(stderr, "\n***** An error occured during the test ! *****\n");
                return 0;
            }
            break;
        case 2 :
            if(!Daplug_authenticate(dpdCard, divk,C_MAC+C_DEC,diversifier1,NULL)){
                fprintf(stderr, "\n***** An error occured during the test ! *****\n");
                return 0;
            }
            break;
        case 3 :
            if(!Daplug_authenticate(dpdCard, divk,C_MAC+R_MAC,diversifier1,NULL)){
                fprintf(stderr, "\n***** An error occured during the test ! *****\n");
                return 0;
            }
            break;
        case 4 :
            if(!Daplug_authenticate(dpdCard, divk,C_MAC+R_ENC,diversifier1,NULL)){
                fprintf(stderr, "\n***** An error occured during the test ! *****\n");
                return 0;
            }
            break;
        case 5 :
            if(!Daplug_authenticate(dpdCard, divk,C_MAC+C_DEC+R_MAC,diversifier1,NULL)){
                fprintf(stderr, "\n***** An error occured during the test ! *****\n");
                return 0;
            }
            break;
        case 6 :
            if(!Daplug_authenticate(dpdCard, divk,C_MAC+C_DEC+R_ENC,diversifier1,NULL)){
                fprintf(stderr, "\n***** An error occured during the test ! *****\n");
                return 0;
            }
            break;
        case 7 :
            if(!Daplug_authenticate(dpdCard, divk,C_MAC+R_MAC+R_ENC,diversifier1,NULL)){
                fprintf(stderr, "\n***** An error occured during the test ! *****\n");
                return 0;
            }
            break;
        case 8 :
            if(!Daplug_authenticate(dpdCard, divk,C_MAC+C_DEC+R_MAC+R_ENC,diversifier1,NULL)){
                fprintf(stderr, "\n***** An error occured during the test ! *****\n");
                return 0;
            }
            break;
        default :
            if(!Daplug_authenticate(dpdCard, divk,C_MAC,diversifier1,NULL)){
                fprintf(stderr, "\n***** An error occured during the test ! *****\n");
                return 0;
            }
    }

    fprintf(stderr, "\n******************************************************************");
    fprintf(stderr, "\n********** \"testDivAuthentication\" terminated with success *******\n");
    fprintf(stderr, "******************************************************************\n");

    return 1;

}

int testAuthenticationWithSam(DaplugDongle *dpdCard, DaplugDongle *dpdSAM, int level){

    //Chip serial as diversifier1
    char div1[16*2+1]="";
    if(!Daplug_getChipDiversifier(dpdCard, div1)){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }

    switch(level){

        case 2 :
            if(!Daplug_authenticateUsingSAM(dpdCard, dpdSAM, SAMCtxKeyVersion, SAMCtxKeyId, SAMGPKeyVersion, TargetKeyVersion, C_MAC+C_DEC, div1, NULL)){
                fprintf(stderr, "\n***** An error occured during the test ! *****\n");
                return 0;
            }
            break;
        case 3 :
            if(!Daplug_authenticateUsingSAM(dpdCard, dpdSAM, SAMCtxKeyVersion, SAMCtxKeyId, SAMGPKeyVersion, TargetKeyVersion, C_MAC+R_MAC, div1, NULL)){
                fprintf(stderr, "\n***** An error occured during the test ! *****\n");
                return 0;
            }
            break;
        case 4 :
            if(!Daplug_authenticateUsingSAM(dpdCard, dpdSAM, SAMCtxKeyVersion, SAMCtxKeyId, SAMGPKeyVersion, TargetKeyVersion, C_MAC+R_ENC, div1, NULL)){
                fprintf(stderr, "\n***** An error occured during the test ! *****\n");
                return 0;
            }
            break;
        case 5 :
            if(!Daplug_authenticateUsingSAM(dpdCard, dpdSAM, SAMCtxKeyVersion, SAMCtxKeyId, SAMGPKeyVersion, TargetKeyVersion, C_MAC+C_DEC+R_MAC, div1, NULL)){
                fprintf(stderr, "\n***** An error occured during the test ! *****\n");
                return 0;
            }
            break;
        case 6 :
            if(!Daplug_authenticateUsingSAM(dpdCard, dpdSAM, SAMCtxKeyVersion, SAMCtxKeyId, SAMGPKeyVersion, TargetKeyVersion, C_MAC+C_DEC+R_ENC, div1, NULL)){
                fprintf(stderr, "\n***** An error occured during the test ! *****\n");
                return 0;
            }
            break;
        case 7 :
            if(!Daplug_authenticateUsingSAM(dpdCard, dpdSAM, SAMCtxKeyVersion, SAMCtxKeyId, SAMGPKeyVersion, TargetKeyVersion, C_MAC+R_MAC+R_ENC, div1, NULL)){
                fprintf(stderr, "\n***** An error occured during the test ! *****\n");
                return 0;
            }
            break;
        case 8 :
            if(!Daplug_authenticateUsingSAM(dpdCard, dpdSAM, SAMCtxKeyVersion, SAMCtxKeyId, SAMGPKeyVersion, TargetKeyVersion, C_MAC+C_DEC+R_MAC+R_ENC, div1, NULL)){
                fprintf(stderr, "\n***** An error occured during the test ! *****\n");
                return 0;
            }
            break;
        default :
            if(!Daplug_authenticateUsingSAM(dpdCard, dpdSAM, SAMCtxKeyVersion, SAMCtxKeyId, SAMGPKeyVersion, TargetKeyVersion, C_MAC, div1, NULL)){
                fprintf(stderr, "\n***** An error occured during the test ! *****\n");
                return 0;
            }
    }

    fprintf(stderr, "\n**********************************************************************");
    fprintf(stderr, "\n********** \"testAuthenticationWithSam\" terminated with success *******\n");
    fprintf(stderr, "**********************************************************************\n");

    return 1;

}

int testGetSerial(DaplugDongle *dpdCard){

    fprintf(stderr,"\n+TEST : GET SERIAL");
    char sn[18*2+1]="";
    if(!Daplug_getDongleSerial(dpdCard, sn)){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }

    fprintf(stderr,"\nSN = %s\n",sn);

    fprintf(stderr, "\n**********************************************************");
    fprintf(stderr, "\n********** \"testGetSerial\" terminated with success *******\n");
    fprintf(stderr, "**********************************************************\n");

    return 1;
}

int testGetStatus(DaplugDongle *dpdCard){

    int s = 0;
    char* status = "";
    fprintf(stderr,"\n+TEST : GET STATUS");
    if(!Daplug_getDongleStatus(dpdCard, &s)){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }
    switch(s){
        case 0x0F:
            status = "PERSONALIZED";
            break;
        case 0x7F:
            status = "TERMINATED";
            break;
        case 0x83:
            status = "LOCKED";
            break;
    }

    fprintf(stderr,"\nstatus = %s\n",status);

    fprintf(stderr, "\n**********************************************************");
    fprintf(stderr, "\n********** \"testGetStatus\" terminated with success *******\n");
    fprintf(stderr, "**********************************************************\n");

    return 1;
}

int testPutkey(DaplugDongle *dpdCard){

    if(!Daplug_authenticate(dpdCard, keyset01,C_MAC+C_DEC+R_MAC+R_ENC,NULL,NULL)){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }

    fprintf(stderr,"\n+TEST: Creating a new keyset");
    if(!Daplug_putKey(dpdCard, newKeyset, 0)){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }
    fprintf(stderr,"\nDeleting the created keyset..\n");
    if(!Daplug_deleteKey(dpdCard, newKeyset.version)){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }

    fprintf(stderr, "\n**********************************************************");
    fprintf(stderr, "\n********** \"testPutkey\" terminated with success **********\n");
    fprintf(stderr, "**********************************************************\n");

    return 1;

}

int testPutkeyWithSAM(DaplugDongle *dpdCard, DaplugDongle *dpdSAM){

    //create SAM provisionnable keyset
    if(!Daplug_authenticate(dpdSAM, keyset01,C_MAC+C_DEC+R_MAC+R_ENC,NULL,NULL)){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }
    if(!Daplug_putKey(dpdSAM, SAMProvisionnableKeyset, 0)){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }

    //create SAM GP usable keyset with the same value of the provisionnable one ; it will be used later for authentication on the target new created keyset
    char enc[GP_KEY_SIZE*2+1]="", mac[GP_KEY_SIZE*2+1]="", dek[GP_KEY_SIZE*2+1]="";
    Keyset GPUsableKeyset;

    keyset_getKey(SAMProvisionnableKeyset, 0, enc);
    keyset_getKey(SAMProvisionnableKeyset, 1, mac);
    keyset_getKey(SAMProvisionnableKeyset, 2, dek);

    if(!keyset_createKeys(&GPUsableKeyset, 0x60, enc, mac, dek)){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }
    GPUsableKeyset.usage = USAGE_SAM_GP;
    int access[] = {ACCESS_ALWAYS, 0x00}; //access according to key role
    if(!keyset_setKeyAccess(&GPUsableKeyset,access)){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }

    if(!Daplug_putKey(dpdSAM, GPUsableKeyset, 0)){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }

    //Authenticate using SAM then create the new target key

    //New target keyset data (here we use a GP keyset)
    int newTargetKeysetVersion = 0x59,
        newTargetKeysetUsage = USAGE_GP,
        newTargetKeysetAccess = (ACCESS_ALWAYS << 8) + C_MAC;

    char chipDiversifier[16*2+1]="";
    if(!Daplug_getChipDiversifier(card, chipDiversifier)){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }

    if(!Daplug_authenticateUsingSAM(dpdCard, dpdSAM, SAMCtxKeyVersion, SAMCtxKeyId, SAMGPKeyVersion, TargetKeyVersion, C_MAC+C_DEC+R_MAC+R_ENC, chipDiversifier, NULL)){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }
    if(!Daplug_putKeyUsingSAM(dpdCard, newTargetKeysetVersion, newTargetKeysetAccess, newTargetKeysetUsage, SAMProvisionnableKeyset.version, chipDiversifier, NULL, 0)){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }

    //test authentication on the new created card keyset
    if(!Daplug_authenticateUsingSAM(dpdCard, dpdSAM, SAMCtxKeyVersion, SAMCtxKeyId, GPUsableKeyset.version, newTargetKeysetVersion, C_MAC, chipDiversifier, NULL)){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }

    //clean card
    if(!Daplug_authenticateUsingSAM(dpdCard, dpdSAM, SAMCtxKeyVersion, SAMCtxKeyId, SAMGPKeyVersion, TargetKeyVersion, C_MAC+C_DEC+R_MAC+R_ENC, chipDiversifier, NULL)){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }
    if(!Daplug_deleteKey(dpdCard, newTargetKeysetVersion)){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }

    //clean sam
    if(!Daplug_authenticate(dpdSAM, keyset01,C_MAC+C_DEC+R_MAC+R_ENC,NULL,NULL)){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }
    if(!Daplug_deleteKey(dpdSAM, SAMProvisionnableKeyset.version)){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }
    if(!Daplug_deleteKey(dpdSAM, GPUsableKeyset.version)){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }

    fprintf(stderr, "\n*****************************************************************");
    fprintf(stderr, "\n********** \"testPutkeyWithSAM\" terminated with success **********\n");
    fprintf(stderr, "*****************************************************************\n");

    return 1;

}

int testExportKey(DaplugDongle *dpdCard){

    if(!Daplug_authenticate(dpdCard, keyset01,C_MAC+C_DEC+R_MAC+R_ENC,NULL,NULL)){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }

    fprintf(stderr,"\n+TEST: Export Key");
    if(!Daplug_putKey(dpdCard, transientKeyset, 0)){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }
    char expk[APDU_D_MAXLEN*2+1]="";
    if(!Daplug_exportKey(dpdCard, 0xFD,1,expk)){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }
    fprintf(stderr,"\nexported key blob = %s\n",expk);

    fprintf(stderr, "\n*************************************************************");
    fprintf(stderr, "\n********** \"testExportKey\" terminated with success **********\n");
    fprintf(stderr, "*************************************************************\n");

    return 1;

}

int testImportKey(DaplugDongle *dpdCard){

    if(!Daplug_authenticate(dpdCard, keyset01,C_MAC+C_DEC+R_MAC+R_ENC,NULL,NULL)){

    }

    fprintf(stderr,"\n+TEST: Import Key");
    //blob previously exported
    char impk[APDU_D_MAXLEN*2+1]="fa4577fdb3753e1c1a0a7fcad91530e1cdd623a6a9f04fb9b2781c92c9eecbbb5c7dc2fa6e2a6fd56b24e13bdc8ae78a9da3203f95510591f3520877af65a7bf46792b169d8804fd9ec6990d3b38617e844c7357ee2c430f";
    if(!Daplug_importKey(dpdCard, 0xFD,0x01,impk)){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }
    fprintf(stderr,"\n");

    fprintf(stderr, "\n*************************************************************");
    fprintf(stderr, "\n********** \"testImportKey\" terminated with success **********\n");
    fprintf(stderr, "*************************************************************\n");

    return 1;

}

int testFileSystem(DaplugDongle *dpdCard){

    /*if(!Daplug_authenticate(dpdCard, keyset01,C_MAC+C_DEC+R_MAC+R_ENC,NULL,NULL)){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }

    fprintf(stderr,"\n+TEST: File System");
    int access[3]={ACCESS_ALWAYS,ACCESS_ALWAYS,ACCESS_ALWAYS};
    if(!Daplug_selectFile(dpdCard, FS_MASTER_FILE)){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }
    if(!Daplug_createDir(dpdCard, 0x0190,access)){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }
    if(!Daplug_selectPath(dpdCard, "3f000190")){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }
    if(!Daplug_createFile(dpdCard, 0x01f4,260,access,0,0)){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }
    if(!Daplug_selectFile(dpdCard, FS_MASTER_FILE)){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }*/
    if(!Daplug_selectPath(dpdCard, "3f00c00f")){ //019001f4
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }/*
    char w_data[264*2+1]="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01234567";
    if(!Daplug_writeData(dpdCard, 0x0000,w_data)){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }
    fprintf(stderr,"\nData to write = %s\n",w_data);
    char r_data[264*2+1]="";
    if(!Daplug_readData(dpdCard, 0x0000,264,r_data)){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }
    fprintf(stderr,"\nRead data = %s\n",r_data);
    if(!Daplug_selectFile(dpdCard, FS_MASTER_FILE)){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }
    if(!Daplug_deleteFileOrDir(dpdCard, 0x0190)){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }

    fprintf(stderr, "\n**************************************************************");
    fprintf(stderr, "\n********** \"testFileSystem\" terminated with success **********\n");
    fprintf(stderr, "**************************************************************\n");
    */
    return 1;

}


int testEncryptDecrypt(DaplugDongle *dpdCard){

    if(!Daplug_authenticate(dpdCard, keyset01,C_MAC+C_DEC+R_MAC+R_ENC,NULL,NULL)){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }

    fprintf(stderr,"\n+TEST: Encrypt / Decrypt");

    if(!Daplug_putKey(dpdCard, encDecKeyset, 0)){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }

    char in[MAX_REAL_DATA_SIZE*2+1]="0123456789abcdef0123456789abcdef", //must be a multiple of 8 bytes
         out[MAX_REAL_DATA_SIZE*2+1]="",
         *iv = NULL;

    int const /*use_ecb = ENC_ECB,*/ use_cbc = ENC_CBC,
        /*use_div1 = ENC_1_DIV,*/ use_div2 = ENC_2_DIV;

    int options = use_cbc + use_div2;

    fprintf(stderr,"\nClear data = %s",in);
    if(!Daplug_encrypt(dpdCard, encDecKeyset.version,1,options,iv,diversifier1,diversifier2,in,out)){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }
    fprintf(stderr,"\nEncrypted data = %s",out);
    strcpy(in,out);
    strcpy(out,"");
    if(!Daplug_decrypt(dpdCard, encDecKeyset.version,1,options,iv,diversifier1,diversifier2,in,out)){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }
    fprintf(stderr,"\nDecrypted data = %s\n",out);

    fprintf(stderr, "\n******************************************************************");
    fprintf(stderr, "\n********** \"testEncryptDecrypt\" terminated with success **********\n");
    fprintf(stderr, "******************************************************************\n");

    return 1;

}

int testGenerateRandom(DaplugDongle *dpdCard, int len){

    fprintf(stderr,"\n+TEST: GENERATE RANDOM");
    char rand[MAX_REAL_DATA_SIZE*2+1]="";
    if(!Daplug_getRandom(dpdCard, len,rand)){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }
    fprintf(stderr,"\nRandom value on %d bytes : %s",len,rand);

    fprintf(stderr, "\n******************************************************************");
    fprintf(stderr, "\n********** \"testGenerateRandom\" terminated with success **********\n");
    fprintf(stderr, "******************************************************************\n");

    return 1;
}

int testHmacSha1(DaplugDongle *dpdCard){

    if(!Daplug_authenticate(dpdCard, keyset01,C_MAC+C_DEC+R_MAC+R_ENC,NULL,NULL)){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }

    if(!Daplug_putKey(dpdCard, hmacSha1Keyset, 0)){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }

    fprintf(stderr,"\n+TEST: Hmac - sha1");

    int options,
        //use1div = OTP_1_DIV,
        use2div = OTP_2_DIV;

    options = use2div;
    char arbitraryData[MAX_REAL_DATA_SIZE*2+1]="01234587",//"012548deac475c5e478fde001111111144dddddddfea09999999999995",
         ret[MAX_REAL_DATA_SIZE*2+1]="";

    if(!Daplug_hmac(dpdCard, hmacSha1Keyset.version,options,diversifier1,diversifier2,arbitraryData,ret)){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }

    //Clean card
    if(!Daplug_deleteKey(dpdCard, hmacSha1Keyset.version)){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }

    fprintf(stderr,"\nArbitrary data : %s",arbitraryData);
    fprintf(stderr,"\nSignature on 20 bytes: %s\n",ret);

    fprintf(stderr, "\n************************************************************");
    fprintf(stderr, "\n********** \"testHmacSha1\" terminated with success **********\n");
    fprintf(stderr, "************************************************************\n");

    return 1;

}

int testHotp(DaplugDongle *dpdCard){

    if(!Daplug_authenticate(dpdCard, keyset01,C_MAC+C_DEC+R_MAC+R_ENC,NULL,NULL)){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }

    fprintf(stderr,"\n+TEST: Hotp");

    if(!Daplug_putKey(dpdCard, hotpKeyset, 0)){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }

    int options,
        //use1div = OTP_1_DIV,
        use2div = OTP_2_DIV,
        //useHotp6 = OTP_6_DIGIT,
        useHotp7 = OTP_7_DIGIT /*,
        useHotp8 = OTP_8_DIGIT*/;

    options = use2div+useHotp7;

    //create counter file if it is not the case
    int ac[3] = {ACCESS_ALWAYS,ACCESS_ALWAYS,ACCESS_ALWAYS};
    if(!Daplug_selectPath(dpdCard, "3f00c010")){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }
    if(!Daplug_createFile(dpdCard, counterFileId,8,ac,0,1)){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }

    char cntFileId_str[2*2+1]="c01d",
         ret[MAX_REAL_DATA_SIZE*2+1]="";

    if(!Daplug_hotp(dpdCard, hotpKeyset.version,options,diversifier1,diversifier2,cntFileId_str,ret)){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }

    //Clean card
    if(!Daplug_selectPath(dpdCard, "3f00c010")){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }
    if(!Daplug_deleteFileOrDir(dpdCard, counterFileId)){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }
    if(!Daplug_deleteKey(dpdCard, hotpKeyset.version)){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }

    fprintf(stderr,"\nHotp: %s\n",ret);

    fprintf(stderr, "\n********************************************************");
    fprintf(stderr, "\n********** \"testHotp\" terminated with success **********\n");
    fprintf(stderr, "********************************************************\n");

    return 1;
}

int testTotp(DaplugDongle *dpdCard){

    if(!Daplug_authenticate(dpdCard, keyset01,C_MAC+C_DEC+R_MAC+R_ENC,NULL,NULL)){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }

    fprintf(stderr,"\n+TEST: Totp");

    //create a time source key if it is not the case
    if(!Daplug_putKey(dpdCard, TimeSrcKeyset, 0)){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }
    if(!Daplug_putKey(dpdCard, totpKeyset, 0)){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }

    int options,
        //use1div = OTP_1_DIV,
        use2div = OTP_2_DIV,
        //useTotp6 = OTP_6_DIGIT,
        //useTotp7 = OTP_7_DIGIT,
        useTotp8 = OTP_8_DIGIT;

    options = use2div+useTotp8;

    int key_id = 0;
    char key[GP_KEY_SIZE*2+1]="";
    keyset_getKey(TimeSrcKeyset,key_id,key);

    char ret[MAX_REAL_DATA_SIZE*2+1]="";

    //keys id are 1,2,3 ; in our struct Keyset they are 0,1,2 (it is why we make key_id + 1
    //0x57 is a time src keyversion ; step & time are optional (0)
    if(!Daplug_setTimeOTP(dpdCard, TimeSrcKeyset.version,key_id+1,key,0,0)){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }
    //use it with Daplug_totp Keyset ; set time otp before
    if(!Daplug_totp(dpdCard, totpKeyset.version,options,diversifier1,diversifier2,"",ret)){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }

    //Clean card
    if(!Daplug_deleteKey(dpdCard, totpKeyset.version)){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }
    if(!Daplug_deleteKey(dpdCard, TimeSrcKeyset.version)){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }

    fprintf(stderr,"\nTotp: %s\n",ret);

    fprintf(stderr, "\n********************************************************");
    fprintf(stderr, "\n********** \"testTotp\" terminated with success **********\n");
    fprintf(stderr, "********************************************************\n");

    return 1;

}


int testKeyboard(DaplugDongle *dpdCard, char *url, int makeHotp, int hotpFormat, char* divForHotp){

    if(!Daplug_authenticate(dpdCard, keyset01,C_MAC+C_DEC+R_MAC+R_ENC,NULL,NULL)){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }

    fprintf(stderr,"\n+TEST : Keyboard");

    int ac[3]={ACCESS_ALWAYS,ACCESS_ALWAYS,ACCESS_ALWAYS};

    int options = hotpFormat; //Digits or modhex

    //Use diversifier?
    if(strlen(divForHotp)!=0){
        //Diversifier validity
        if(strlen(divForHotp)!=16*2 || !isHexInput(divForHotp)){
            fprintf(stderr,"\ntestKeyboard(): Wrong diversifier value !\n");
            fprintf(stderr, "\n***** An error occured during the test ! *****\n");
            return 0;
        }
        else{
            options = options + KB_HOTP_USE_DIV;
        }
    }

    //Make hotp
    if(makeHotp != FALSE){

        //if modhex format
        if(options & KB_HOTP_MODHEX){
            fprintf(stderr,"\nTry to create modhex mapping file...\n");
            //When using modhex output for hotp, try to create file "3f00/0001"
            if(!Daplug_selectPath(dpdCard, "3f00")){
                fprintf(stderr, "\n***** An error occured during the test ! *****\n");
                return 0;
            }
            if(!Daplug_createFile(dpdCard, modhexFileId,16,ac,0,0)){
                fprintf(stderr, "\n***** An error occured during the test ! *****\n");
                return 0;
            }
            if(!Daplug_selectFile(dpdCard, modhexFileId)){
                fprintf(stderr, "\n***** An error occured during the test ! *****\n");
                return 0;
            }
            //write Hid Code used  for mapping (refer to product specification for more details - section "keyboard file")
            if(!Daplug_writeData(dpdCard, 0,"06050708090a0b0c0d0e0f1115171819")){
                fprintf(stderr, "\n***** An error occured during the test ! *****\n");
                return 0;
            }
        }

        //try to create Hotp keyset
        fprintf(stderr,"\nTry to create Hotp keyset...\n");
        if(!Daplug_putKey(dpdCard, hotpKeyset, 0)){
            fprintf(stderr, "\n***** An error occured during the test ! *****\n");
            return 0;
        }
        //Try to create counter file
        fprintf(stderr,"\nTry to create counter file...\n");
        if(!Daplug_selectPath(dpdCard, "3f00c010")){
            fprintf(stderr, "\n***** An error occured during the test ! *****\n");
            return 0;
        }
        if(!Daplug_createFile(dpdCard, counterFileId,8,ac,0,1)){
            fprintf(stderr, "\n***** An error occured during the test ! *****\n");
            return 0;
        }
    }

    int fileSize = 500;
    fprintf(stderr,"\nTry to create keyboard file...\n");
    if(!Daplug_selectFile(dpdCard, FS_MASTER_FILE)){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }
    if(!Daplug_createFile(dpdCard, kbFileId,fileSize,ac,0,0)){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }
    if(!Daplug_selectFile(dpdCard, kbFileId)){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }

    fprintf(stderr,"\nSetting keyboard file content\n");
    Keyboard kb;
    keyboard_init(&kb);
    //Mode detection win/mac
    if(!keyboard_addOSProbe(&kb,-1,-1,-1)){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }
    //windows version
    if(!keyboard_addIfPC(&kb)){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }
    //send win+r without sending blank stuff before
    if(!keyboard_addOSProbeWinR(&kb,-1,0xF000,-1)){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }
    //wait a bit for command windows to appear
    if(!keyboard_addSleep(&kb,-1)){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }
    //Type in the link address
    if(!keyboard_addTextWindows(&kb,url)){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }
    //add hotp code
    if(makeHotp != FALSE){
        //add hotp code
        if(!keyboard_addHotpCode(&kb,options,0x08,hotpKeyset.version,counterFileId,divForHotp)){
            fprintf(stderr, "\n***** An error occured during the test ! *****\n");
            return 0;
        }
    }
    //add return
    if(!keyboard_addReturn(&kb)){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }
    //mac version
    if(!keyboard_addIfMac(&kb)){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }
    //Type cmd + space, then release key
    if(!keyboard_addKeyCodeRelease(&kb,"01082c")){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }
    //wait a bit for spotlight to appear
    if(!keyboard_addSleep(&kb,0x14000)){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }
    //Type "Safari<wait><return>"
    if(!keyboard_addTextMac(&kb,"Safari.app",0,-1)){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }
    if(!keyboard_addSleep(&kb,0x3c000)){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }
    if(!keyboard_addReturn(&kb)){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }
    if(!keyboard_addSleep(&kb,-1)){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }
    if(!keyboard_addSleep(&kb,-1)){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }
    //if azerty: erase and retry : backspace
    if(!keyboard_addKeyCodeRaw(&kb,"2A2A2A2A2A2A2A2A2A2A")){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }
    if(!keyboard_addTextMac(&kb,"Safari.app",1,-1)){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }
    if(!keyboard_addSleep(&kb,0x3c000)){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }
    if(!keyboard_addReturn(&kb)){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }
    //wait for Safari to appear (and possibly load the default page)
    if(!keyboard_addSleep(&kb,0x78000)){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }
    //select new tab cmd + T
    if(!keyboard_addKeyCodeRelease(&kb,"010817")){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }
    if(!keyboard_addSleep(&kb,0x78000)){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }
    //Get back the focus just in case with cmd+L
    if(!keyboard_addKeyCodeRelease(&kb,"01080f")){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }
    if(!keyboard_addSleep(&kb,0x3c000)){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }
    //Type the url (qwerty)
    if(!keyboard_addTextMac(&kb,url,0,-1)){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }
    //add hotp code
    if(makeHotp != FALSE){
        //add hotp code
        if(!keyboard_addHotpCode(&kb,options,0x08,hotpKeyset.version,counterFileId,divForHotp)){
            fprintf(stderr, "\n***** An error occured during the test ! *****\n");
            return 0;
        }
    }
    //add return
    if(!keyboard_addReturn(&kb)){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }
    //wait for the page to load
    if(!keyboard_addSleep(&kb,0x14000)){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }
    //cmd + w close tab with the opposite layout
    if(!keyboard_addKeyCodeRelease(&kb,"01081d")){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }
    //Then retry with the other keyset
    //selectnew tab cmd+T
    if(!keyboard_addKeyCodeRelease(&kb,"010817")){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }
    if(!keyboard_addSleep(&kb,0x78000)){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }
    //Get back the focus just in case with cmd+L
    if(!keyboard_addKeyCodeRelease(&kb,"01080f")){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }
    if(!keyboard_addSleep(&kb,0x3c000)){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }
    //Type the url (azerty)
    if(!keyboard_addTextMac(&kb,url,1,-1)){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }
    if(makeHotp != FALSE){
        //add hotp code
        if(!keyboard_addHotpCode(&kb,options,0x08,hotpKeyset.version,counterFileId,divForHotp)){
            fprintf(stderr, "\n***** An error occured during the test ! *****\n");
            return 0;
        }
    }
    //add return
    if(!keyboard_addReturn(&kb)){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }
    //wait for the page to load
    if(!keyboard_addSleep(&kb,0x14000)){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }
    //cmd + w close tab with the opposite layout
    if(!keyboard_addKeyCodeRelease(&kb,"01081a")){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }

    //ensure zeroized to avoid misinterpretaion
    if(!keyboard_zeroPad(&kb,fileSize)){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }

    if(!Daplug_writeData(dpdCard, 0,kb.content)){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }

    fprintf(stderr,"\nSetting current file as keyboard file\n");
    if(!Daplug_useAsKeyboard(dpdCard)){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }

    fprintf(stderr,"\nActivating keyboard boot\n");
    if(!Daplug_setKeyboardAtBoot(dpdCard, 1)){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }

    fprintf(stderr, "\n************************************************************");
    fprintf(stderr, "\n********** \"testKeyboard\" terminated with success **********\n");
    fprintf(stderr, "************************************************************\n");

    return 1;

}

int testDisableKeyboard(DaplugDongle *dpdCard){

    if(!Daplug_authenticate(dpdCard, keyset01,C_MAC+C_DEC+R_MAC+R_ENC,NULL,NULL)){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }

    fprintf(stderr,"\n+TEST : Disable keyboard");
    if(!Daplug_setKeyboardAtBoot(dpdCard, 0)){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }

    //cleanCard
    //try to remove counter file
    if(!Daplug_selectPath(dpdCard, "3f00c010")){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }
    if(!Daplug_deleteFileOrDir(dpdCard, counterFileId)){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }
    //try to remove keyboard file
    if(!Daplug_selectPath(dpdCard, "3f00")){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }
    if(!Daplug_deleteFileOrDir(dpdCard, kbFileId)){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }
    //try to remove modhex mapping file
    if(!Daplug_selectPath(dpdCard, "3f00")){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }
    if(!Daplug_deleteFileOrDir(dpdCard, modhexFileId)){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }
    //try to remove hotp keyset
    if(!Daplug_deleteKey(dpdCard, hotpKeyset.version)){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }

    fprintf(stderr, "\n*******************************************************************");
    fprintf(stderr, "\n********** \"testDisableKeyboard\" terminated with success **********\n");
    fprintf(stderr, "*******************************************************************\n");

    return 1;

}

int testCheckLicenses(DaplugDongle *dpdCard){

    if(!Daplug_authenticate(dpdCard, keyset01,C_MAC+C_DEC+R_MAC+R_ENC,NULL,NULL)){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }

    if(!Daplug_selectPath(dpdCard, "3f00c00fd00d")){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }
    if(!Daplug_selectFile(dpdCard, 0xa1ba)){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }
    char readData[2*2+1]="";
    char presentLicenses[255]="";
    if(!Daplug_readData(dpdCard, 0, 1,readData)){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }
    int rd = 0;
    sscanf(readData,"%04X", &rd);
    rd = (rd & 0xff00) >> 8;

    if(rd & 0x01) strcat(presentLicenses, " FILE ");
    if(rd & 0x02) strcat(presentLicenses, " KB ");
    if(rd & 0x04) strcat(presentLicenses, " URL ");
    if(rd & 0x08) strcat(presentLicenses, " CRYPTO ");
    if(rd & 0x10) strcat(presentLicenses, " SAM-COM ");
    if(rd & 0x20) strcat(presentLicenses, " SAM ");

    printf("\nActivated licenses on this card are: %s\n", presentLicenses);

    fprintf(stderr, "\n**************************************************************");
    fprintf(stderr, "\n********** \"testCheckLicenses\" terminated with success *******\n");
    fprintf(stderr, "**************************************************************\n");

    return 1;

}

int testDiversifyKeyUsingSAM(DaplugDongle *dpdCard, DaplugDongle *dpdSAM){

    //create SAM exportable keyset
    if(!Daplug_authenticate(dpdSAM, keyset01,C_MAC+C_DEC+R_MAC+R_ENC,NULL,NULL)){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }
    Keyset exportableKeyset;
    if(!keyset_createKeys(&exportableKeyset, 0x62,"0123456789abcdef0123456789abcdef",NULL,NULL)){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }
    exportableKeyset.usage = USAGE_SAM_CLEAR_EXPORT_DIV1;
    int access[] = {ACCESS_ALWAYS,0};
    if(!keyset_setKeyAccess(&exportableKeyset,access)){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }
    if(!Daplug_putKey(dpdSAM, exportableKeyset, 0)){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }

    //SAM authenticate
    //Chip serial as diversifier1
    char div1[16*2+1]="";
    if(!Daplug_getChipDiversifier(dpdCard, div1)){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }
    if(!Daplug_authenticateUsingSAM(dpdCard, dpdSAM, SAMCtxKeyVersion, SAMCtxKeyId, SAMGPKeyVersion, TargetKeyVersion, C_MAC, div1, NULL)){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }

    //Diversify
    Keyset newTargetKeyset; //a GP keyset for example
    keyset_setVersion(&newTargetKeyset, 0x63);
    newTargetKeyset.usage = USAGE_GP;
    int access2[] = {ACCESS_ALWAYS,C_MAC};
    if(!keyset_setKeyAccess(&newTargetKeyset,access2)){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }
    if(!Daplug_computeDiversifiedKeysUsingSAM(dpdCard, exportableKeyset.version, diversifier1, NULL, &newTargetKeyset)){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }

    //Putkey
    if(!Daplug_authenticate(dpdCard, keyset01,C_MAC+C_DEC+R_MAC+R_ENC,NULL,NULL)){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }
    if(!Daplug_putKey(dpdCard, newTargetKeyset, 0)){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }

    //Use it
    if(!Daplug_authenticate(dpdCard, newTargetKeyset, C_MAC, NULL, NULL)){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }

    //clean sam
    if(!Daplug_deleteKey(dpdSAM, exportableKeyset.version)){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }

    //clean card
    if(!Daplug_authenticate(dpdCard, keyset01,C_MAC+C_DEC+R_MAC+R_ENC,NULL,NULL)){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }
    if(!Daplug_deleteKey(dpdCard, newTargetKeyset.version)){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }

    fprintf(stderr, "\n*********************************************************************");
    fprintf(stderr, "\n********** \"testDiversifyKeyUsingSAM\" terminated with success *******\n");
    fprintf(stderr, "*********************************************************************\n");

    return 1;

}

int main()
{

    //=====================================================================================================

    //keyset 01 - GP Keyset (used for authentication)
    if(!keyset_createKeys(&keyset01, 0x01,"404142434445464748494a4b4c4d4e4f",NULL,NULL)){
        return 0;
    }

    //Keysets to create
    /*
    expected : a new keyset id & three gp keys.
    Possible "usage" to use are present in the "keyset.h" file..
    access value 1 =  time src key version if TOTP key, if other key, key version of a keyset wich protect the access to
    the new created keyset (0x01 to 0x0F), or 0x00 for always access.
    access value 2 = min security level if GP key ; key length if hmac-sha1/hotp/hotp-validation/totp/totp-validation key ;
    or decryption access if encrypt/decrypt key.
    For more details, refer to the product specification, section "put key".
    */

    //Any keyset
    if(!keyset_createKeys(&newKeyset, 0x77,"202122232425262728292a2b2c2d2e2f", "404142434445464748494a4b4c4d4e4f", "1000ad12345879652145aabbccd4efda")){
        return 0;
    }
    newKeyset.usage = USAGE_GP; //any usage (just for test)
    int access[] = {ACCESS_ALWAYS, C_MAC}; //access according to key role
    if(!keyset_setKeyAccess(&newKeyset,access)){
        return 0;
    }

    //Transient keyset
    /*
    A transient keyset (F0) is a virtual keyset located in RAM.. wich can be exported & imported.
    when exported, the keyset is encrypted with a transient export key (role 0x0F)..
    In our test we use the enc key (01) of the existing transient export key FD.
    */
    if(!keyset_createKeys(&transientKeyset, 0xF0,"0123456789abcdef0123456789abcdef", NULL, NULL)){
        return 0;
    }
    transientKeyset.usage = USAGE_GP; //any usage (just for test)
    int access2[] = {ACCESS_ALWAYS, C_MAC};
    if(!keyset_setKeyAccess(&transientKeyset,access2)){
        return 0;
    }

    //Encrypt-Decrypt keyset
    if(!keyset_createKeys(&encDecKeyset, 0x53,"0123456789abcdef0123456789abcdef",NULL,NULL)){
        return 0;
    }
    encDecKeyset.usage = USAGE_ENC_DEC;
    int access3[] = {ACCESS_ALWAYS,0};
    if(!keyset_setKeyAccess(&encDecKeyset,access3)){
        return 0;
    }

    //Hmac-sha1 keyset
    if(!keyset_createKeys(&hmacSha1Keyset, 0x54,"0123456789abcdef0123456789abcdef",NULL,NULL)){
        return 0;
    }
    hmacSha1Keyset.usage = USAGE_HMAC_SHA1;
    int access4[] = {ACCESS_ALWAYS, 48};
    if(!keyset_setKeyAccess(&hmacSha1Keyset,access4)){
        return 0;
    }

    //Hotp keyset
    if(!keyset_createKeys(&hotpKeyset, 0x55,"0123456789abcdef0123456789abcdef", NULL, NULL)){
        return 0;
    }
    hotpKeyset.usage = USAGE_HOTP;
    int access5[] = {ACCESS_ALWAYS, 48};
    if(!keyset_setKeyAccess(&hotpKeyset,access5)){
        return 0;
    }

    //Time source keyset
    if(!keyset_createKeys(&TimeSrcKeyset, 0x57,"01234567898888844444556789abcdef",NULL,NULL)){
        return 0;
    }
    TimeSrcKeyset.usage = USAGE_TOTP_TIME_SRC;
    int access7[] = {ACCESS_ALWAYS, 0x00};
    if(!keyset_setKeyAccess(&TimeSrcKeyset,access7)){
        return 0;
    }

    //Totp keyset
    if(!keyset_createKeys(&totpKeyset, 0x56,"0123456789abcdef0123456789abcdef",NULL,NULL)){
        return 0;
    }
    totpKeyset.usage = USAGE_TOTP;
    int access6[] = {TimeSrcKeyset.version,48};
    if(!keyset_setKeyAccess(&totpKeyset,access6)){
        return 0;
    }

    //SAM provisionnable keyset
    if(!keyset_createKeys(&SAMProvisionnableKeyset, 0x58,"202122232425262728292a2b2c2d2e2f", "404142434445464748494a4b4c4d4e4f", "1000ad12345879652145aabbccd4efda")){
        return 0;
    }
    SAMProvisionnableKeyset.usage = USAGE_SAM_DIV1;
    int access8[] = {ACCESS_ALWAYS, 0x00};
    if(!keyset_setKeyAccess(&SAMProvisionnableKeyset,access8)){
        return 0;
    }

    //============================================= Log ================================================

    //open log file for exchanged apdus
    flog_apdu = fopen("apdu_log.txt","w");

    //=================================== Enumerating then selecting dongle ============================

    /*
    If you want test SAM functions, we assume that you have a card and a sam connected;
    that the card is the first detected (id 0) and the SAM is the second detected (id 1)
    */

    char **donglesList = NULL;
    int nbDongles = Daplug_getDonglesList(&donglesList);

    if(nbDongles > 0){
        fprintf(stdout,"\n+Connected dongles:\n");
    }else{
        return 0;
    }

    int i;
    for(i=0;i<nbDongles;i++){
        fprintf(stderr, "\n%s", donglesList[i]);
    }

    fprintf(stderr, "\n\nget card on %s...", donglesList[0]);
    if((card = Daplug_getDongleById(0)) == NULL){
        fprintf(stderr, "\nNo card connected.\n");
    }else{
        fprintf(stderr, "\nOk.\n");
    }

    fprintf(stderr, "\nget SAM on %s...", donglesList[1]);
    if((sam = Daplug_getDongleById(1)) == NULL){
        fprintf(stderr, "\nNo SAM connected.\n");
    }else{
        fprintf(stderr, "\nOk.\n");
    }

    //===================================== Test mode switching =======================================

    //expected : mode - HID_DEVICE , WINUSB_DEVICE
    //Remove dongle then reinsert it after switching
    /*
    if(card) testModeSwitching(card, WINUSB_DEVICE);
    else return 0;
    //*/
    //===================================== Authentication =============================================
    /*
    expected : security level (1 = Command integrity (the default, mandatory), 2 = Command data encryption
                                 3 = Response integrity, 4 = Response data encryption
                                 5 = 1 & 2 & 3 , 6 = 1 & 2 & 4 , 7 = 1 & 3 & 4
                                 8 = 1 & 2 & 3 & 4 , All other values = Command integrity  */
    /*
    if(card) testAuthentication(card, 8);
    else return 0;
    //*/
    //Or using diversified keys
    /*
    if(card) testDivAuthentication(card, 8);
    else return 0;
    //*/
    //Or using a SAM
    /*
    if(card && sam) testAuthenticationWithSam(card, sam, 8); //Use community keysets 0x66 (SAM) => 0x42 (card)
    else return 0;
    //*/
    //====================================== Serial & status ============================================
    /*
    if(card) testGetSerial(card);
    else return 0;
    //*/
    /*
    if(card) testGetStatus(card);
    else return 0;
    //*/
    //========================================= New, export/import key ==================================
    /*
    if(card) testPutkey(card);
    else return 0;
    //*/
    /*
    if(sam && card) testPutkeyWithSAM(card, sam);
    else return 0;
    //*/
    /*
    To test transient keyset operation, create the transient keyset F0 with any role (USAGE_GP for example),
    Perform an export, remove the dongle & reinsert it then perform an import.
    Finally, use the imported keyset (GP authentication if USAGE_GP role)
    */
    /*
    if(card) testExportKey(card);
    else return 0;
    //*/
    /*
    if(card) testImportKey(card);
    else return 0;
    //*/
    //========================================= File system ==============================================
    /*
    if(card) testFileSystem(card);
    else return 0;
    //*/
    //======================================= Encryption & random ========================================
    /*
    if(card) testEncryptDecrypt(card);
    else return 0;
    //*/
    //expected: Random length
    /*
    if(card) testGenerateRandom(card, 239);
    else return 0;
    //*/
    //========================================== HMAC, HOTP, TOTP ========================================
    /*
    if(card )testHmacSha1(card);
    else return 0;
    //*/
    /*
    if(card) testHotp(card);
    else return 0;
    //*/
    /*
    if(card) testTotp(card);
    else return 0;
    //*/
    //====================================== Keyboard functions ===========================================

    //If <testKeyboard> terminates with some errors, try <testDisableKeyboard> first.
    /*
    if(card) testKeyboard(card, "http://www.plug-up.com/", TRUE, KB_HOTP_MODHEX, "");
    else return 0;
    //*/
    /*
    if(card) testDisableKeyboard(card);
    else return 0;
    //*/
    //====================================== Others =======================================================

    /*
    //Ckeck Lisences
    printf("\nSAM...\n");
    if(sam) testCheckLicenses(sam);
    printf("\nCard...\n");
    if(card) testCheckLicenses(card);
    //*/
    /*
    if(card && sam) testDiversifyKeyUsingSAM(card, sam);
    else return 0;
    //*/
    //======================================= END =========================================================

    if(card) Daplug_close(card);
    if(sam) Daplug_close(sam);


    if(donglesList) Daplug_exit(&donglesList);
    if(flog_apdu) fclose(flog_apdu);

    //=====================================================================================================

    return 1;


}
