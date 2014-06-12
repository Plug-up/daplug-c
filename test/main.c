/**
 * \file main.c
 * \brief
 * \author S.BENAMAR s.benamar@plug-up.com
 * \
 * \version 1.0
 * \date 26/05/2014
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


void testModeSwitching(DaplugDongle *dpdCard, int mode){

    if(mode == 0 ){
        fprintf(stderr,"\n+Switch to hid mode...");
        Daplug_winusbToHid(dpdCard);
    }

    if(mode == 1){
        fprintf(stderr,"\n+Switch to winusb mode...");
        Daplug_hidToWinusb(dpdCard);
    }

}

void testAuthentication(DaplugDongle *dpdCard, int level){

    fprintf(stderr,"\n+Authentication...");

    switch(level){
        case 1 :
            Daplug_authenticate(dpdCard, keyset01,C_MAC,NULL,NULL);
            break;
        case 2 :
            Daplug_authenticate(dpdCard, keyset01,C_MAC+C_DEC,NULL,NULL);
            break;
        case 3 :
            Daplug_authenticate(dpdCard, keyset01,C_MAC+R_MAC,NULL,NULL);
            break;
        case 4 :
            Daplug_authenticate(dpdCard, keyset01,C_MAC+R_ENC,NULL,NULL);
            break;
        case 5 :
            Daplug_authenticate(dpdCard, keyset01,C_MAC+C_DEC+R_MAC,NULL,NULL);
            break;
        case 6 :
            Daplug_authenticate(dpdCard, keyset01,C_MAC+C_DEC+R_ENC,NULL,NULL);
            break;
        case 7 :
            Daplug_authenticate(dpdCard, keyset01,C_MAC+R_MAC+R_ENC,NULL,NULL);
            break;
        case 8 :
            Daplug_authenticate(dpdCard, keyset01,C_MAC+C_DEC+R_MAC+R_ENC,NULL,NULL);
            break;
        default :
            Daplug_authenticate(dpdCard, keyset01,C_MAC,NULL,NULL);
    }

}

void testDivAuthentication(DaplugDongle *dpdCard, int level){

    fprintf(stderr,"\n+Authentication using diversified keys...");

    //Keyset 01 with diversified keys
    Keyset divk;
    divk.version = keyset01.version;
    Daplug_computeDiversifiedKeys(dpdCard, keyset01,&divk,diversifier1);

    switch(level){
        case 1 :
            Daplug_authenticate(dpdCard, divk,C_MAC,NULL,NULL);
            break;
        case 2 :
            Daplug_authenticate(dpdCard, divk,C_MAC+C_DEC,diversifier1,NULL);
            break;
        case 3 :
            Daplug_authenticate(dpdCard, divk,C_MAC+R_MAC,diversifier1,NULL);
            break;
        case 4 :
            Daplug_authenticate(dpdCard, divk,C_MAC+R_ENC,diversifier1,NULL);
            break;
        case 5 :
            Daplug_authenticate(dpdCard, divk,C_MAC+C_DEC+R_MAC,diversifier1,NULL);
            break;
        case 6 :
            Daplug_authenticate(dpdCard, divk,C_MAC+C_DEC+R_ENC,diversifier1,NULL);
            break;
        case 7 :
            Daplug_authenticate(dpdCard, divk,C_MAC+R_MAC+R_ENC,diversifier1,NULL);
            break;
        case 8 :
            Daplug_authenticate(dpdCard, divk,C_MAC+C_DEC+R_MAC+R_ENC,diversifier1,NULL);
            break;
        default :
            Daplug_authenticate(dpdCard, divk,C_MAC,diversifier1,NULL);
    }

}

void testAuthenticationWithSam(DaplugDongle *dpdCard, DaplugDongle *dpdSAM, int level){

    //Chip serial as diversifier1
    char div1[16*2+1]="";
    if(!Daplug_getChipDiversifier(dpdCard, div1)){
        fprintf(stderr,"\ntestAuthenticationWithSam(): An error occured !\n");
        return;
    }

    switch(level){

        case 2 :
            Daplug_authenticateUsingSAM(dpdCard, dpdSAM, SAMCtxKeyVersion, SAMCtxKeyId, SAMGPKeyVersion, TargetKeyVersion, C_MAC+C_DEC, div1, NULL);
            break;
        case 3 :
            Daplug_authenticateUsingSAM(dpdCard, dpdSAM, SAMCtxKeyVersion, SAMCtxKeyId, SAMGPKeyVersion, TargetKeyVersion, C_MAC+R_MAC, div1, NULL);
            break;
        case 4 :
            Daplug_authenticateUsingSAM(dpdCard, dpdSAM, SAMCtxKeyVersion, SAMCtxKeyId, SAMGPKeyVersion, TargetKeyVersion, C_MAC+R_ENC, div1, NULL);
            break;
        case 5 :
            Daplug_authenticateUsingSAM(dpdCard, dpdSAM, SAMCtxKeyVersion, SAMCtxKeyId, SAMGPKeyVersion, TargetKeyVersion, C_MAC+C_DEC+R_MAC, div1, NULL);
            break;
        case 6 :
            Daplug_authenticateUsingSAM(dpdCard, dpdSAM, SAMCtxKeyVersion, SAMCtxKeyId, SAMGPKeyVersion, TargetKeyVersion, C_MAC+C_DEC+R_ENC, div1, NULL);
            break;
        case 7 :
            Daplug_authenticateUsingSAM(dpdCard, dpdSAM, SAMCtxKeyVersion, SAMCtxKeyId, SAMGPKeyVersion, TargetKeyVersion, C_MAC+R_MAC+R_ENC, div1, NULL);
            break;
        case 8 :
            Daplug_authenticateUsingSAM(dpdCard, dpdSAM, SAMCtxKeyVersion, SAMCtxKeyId, SAMGPKeyVersion, TargetKeyVersion, C_MAC+C_DEC+R_MAC+R_ENC, div1, NULL);
            break;
        default :
            Daplug_authenticateUsingSAM(dpdCard, dpdSAM, SAMCtxKeyVersion, SAMCtxKeyId, SAMGPKeyVersion, TargetKeyVersion, C_MAC, div1, NULL);
    }

}

void testGetSerial(DaplugDongle *dpdCard){
    fprintf(stderr,"\n+TEST : GET SERIAL");
    char sn[0x12*2+1]="";
    if(Daplug_getDongleSerial(dpdCard, sn)){
        fprintf(stderr,"\nSN = %s\n",sn);
    }
}

void testSetStatus(DaplugDongle *dpdCard, int status){
    fprintf(stderr,"\n+TEST : SET STATUS");
    Daplug_setDongleStatus(dpdCard, status);
}

void testGetStatus(DaplugDongle *dpdCard){

    int s = 0;
    char* status = "";
    fprintf(stderr,"\n+TEST : GET STATUS");
    Daplug_getDongleStatus(dpdCard, &s);
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
}

void testDeleteKey(DaplugDongle *dpdCard, int version){

    Daplug_authenticate(dpdCard, keyset01,C_MAC+C_DEC+R_MAC+R_ENC,NULL,NULL);
    Daplug_deleteKey(dpdCard, version);

}

void testPutkey(DaplugDongle *dpdCard){

    Daplug_authenticate(dpdCard, keyset01,C_MAC+C_DEC+R_MAC+R_ENC,NULL,NULL);

    fprintf(stderr,"\n+TEST: Creating a new keyset");
    Daplug_putKey(dpdCard, newKeyset, 0);
    fprintf(stderr,"\nDeleting the created keyset..\n");
    Daplug_deleteKey(dpdCard, newKeyset.version);

}

void testPutkeyWithSAM(DaplugDongle *dpdCard, DaplugDongle *dpdSAM){

    //create SAM provisionnable keyset
    Daplug_authenticate(dpdSAM, keyset01,C_MAC+C_DEC+R_MAC+R_ENC,NULL,NULL);
    Daplug_putKey(dpdSAM, SAMProvisionnableKeyset, 0);

    //create SAM GP usable keyset with the same value of the provisionnable one ; it will be used later for authentication on the target new created keyset
    char enc[GP_KEY_SIZE*2+1]="", mac[GP_KEY_SIZE*2+1]="", dek[GP_KEY_SIZE*2+1]="";
    Keyset GPUsableKeyset;

    keyset_getKey(SAMProvisionnableKeyset, 0, enc);
    keyset_getKey(SAMProvisionnableKeyset, 1, mac);
    keyset_getKey(SAMProvisionnableKeyset, 2, dek);

    if(!keyset_createKeys(&GPUsableKeyset, 0x60, enc, mac, dek)){
        return;
    }
    GPUsableKeyset.usage = USAGE_SAM_GP;
    int access[] = {ACCESS_ALWAYS, 0x00}; //access according to key role
    if(!keyset_setKeyAccess(&GPUsableKeyset,access)){
        return;
    }

    Daplug_putKey(dpdSAM, GPUsableKeyset, 0);

    //Authenticate using SAM then create the new target key

    //New target keyset data (here we use a GP keyset)
    int newTargetKeysetVersion = 0x59,
        newTargetKeysetUsage = USAGE_GP,
        newTargetKeysetAccess = (ACCESS_ALWAYS << 8) + C_MAC;

    char chipDiversifier[16*2+1]="";
    Daplug_getChipDiversifier(card, chipDiversifier);

    Daplug_authenticateUsingSAM(dpdCard, dpdSAM, SAMCtxKeyVersion, SAMCtxKeyId, SAMGPKeyVersion, TargetKeyVersion, C_MAC+C_DEC+R_MAC+R_ENC, chipDiversifier, NULL);
    Daplug_putKeyUsingSAM(dpdCard, newTargetKeysetVersion, newTargetKeysetAccess, newTargetKeysetUsage, SAMProvisionnableKeyset.version, chipDiversifier, NULL, 0);

    //test authentication on the new created card keyset
    Daplug_authenticateUsingSAM(dpdCard, dpdSAM, SAMCtxKeyVersion, SAMCtxKeyId, GPUsableKeyset.version, newTargetKeysetVersion, C_MAC, chipDiversifier, NULL);

    //clean card
    Daplug_authenticateUsingSAM(dpdCard, dpdSAM, SAMCtxKeyVersion, SAMCtxKeyId, SAMGPKeyVersion, TargetKeyVersion, C_MAC+C_DEC+R_MAC+R_ENC, chipDiversifier, NULL);
    Daplug_deleteKey(dpdCard, newTargetKeysetVersion);

    //clean sam
    Daplug_authenticate(dpdSAM, keyset01,C_MAC+C_DEC+R_MAC+R_ENC,NULL,NULL);
    Daplug_deleteKey(dpdSAM, SAMProvisionnableKeyset.version);
    Daplug_deleteKey(dpdSAM, GPUsableKeyset.version);

}

void testExportKey(DaplugDongle *dpdCard){

    Daplug_authenticate(dpdCard, keyset01,C_MAC+C_DEC+R_MAC+R_ENC,NULL,NULL);

    fprintf(stderr,"\n+TEST: Export Key");
    Daplug_putKey(dpdCard, transientKeyset, 0);
    char expk[APDU_D_MAXLEN*2+1]="";
    Daplug_exportKey(dpdCard, 0xFD,1,expk);
    fprintf(stderr,"\nexported key blob = %s\n",expk);

}

void testImportKey(DaplugDongle *dpdCard){

    Daplug_authenticate(dpdCard, keyset01,C_MAC+C_DEC+R_MAC+R_ENC,NULL,NULL);

    fprintf(stderr,"\n+TEST: Import Key");
    //blob previously exported
    char impk[APDU_D_MAXLEN*2+1]="6825b2609ea2617c85861f5cc7ef44f735035ff5b3e665a3fa32ac0f7bf00c223c70688f56c0912700b9315a0dcb37377f388558f9ec508099f354c4bee4702c38e7862e61049ae1ee0b2b07bf12bc1a5b01bf24423b55a9";
    Daplug_importKey(dpdCard, 0xFD,0x01,impk);
    fprintf(stderr,"\n");

}

void testFileSystem(DaplugDongle *dpdCard){

    Daplug_authenticate(dpdCard, keyset01,C_MAC+C_DEC+R_MAC+R_ENC,NULL,NULL);

    fprintf(stderr,"\n+TEST: File System");
    int access[3]={ACCESS_ALWAYS,ACCESS_ALWAYS,ACCESS_ALWAYS};
    Daplug_selectFile(dpdCard, FS_MASTER_FILE);
    Daplug_createDir(dpdCard, 0x0190,access);
    Daplug_selectPath(dpdCard, "3f000190");
    Daplug_createFile(dpdCard, 0x01f4,260,access,0,0);
    Daplug_selectFile(dpdCard, FS_MASTER_FILE);
    Daplug_selectPath(dpdCard, "019001f4");
    char w_data[264*2+1]="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01234567";
    Daplug_writeData(dpdCard, 0x0000,w_data);
    fprintf(stderr,"\nData to write = %s\n",w_data);
    char r_data[264*2+1]="";
    Daplug_readData(dpdCard, 0x0000,264,r_data);
    fprintf(stderr,"\nRead data = %s\n",r_data);
    Daplug_selectFile(dpdCard, FS_MASTER_FILE);
    Daplug_deleteFileOrDir(dpdCard, 0x0190);

}


void testEncryptDecrypt(DaplugDongle *dpdCard){

    Daplug_authenticate(dpdCard, keyset01,C_MAC+C_DEC+R_MAC+R_ENC,NULL,NULL);

    fprintf(stderr,"\n+TEST: Encrypt / Decrypt");

    Daplug_putKey(dpdCard, encDecKeyset, 0);

    char in[MAX_REAL_DATA_SIZE*2+1]="0123456789abcdef0123456789abcdef", //must be a multiple of 8 bytes
         out[MAX_REAL_DATA_SIZE*2+1]="",
         *iv = NULL;

    int const /*use_ecb = ENC_ECB,*/ use_cbc = ENC_CBC,
        /*use_div1 = ENC_1_DIV,*/ use_div2 = ENC_2_DIV;

    int options = use_cbc + use_div2;

    fprintf(stderr,"\nClear data = %s",in);
    Daplug_encrypt(dpdCard, encDecKeyset.version,1,options,iv,diversifier1,diversifier2,in,out);
    fprintf(stderr,"\nEncrypted data = %s",out);
    strcpy(in,out);
    strcpy(out,"");
    Daplug_decrypt(dpdCard, encDecKeyset.version,1,options,iv,diversifier1,diversifier2,in,out);
    fprintf(stderr,"\nDecrypted data = %s\n",out);

}

void testGenerateRandom(DaplugDongle *dpdCard, int len){

    fprintf(stderr,"\n+TEST: GENERATE RANDOM");
    char rand[MAX_REAL_DATA_SIZE*2+1]="";
    Daplug_getRandom(dpdCard, len,rand);
    fprintf(stderr,"\nRandom value on %d bytes : %s",len,rand);
}

void testHmacSha1(DaplugDongle *dpdCard){

    Daplug_authenticate(dpdCard, keyset01,C_MAC+C_DEC+R_MAC+R_ENC,NULL,NULL);

    Daplug_putKey(dpdCard, hmacSha1Keyset, 0);

    fprintf(stderr,"\n+TEST: Hmac - sha1");

    int options,
        //use1div = OTP_1_DIV,
        use2div = OTP_2_DIV;

    options = use2div;
    char arbitraryData[MAX_REAL_DATA_SIZE*2+1]="01234587",//"012548deac475c5e478fde001111111144dddddddfea09999999999995",
         ret[MAX_REAL_DATA_SIZE*2+1]="";

    Daplug_hmac(dpdCard, hmacSha1Keyset.version,options,diversifier1,diversifier2,arbitraryData,ret);

    //Clean card
    Daplug_deleteKey(dpdCard, hmacSha1Keyset.version);

    fprintf(stderr,"\nArbitrary data : %s",arbitraryData);
    fprintf(stderr,"\nSignature on 20 bytes: %s\n",ret);


}

void testHotp(DaplugDongle *dpdCard){

    Daplug_authenticate(dpdCard, keyset01,C_MAC+C_DEC+R_MAC+R_ENC,NULL,NULL);


    fprintf(stderr,"\n+TEST: Hotp");

    Daplug_putKey(dpdCard, hotpKeyset, 0);

    int options,
        //use1div = OTP_1_DIV,
        use2div = OTP_2_DIV,
        //useHotp6 = OTP_6_DIGIT,
        useHotp7 = OTP_7_DIGIT /*,
        useHotp8 = OTP_8_DIGIT*/;

    options = use2div+useHotp7;

    //create counter file if it is not the case
    int ac[3] = {ACCESS_ALWAYS,ACCESS_ALWAYS,ACCESS_ALWAYS};
    Daplug_selectPath(dpdCard, "3f00c010");
    Daplug_createFile(dpdCard, counterFileId,8,ac,0,1);

    char cntFileId_str[2*2+1]="c01d",
         ret[MAX_REAL_DATA_SIZE*2+1]="";

    Daplug_hotp(dpdCard, hotpKeyset.version,options,diversifier1,diversifier2,cntFileId_str,ret);

    //Clean card
    Daplug_selectPath(dpdCard, "3f00c010");
    Daplug_deleteFileOrDir(dpdCard, counterFileId);
    Daplug_deleteKey(dpdCard, hotpKeyset.version);

    fprintf(stderr,"\nHotp: %s\n",ret);
}

void testTotp(DaplugDongle *dpdCard){

    Daplug_authenticate(dpdCard, keyset01,C_MAC+C_DEC+R_MAC+R_ENC,NULL,NULL);

    fprintf(stderr,"\n+TEST: Totp");

    Daplug_putKey(dpdCard, TimeSrcKeyset, 0);//create a time source key if it is not the case
    Daplug_putKey(dpdCard, totpKeyset, 0);

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
    Daplug_setTimeOTP(dpdCard, TimeSrcKeyset.version,key_id+1,key,0,0);//0x57 is a time src keyversion ; step & time are optional (0)
    Daplug_totp(dpdCard, totpKeyset.version,options,diversifier1,diversifier2,"",ret); //use it with Daplug_totp Keyset ; set time otp before

    //Clean card
    Daplug_deleteKey(dpdCard, totpKeyset.version);
    Daplug_deleteKey(dpdCard, TimeSrcKeyset.version);

    fprintf(stderr,"\nTotp: %s\n",ret);

}


void testKeyboard(DaplugDongle *dpdCard, char *url, int makeHotp, int hotpFormat, char* divForHotp){

    Daplug_authenticate(dpdCard, keyset01,C_MAC+C_DEC+R_MAC+R_ENC,NULL,NULL);

    fprintf(stderr,"\n+TEST : Keyboard");

    int ac[3]={ACCESS_ALWAYS,ACCESS_ALWAYS,ACCESS_ALWAYS};

    int options = hotpFormat; //Digits or modhex

    //Use diversifier?
    if(strlen(divForHotp)!=0){
        //Diversifier validity
        if(strlen(divForHotp)!=16*2 || !isHexInput(divForHotp)){
            fprintf(stderr,"\ntestKeyboard(): Wrong diversifier value !\n");
            return;
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
            Daplug_selectPath(dpdCard, "3f00");
            Daplug_createFile(dpdCard, modhexFileId,16,ac,0,0);
            Daplug_selectFile(dpdCard, modhexFileId);
            //write Hid Code used  for mapping (refer to product specification for more details - section "keyboard file")
            Daplug_writeData(dpdCard, 0,"06050708090a0b0c0d0e0f1115171819");
        }

        //try to create Hotp keyset
        fprintf(stderr,"\nTry to create Hotp keyset...\n");
        Daplug_putKey(dpdCard, hotpKeyset, 0);
        //Try to create counter file
        fprintf(stderr,"\nTry to create counter file...\n");
        Daplug_selectPath(dpdCard, "3f00c010");
        Daplug_createFile(dpdCard, counterFileId,8,ac,0,1);
    }

    int fileSize = 500;
    fprintf(stderr,"\nTry to create keyboard file...\n");
    Daplug_selectFile(dpdCard, FS_MASTER_FILE);
    Daplug_createFile(dpdCard, kbFileId,fileSize,ac,0,0);
    Daplug_selectFile(dpdCard, kbFileId);

    fprintf(stderr,"\nSetting keyboard file content\n");
    Keyboard kb;
    keyboard_init(&kb);
    //Mode detection win/mac
    keyboard_addOSProbe(&kb,-1,-1,-1);
    //windows version
    keyboard_addIfPC(&kb);
    //send win+r without sending blank stuff before
    keyboard_addOSProbeWinR(&kb,-1,0xF000,-1);
    //wait a bit for command windows to appear
    keyboard_addSleep(&kb,-1);
    //Type in the link address
    keyboard_addTextWindows(&kb,url);
    //add hotp code
    if(makeHotp != FALSE){
        //add hotp code
        keyboard_addHotpCode(&kb,options,0x08,hotpKeyset.version,counterFileId,divForHotp);
    }
    //add return
    keyboard_addReturn(&kb);
    //mac version
    keyboard_addIfMac(&kb);
    //Type cmd + space, then release key
    keyboard_addKeyCodeRelease(&kb,"01082c");
    //wait a bit for spotlight to appear
    keyboard_addSleep(&kb,0x14000);
    //Type "Safari<wait><return>"
    keyboard_addTextMac(&kb,"Safari.app",0,-1);
    keyboard_addSleep(&kb,0x3c000);
    keyboard_addReturn(&kb);
    keyboard_addSleep(&kb,-1);
    keyboard_addSleep(&kb,-1);
    //if azerty: erase and retry
    keyboard_addKeyCodeRaw(&kb,"2A2A2A2A2A2A2A2A2A2A");//backspace
    keyboard_addTextMac(&kb,"Safari.app",1,-1);
    keyboard_addSleep(&kb,0x3c000);
    keyboard_addReturn(&kb);
    //wait for Safari to appear (and possibly load the default page)
    keyboard_addSleep(&kb,0x78000);
    //select new tab cmd + T
    keyboard_addKeyCodeRelease(&kb,"010817");
    keyboard_addSleep(&kb,0x78000);
    //Get back the focus just in case with cmd+L
    keyboard_addKeyCodeRelease(&kb,"01080f");
    keyboard_addSleep(&kb,0x3c000);
    //Type the url (qwerty)
    keyboard_addTextMac(&kb,url,0,-1);
    //add hotp code
    if(makeHotp != FALSE){
        //add hotp code
        keyboard_addHotpCode(&kb,options,0x08,hotpKeyset.version,counterFileId,divForHotp);
    }
    //add return
    keyboard_addReturn(&kb);
    //wait for the page to load
    keyboard_addSleep(&kb,0x14000);
    //cmd + w close tab with the opposite layout
    keyboard_addKeyCodeRelease(&kb,"01081d");
    //Then retry with the other keyset
    //selectnew tab cmd+T
    keyboard_addKeyCodeRelease(&kb,"010817");
    keyboard_addSleep(&kb,0x78000);
    //Get back the focus just in case with cmd+L
    keyboard_addKeyCodeRelease(&kb,"01080f");
    keyboard_addSleep(&kb,0x3c000);
    //Type the url (azerty)
    keyboard_addTextMac(&kb,url,1,-1);
    if(makeHotp != FALSE){
        //add hotp code
        keyboard_addHotpCode(&kb,options,0x08,hotpKeyset.version,counterFileId,divForHotp);
    }
    //add return
    keyboard_addReturn(&kb);
    //wait for the page to load
    keyboard_addSleep(&kb,0x14000);
    //cmd + w close tab with the opposite layout
    keyboard_addKeyCodeRelease(&kb,"01081a");

    //ensure zeroized to avoid misinterpretaion
    keyboard_zeroPad(&kb,fileSize);

    Daplug_writeData(dpdCard, 0,kb.content);

    fprintf(stderr,"\nSetting current file as keyboard file\n");
    Daplug_useAsKeyboard(dpdCard);

    fprintf(stderr,"\nActivating keyboard boot\n");
    Daplug_setKeyboardAtBoot(dpdCard, 1);

}

void testDisableKeyboard(DaplugDongle *dpdCard){

    Daplug_authenticate(dpdCard, keyset01,C_MAC+C_DEC+R_MAC+R_ENC,NULL,NULL);

    fprintf(stderr,"\n+TEST : Disable keyboard");
    Daplug_setKeyboardAtBoot(dpdCard, 0);

    //cleanCard
    //try to remove counter file
    Daplug_selectPath(dpdCard, "3f00c010");
    Daplug_deleteFileOrDir(dpdCard, counterFileId);
    //try to remove keyboard file
    Daplug_selectPath(dpdCard, "3f00");
    Daplug_deleteFileOrDir(dpdCard, kbFileId);
    //try to remove modhex mapping file
    Daplug_selectPath(dpdCard, "3f00");
    Daplug_deleteFileOrDir(dpdCard, modhexFileId);
    //try to remove hotp keyset
    Daplug_deleteKey(dpdCard, hotpKeyset.version);

}

void checkLicenses(DaplugDongle *dpdCard){

    Daplug_authenticate(dpdCard, keyset01,C_MAC+C_DEC+R_MAC+R_ENC,NULL,NULL);

    Daplug_selectPath(dpdCard, "3f00c00fd00d");
    Daplug_selectFile(dpdCard, 0xa1ba);
    char readData[2*2+1]="";
    char presentLicenses[255]="";
    if(!Daplug_readData(dpdCard, 0, 1,readData)){
        fprintf(stderr, "\ncheckLicenses() - Cannot read license file !\n");
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

    printf("\nActivated licenses are: %s\n", presentLicenses);

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
    If you want do tests only on card (without using SAM), just comment code corresponding to tests functions using SAM.
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
        return 0;
    }else{
        fprintf(stderr, "\nOk.\n");
    }

    //*
    fprintf(stderr, "\nget SAM on %s...", donglesList[1]);
    if((sam = Daplug_getDongleById(1)) == NULL){
        return 0;
    }else{
        fprintf(stderr, "\nOk.\n");
    }
    //*/

    //===================================== Test mode switching =======================================

    //expected : mode - HID_DEVICE , WINUSB_DEVICE
    //Remove dongle then reinsert it after switching
    //testModeSwitching(card, WINUSB_DEVICE);

    //===================================== Authentication =============================================
    /*
    expected : security level (1 = Command integrity (the default, mandatory), 2 = Command data encryption
                                 3 = Response integrity, 4 = Response data encryption
                                 5 = 1 & 2 & 3 , 6 = 1 & 2 & 4 , 7 = 1 & 3 & 4
                                 8 = 1 & 2 & 3 & 4 , All other values = Command integrity  */
    //testAuthentication(card, 8);

    //Or using diversified keys
    //testDivAuthentication(card, 8);

    //Or using a SAM
    //testAuthenticationWithSam(card, sam, 8); //Use community keysets 0x66 (SAM) => 0x42 (card)

    //====================================== Check present licenses on the card =========================

    /*
    printf("\nSAM...\n");
    checkLicenses(sam);
    printf("\nCard...\n");
    checkLicenses(card);
    //*/

    //====================================== Serial & status ============================================

    //testGetSerial(card);

    //testGetStatus(card);

    //========================================= New, export/import key ==================================

    //testPutkey(card);

    //testPutkeyWithSAM(card, sam);

    //expected : keyset version
    //testDeleteKey(card, newKeyset.version);

    /*
    To test transient keyset operation, create the transient keyset F0 with any role (USAGE_GP for example),
    Perform an export, remove the dongle & reinsert it then perform an import.
    Finally, use the imported keyset (GP authentication if USAGE_GP role)
    */
    //testExportKey(card);

    //testImportKey(card);

    //========================================= File system ==============================================

    //testFileSystem(card);

    //======================================= Encryption & random ========================================

    //testEncryptDecrypt(card);

    //expected: Random length
    //testGenerateRandom(card, 239);

    //========================================== HMAC, HOTP, TOTP ========================================

    //testHmacSha1(card);

    //testHotp(card);

    //testTotp(card);

    //====================================== Keyboard functions ===========================================

    //testKeyboard(card, "http://www.plug-up.com/", TRUE, KB_HOTP_MODHEX, "");

    //testDisableKeyboard(card);

    //======================================= END =========================================================

    if(card) Daplug_close(card);
    if(sam) Daplug_close(sam);


    if(donglesList) Daplug_exit(&donglesList);
    fclose(flog_apdu);

    //=====================================================================================================

    return 1;


}
