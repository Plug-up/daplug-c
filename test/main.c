/**
 * \file main.c
 * \brief
 * \author S.BENAMAR s.benamar@plug-up.com
 * \
 * \version 1.0
 * \date 02/12/2013
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

extern FILE *flog_apdu;

DaplugDongle dpd;
Dongle_info dongles[CON_DNG_MAX_NB];
int dongles_nb = 0,
    counterFileId = 0xc01d,
    kbFileId = 0x0800,
    modhexFileId = 0x0001;
Keyset keyset01, newKeyset,
       transientKeyset, encDecKeyset,
       hmacSha1Keyset, hotpKeyset, totpKeyset,
       TimeSrcKeyset;
char *diversifier1 = "0123456789abcdeffedcba9876543210",
     *diversifier2 = "fedcba98765432100123456789abcdef";


int testDongleDetection(int id){

    int nb = 0;
    nb = Daplug_getDongleList(dongles);

    if(nb <= 0){
        fprintf(stderr,"\nNo valid dongle inserted !\n");
        return 0;
    }

    int i;
    fprintf(stderr,"\n+Connected dongles:\n");
    for(i=0;i<nb;i++){
        if(dongles[i].type == HID_DEVICE){
            fprintf(stderr,"HID ");
        }
        if(dongles[i].type == WINUSB_DEVICE){
            fprintf(stderr,"WINUSB ");
        }
        fprintf(stderr,"dongle - Id : %02d\n",i+1);

    }

    fprintf(stderr,"\n+Selecting dongle:");

    id--;

    if(id<0 || id>=nb){
        fprintf(stderr,"\n%02d is not a valid id dongle !\n",id+1);
        return 0;
    }

    Dongle_info *d = &dongles[id];

    if(!Daplug_getDongleById(d,&dpd)){
        return 0;
    }else{
        fprintf(stderr,"\nDongle N° %02d selected.\n",id+1);
    }

    return nb;

}

void testModeSwitching(int mode){

    if(mode == 0 ){
        fprintf(stderr,"\n+Switch to hid mode...");
        Daplug_winusbToHid(&dpd);
    }

    if(mode == 1){
        fprintf(stderr,"\n+Switch to winusb mode...");
        Daplug_hidToWinusb(&dpd);
    }

}

void testAuthentication(int level){

    fprintf(stderr,"\n+Authentication...");

    switch(level){
        case 1 :
            Daplug_authenticate(&dpd,keyset01,C_MAC,"","");
            break;
        case 2 :
            Daplug_authenticate(&dpd,keyset01,C_MAC+C_DEC,"","");
            break;
        case 3 :
            Daplug_authenticate(&dpd,keyset01,C_MAC+R_MAC,"","");
            break;
        case 4 :
            Daplug_authenticate(&dpd,keyset01,C_MAC+R_ENC,"","");
            break;
        case 5 :
            Daplug_authenticate(&dpd,keyset01,C_MAC+C_DEC+R_MAC,"","");
            break;
        case 6 :
            Daplug_authenticate(&dpd,keyset01,C_MAC+C_DEC+R_ENC,"","");
            break;
        case 7 :
            Daplug_authenticate(&dpd,keyset01,C_MAC+R_MAC+R_ENC,"","");
            break;
        case 8 :
            Daplug_authenticate(&dpd,keyset01,C_MAC+C_DEC+R_MAC+R_ENC,"","");
            break;
        default :
            Daplug_authenticate(&dpd,keyset01,C_MAC,"","");
    }

}

void testDivAuthentication(int level){

    fprintf(stderr,"\n+Authentication using diversified keys...");

    //Keyset 01 with diversified keys
    Keyset divk;
    divk.version = keyset01.version;
    Daplug_computeDiversifiedKeys(keyset01,&divk,diversifier1);

    switch(level){
        case 1 :
            Daplug_authenticate(&dpd,divk,C_MAC,"","");
            break;
        case 2 :
            Daplug_authenticate(&dpd,divk,C_MAC+C_DEC,diversifier1,"");
            break;
        case 3 :
            Daplug_authenticate(&dpd,divk,C_MAC+R_MAC,diversifier1,"");
            break;
        case 4 :
            Daplug_authenticate(&dpd,divk,C_MAC+R_ENC,diversifier1,"");
            break;
        case 5 :
            Daplug_authenticate(&dpd,divk,C_MAC+C_DEC+R_MAC,diversifier1,"");
            break;
        case 6 :
            Daplug_authenticate(&dpd,divk,C_MAC+C_DEC+R_ENC,diversifier1,"");
            break;
        case 7 :
            Daplug_authenticate(&dpd,divk,C_MAC+R_MAC+R_ENC,diversifier1,"");
            break;
        case 8 :
            Daplug_authenticate(&dpd,divk,C_MAC+C_DEC+R_MAC+R_ENC,diversifier1,"");
            break;
        default :
            Daplug_authenticate(&dpd,divk,C_MAC,diversifier1,"");
    }

}

void testGetSerial(){
    fprintf(stderr,"\n+TEST : GET SERIAL");
    char sn[0x12*2+1]="";
    if(Daplug_getDongleSerial(&dpd,sn)){
        fprintf(stderr,"\nSN = %s\n",sn);
    }
}

void testSetStatus(int status){
    fprintf(stderr,"\n+TEST : SET STATUS");
    Daplug_setDongleStatus(&dpd,status);
}

void testGetStatus(){

    int s = 0;
    char* status = "";
    fprintf(stderr,"\n+TEST : GET STATUS");
    Daplug_getDongleStatus(&dpd,&s);
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

void testDeleteKey(int version){

    Daplug_deleteKey(&dpd,version);

}

void testPutkey(){

    fprintf(stderr,"\n+TEST: Creating a new keyset");
    Daplug_putKey(&dpd,newKeyset);
    fprintf(stderr,"\nDeleting the created keyset..\n");
    testDeleteKey(newKeyset.version);

}

void testExportKey(){

    fprintf(stderr,"\n+TEST: Export Key");
    Daplug_putKey(&dpd,transientKeyset);
    char expk[APDU_D_MAXLEN*2+1]="";
    Daplug_exportKey(&dpd,0xFD,1,expk);
    fprintf(stderr,"\nexported key blob = %s\n",expk);

}

void testImportKey(){

    fprintf(stderr,"\n+TEST: Import Key");
    //blob previously exported
    char impk[APDU_D_MAXLEN*2+1]="dc62724584a503c74d5f9b3ad1d49cf552a58af25933bb94e6283f5b89951a7b3865c71bf08e76d5ad7ccb33a6683f4b06847fd6e07de3532c361d08980fa2169f1e890aa0171d19ae713ca896e811612c12a5729a137c42";
    Daplug_importKey(&dpd,0xFD,0x01,impk);
    fprintf(stderr,"\n");

}

void testFileSystem(){

    fprintf(stderr,"\n+TEST: File System");
    int access[3]={ACCESS_ALWAYS,ACCESS_ALWAYS,ACCESS_ALWAYS};
    Daplug_selectFile(&dpd,FS_MASTER_FILE);
    Daplug_createDir(&dpd,0x0190,access);
    Daplug_selectPath(&dpd,"3f000190");
    Daplug_createFile(&dpd,0x01f4,260,access,0,0);
    Daplug_selectFile(&dpd,FS_MASTER_FILE);
    Daplug_selectPath(&dpd,"019001f4");
    char w_data[264*2+1]="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01234567";
    Daplug_writeData(&dpd,0x0000,w_data);
    fprintf(stderr,"\nData to write = %s\n",w_data);
    char r_data[264*2+1]="";
    Daplug_readData(&dpd,0x0000,264,r_data);
    fprintf(stderr,"\nRead data = %s\n",r_data);
    Daplug_selectFile(&dpd,FS_MASTER_FILE);
    Daplug_deleteFileOrDir(&dpd,0x0190);

}


void testEncryptDecrypt(){

    fprintf(stderr,"\n+TEST: Encrypt / Decrypt");

    Daplug_putKey(&dpd,encDecKeyset);

    char in[MAX_REAL_DATA_SIZE*2+1]="0123456789abcdef0123456789abcdef", //must be a multiple of 8 bytes
         out[MAX_REAL_DATA_SIZE*2+1]="",
         iv[8*2+1]="";

    int const /*use_ecb = ENC_ECB,*/ use_cbc = ENC_CBC,
        /*use_div1 = ENC_1_DIV,*/ use_div2 = ENC_2_DIV;

    int options = use_cbc+use_div2;

    fprintf(stderr,"\nClear data = %s",in);
    Daplug_encrypt(&dpd,encDecKeyset.version,1,options,iv,diversifier1,diversifier2,in,out);
    fprintf(stderr,"\nEncrypted data = %s",out);
    strcpy(in,out);
    strcpy(out,"");
    Daplug_decrypt(&dpd,encDecKeyset.version,1,options,iv,diversifier1,diversifier2,in,out);
    fprintf(stderr,"\nDecrypted data = %s\n",out);

}

void testGenerateRandom(int len){

    fprintf(stderr,"\n+TEST: GENERATE RANDOM");
    char rand[MAX_REAL_DATA_SIZE*2+1]="";
    Daplug_getRandom(&dpd,len,rand);
    fprintf(stderr,"\nRandom value on %d bytes : %s",len,rand);
}

void testHmacSha1(){

    Daplug_putKey(&dpd,hmacSha1Keyset);

    fprintf(stderr,"\n+TEST: Hmac - sha1");

    int options,
        //use1div = OTP_1_DIV,
        use2div = OTP_2_DIV;

    options = use2div;
    char arbitraryData[MAX_REAL_DATA_SIZE*2+1]="012548deac475c5e478fde001111111144dddddddfea09999999999995",
         ret[MAX_REAL_DATA_SIZE*2+1]="";

    Daplug_hmac(&dpd,hmacSha1Keyset.version,options,diversifier1,diversifier2,arbitraryData,ret);

    //Clean card
    Daplug_deleteKey(&dpd,hmacSha1Keyset.version);

    fprintf(stderr,"\nArbitrary data : %s",arbitraryData);
    fprintf(stderr,"\nSignature on 20 bytes: %s\n",ret);


}

void testHotp(){

    fprintf(stderr,"\n+TEST: Hotp");

    Daplug_putKey(&dpd,hotpKeyset);

    int options,
        //use1div = OTP_1_DIV,
        use2div = OTP_2_DIV,
        //useHotp6 = OTP_6_DIGIT,
        useHotp7 = OTP_7_DIGIT /*,
        useHotp8 = OTP_8_DIGIT*/;

    options = use2div+useHotp7;

    //create counter file if it is not the case
    int ac[3] = {ACCESS_ALWAYS,ACCESS_ALWAYS,ACCESS_ALWAYS};
    Daplug_selectPath(&dpd,"3f00c010");
    Daplug_createFile(&dpd,counterFileId,8,ac,0,1);

    char cntFileId_str[2*2+1]="c01d",
         ret[MAX_REAL_DATA_SIZE*2+1]="";

    Daplug_hotp(&dpd,hotpKeyset.version,options,diversifier1,diversifier2,cntFileId_str,ret);

    //Clean card
    Daplug_selectPath(&dpd,"3f00c010");
    Daplug_deleteFileOrDir(&dpd,counterFileId);
    Daplug_deleteKey(&dpd,hotpKeyset.version);

    fprintf(stderr,"\nHotp: %s\n",ret);
}

void testTotp(){

    fprintf(stderr,"\n+TEST: Totp");

    Daplug_putKey(&dpd,TimeSrcKeyset);//create a time source key if it is not the case
    Daplug_putKey(&dpd,totpKeyset);

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
    Daplug_setTimeOTP(&dpd,TimeSrcKeyset.version,key_id+1,key,0,0);//0x57 is a time src keyversion ; step & time are optional (0)
    Daplug_totp(&dpd,totpKeyset.version,options,diversifier1,diversifier2,"",ret); //use it with Daplug_totp Keyset ; set time otp before

    //Clean card
    Daplug_deleteKey(&dpd,totpKeyset.version);
    Daplug_deleteKey(&dpd,TimeSrcKeyset.version);

    fprintf(stderr,"\nTotp: %s\n",ret);

}


void testKeyboard(char *url, int makeHotp, int hotpFormat, char* divForHotp){

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
            Daplug_selectPath(&dpd,"3f00");
            Daplug_createFile(&dpd,modhexFileId,16,ac,0,0);
            Daplug_selectFile(&dpd,modhexFileId);
            //write Hid Code used  for mapping (refer to product specification for more details - section "keyboard file")
            Daplug_writeData(&dpd,0,"06050708090a0b0c0d0e0f1115171819");
        }

        //try to create Hotp keyset
        fprintf(stderr,"\nTry to create Hotp keyset...\n");
        Daplug_putKey(&dpd,hotpKeyset);
        //Try to create counter file
        fprintf(stderr,"\nTry to create counter file...\n");
        Daplug_selectPath(&dpd,"3f00c010");
        Daplug_createFile(&dpd,counterFileId,8,ac,0,1);
    }

    int fileSize = 500;
    fprintf(stderr,"\nTry to create keyboard file...\n");
    Daplug_selectFile(&dpd,FS_MASTER_FILE);
    Daplug_createFile(&dpd,kbFileId,fileSize,ac,0,0);
    Daplug_selectFile(&dpd,kbFileId);

    fprintf(stderr,"\nSetting keyboard file content\n");
    Keyboard kb;
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

    Daplug_writeData(&dpd,0,kb.content);

    fprintf(stderr,"\nSetting current file as keyboard file\n");
    Daplug_useAsKeyboard(&dpd);

    fprintf(stderr,"\nActivating keyboard boot\n");
    Daplug_setKeyboardAtBoot(&dpd,1);

}

void testDisableKeyboard(){

    fprintf(stderr,"\n+TEST : Disable keyboard");
    Daplug_setKeyboardAtBoot(&dpd,0);

    //cleanCard
    //try to remove counter file
    Daplug_selectPath(&dpd, "3f00c010");
    Daplug_deleteFileOrDir(&dpd,counterFileId);
    //try to remove keyboard file
    Daplug_selectPath(&dpd, "3f00");
    Daplug_deleteFileOrDir(&dpd,kbFileId);
    //try to remove modhex mapping file
    Daplug_selectPath(&dpd, "3f00");
    Daplug_deleteFileOrDir(&dpd,modhexFileId);
    //try to remove hotp keyset
    Daplug_deleteKey(&dpd,hotpKeyset.version);

}

void terminate(){

    fprintf(stderr,"\n+Terminating...");

    Daplug_free(&dpd, dongles, dongles_nb);
    Daplug_exit();
}

int main()
{

    //=====================================================================================================

    //keyset 01 - GP Keyset (used for authentication)
    keyset_createKeys(&keyset01, 0x01,"404142434445464748494a4b4c4d4e4f","","");

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
    keyset_createKeys(&newKeyset, 0x77,"202122232425262728292a2b2c2d2e2f",
                           "404142434445464748494a4b4c4d4e4f",
                           "1000ad12345879652145aabbccd4efda");
    newKeyset.usage = USAGE_HOTP; //any usage (just for test)
    Byte access[2] = {ACCESS_ALWAYS,48}; //access according to key role
    keyset_setKeyAccess(&newKeyset,access);

    //Transient keyset
    /*
    A transient keyset (F0) is a virtual keyset located in RAM.. wich can be exported & imported.
    when exported, the keyset is encrypted with a transient export key (role 0x0F)..
    In our test we use the enc key (01) of the existing transient export key FD.
    */
    keyset_createKeys(&transientKeyset, 0xF0,"0123456789abcdef0123456789abcdef","","");
    transientKeyset.usage = USAGE_GP; //any usage (just for test)
    Byte access2[2] = {ACCESS_ALWAYS,C_MAC};
    keyset_setKeyAccess(&transientKeyset,access2);

    //Encrypt-Decrypt keyset
    keyset_createKeys(&encDecKeyset, 0x53,"0123456789abcdef0123456789abcdef","","");
    encDecKeyset.usage = USAGE_ENC_DEC;
    Byte access3[2] = {ACCESS_ALWAYS,0};
    keyset_setKeyAccess(&encDecKeyset,access3);

    //Hmac-sha1 keyset
    keyset_createKeys(&hmacSha1Keyset, 0x54,"0123456789abcdef0123456789abcdef","","");
    hmacSha1Keyset.usage = USAGE_HMAC_SHA1;
    Byte access4[2] = {ACCESS_ALWAYS,48};
    keyset_setKeyAccess(&hmacSha1Keyset,access4);

    //Hotp keyset
    keyset_createKeys(&hotpKeyset, 0x55,"0123456789abcdef0123456789abcdef","","");
    hotpKeyset.usage = USAGE_HOTP;
    Byte access5[2] = {ACCESS_ALWAYS,48};
    keyset_setKeyAccess(&hotpKeyset,access5);

    //Totp keyset
    keyset_createKeys(&totpKeyset, 0x56,"0123456789abcdef0123456789abcdef","","");
    totpKeyset.usage = USAGE_TOTP;
    Byte access6[2] = {0x57,48};
    keyset_setKeyAccess(&totpKeyset,access6);

    //Time source keyset
    keyset_createKeys(&TimeSrcKeyset, 0x57,"01234567898888844444556789abcdef","","");
    TimeSrcKeyset.usage = USAGE_TOTP_TIME_SRC;
    Byte access7[2] = {ACCESS_ALWAYS,0};
    keyset_setKeyAccess(&TimeSrcKeyset,access7);

    //============================================= Log ================================================

    //open log file for exchanged apdus
    flog_apdu = fopen("apdu_log.txt","w");

    //=================================== Enumerating then selecting dongle ============================

    //expected : dongle id (1 to number of connected dongles)
    dongles_nb = testDongleDetection(1);

    //expected : mode - HID_DEVICE , WINUSB_DEVICE
    //Remove dongle then reinsert it after switching
    //testModeSwitching(WINUSB_DEVICE);

    //===================================== Authentication =============================================
    /*
    expected : security level (1 = Command integrity (the default, mandatory), 2 = Command data encryption
                                 3 = Response integrity, 4 = Response data encryption
                                 5 = 1 & 2 & 3 , 6 = 1 & 2 & 4 , 7 = 1 & 3 & 4
                                 8 = 1 & 2 & 3 & 4 , All other values = Command integrity  */
    testAuthentication(8);

    //Or using diversified keys
    //testDivAuthentication(8);

    //====================================== Serial & status ============================================

    //testGetSerial();

    //testGetStatus();

    //========================================= New, export/import key ==================================

    //testPutkey();

    //expected : keyset version
    //testDeleteKey(0x77);

    /*
    To test transient keyset operation, create the transient keyset F0 with any role (USAGE_GP for example),
    Perform an export, remove the dongle & reinsert it then perform an import.
    Finally, use the imported keyset (GP authentication if USAGE_GP role)
    */
    //testExportKey();

    //testImportKey();

    //========================================= File system ==============================================

    //testFileSystem();

    //======================================= Encryption & random ========================================

    //testEncryptDecrypt();

    //expected: Random length
    //testGenerateRandom(20);

    //========================================== HMAC, HOTP, TOTP ========================================

    //testHmacSha1();

    //testHotp();

    //testTotp();

    //====================================== Keyboard functions ===========================================

    //testKeyboard("http://www.plug-up.com/", TRUE, KB_HOTP_MODHEX, "");

    //testDisableKeyboard();

    //=====================================================================================================

    terminate();

    fclose(flog_apdu);

    //=====================================================================================================

    return 0;


}

