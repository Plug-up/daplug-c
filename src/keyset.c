/**
 * \file keyset.c
 * \brief
 * \author S.BENAMAR s.benamar@plug-up.com
 * \version 1.2
 * \date 09/06/2014
 *
 * Helps to manipulate keysets.
 *
 */

#include <daplug/keyset.h>

int DAPLUGCALL keyset_createKeys(Keyset *keys, int version, const char* encKey,const char* macKey,const char* dekKey){

    if(version < 0 || version > 0xFF){
        fprintf(stderr, "\nkeyset_setVersion() - Invalid key version : %d\n", version);
        return 0;
    }

    keys->version = version;

    if(strlen(encKey) != 16*2 || !isHexInput(encKey)){
        fprintf(stderr,"\nkeyset_createKeys() - Invalid key value : \"%s\"\n", encKey);
        return 0;
    }
    else if(macKey != NULL && (strlen(macKey) != 16*2 || !isHexInput(macKey))){
        fprintf(stderr,"\nkeyset_createKeys() - Invalid key value : \"%s\"\n", macKey);
        return 0;
    }
    else if(dekKey != NULL && (strlen(dekKey) != 16*2 || !isHexInput(dekKey))){
        fprintf(stderr,"\nkeyset_createKeys() - Invalid key value : \"%s\"\n", dekKey);
        return 0;
    }

    strToBytes(encKey,keys->key[0]);

    if(macKey != NULL)
        strToBytes(macKey,keys->key[1]);
    else
        strToBytes(encKey,keys->key[1]);

    if(dekKey != NULL)
        strToBytes(dekKey,keys->key[2]);
    else
        strToBytes(encKey,keys->key[2]);

    keys->access[0] = 0;
    keys->access[1] = 0;
    keys->usage = 0;

    return 1;
}

int DAPLUGCALL keyset_setVersion(Keyset *keys, int version){

    if(version < 0 || version > 0xFF){
        fprintf(stderr, "\nkeyset_setVersion() - Invalid key version : %d\n", version);
        return 0;
    }

    keys->version = version;

    return 1;
}

void DAPLUGCALL keyset_getVersion(Keyset keys, int *version){
    *version = keys.version;
}

int DAPLUGCALL keyset_setKey(Keyset *keys,int id, char *key_value){

    if(strlen(key_value) != 16*2 || !isHexInput(key_value)){
        fprintf(stderr,"\nkeyset_setKey() - Invalid key value : \"%s\"\n", key_value);
        return 0;
    }

    strToBytes(key_value,keys->key[id]);

    return 1;

}

void DAPLUGCALL keyset_getKey(Keyset keys,int id, char *key_value){

    bytesToStr(keys.key[id],GP_KEY_SIZE, key_value);

}

void DAPLUGCALL keyset_getKeyUsage(Keyset keys, int *ku){

    *ku = keys.usage;
}

int DAPLUGCALL keyset_setKeyAccess(Keyset *keys, int access[]){

    int i;
    for(i=0; i<2; i++){

        if(access[i] < 0 || access[i] > 0xFF){
            fprintf(stderr,"\nkeyset_setKeyAccess() - Invalid access value : %d\n", access[i]);
            return 0;
        }

        keys->access[i] = access[i];

    }

    return 1;
}

void DAPLUGCALL keyset_getKeyAccess(Keyset keys, int access[]){

    int i;
    for(i=0; i<2; i++){
        access[i] = keys.access[i];
    }
}
