pragma circom 2.0.0;

include "../circomlib-master/circuits/sha256/sha256.circom";
include "../circomlib-master/circuits/comparators.circom";
include "./incrementalQuinTree.circom";
include "./cbor.circom";

// TODO: only use <== not ==>

#define CLAIMS_SKIP_EXAMPLE 27 

/* CBOR types */
#define MAJOR_TYPE_INT 0
#define MAJOR_TYPE_NEGATIVE_INT 1
#define MAJOR_TYPE_BYTES 2
#define MAJOR_TYPE_STRING 3
#define MAJOR_TYPE_ARRAY 4
#define MAJOR_TYPE_MAP 5
#define MAJOR_TYPE_TAG 6
#define MAJOR_TYPE_CONTENT_FREE 7

#define CREDENTIAL_SUBJECT_PATH_LEN 2

#define TO_BE_SIGNED_BITS 2512

// usually is 5. TODO: allow for more?
#define MAX_CWT_MAP_LEN 5

/* assert through constraint and assert */
#define hardcore_assert(a, b) a === b; assert(a == b)

/* assign bytes to a signal in one go */
#define copyBytes(b, a) for(var z = 0; z<ToBeSignedBytes; z++) { a.bytes[z] <== b[z]; }


#define CREDENTIAL_SUBJECT_MAP_LEN 3

#define GIVEN_NAME_STR [103, 105, 118, 101, 110, 78, 97, 109, 101]
#define GIVEN_NAME_LEN 9

#define FAMILY_NAME_STR [102, 97, 109, 105, 108, 121, 78, 97, 109, 101]
#define FAMILY_NAME_LEN 10

#define DOB_STR [100, 111, 98]
#define DOB_LEN 3

#define STRING_MAX_LEN 10

#define NOT(in) (1 + in - 2*in)


template FindMapKey(ToBeSignedBytes, ConstBytes, ConstBytesLen) {
    signal input maplen;
    signal input bytes[ToBeSignedBytes];
    signal input pos;

    signal output needlepos;

    signal mapval_v[MAX_CWT_MAP_LEN];
    signal mapval_type[MAX_CWT_MAP_LEN];
    signal mapval_value[MAX_CWT_MAP_LEN];
    signal mapval_isNeedle[MAX_CWT_MAP_LEN];
    signal mapval_isAccepted[MAX_CWT_MAP_LEN];

    component mapval_readType[MAX_CWT_MAP_LEN];
    component mapval_decodeUint[MAX_CWT_MAP_LEN];
    component mapval_skipValue[MAX_CWT_MAP_LEN];
    component mapval_isString[MAX_CWT_MAP_LEN];
    component mapval_isNeedleString[MAX_CWT_MAP_LEN];
    component mapval_withinMaplen[MAX_CWT_MAP_LEN];

    signal pos_loop_1[MAX_CWT_MAP_LEN]; // TODO: better variable names?
    signal pos_loop_2[MAX_CWT_MAP_LEN];
    signal pos_loop_3[MAX_CWT_MAP_LEN];

    component calculateTotal_foundpos = CalculateTotal(MAX_CWT_MAP_LEN);

    pos_loop_1[0] <== pos;

    for (var k = 0; k < MAX_CWT_MAP_LEN; k++) { 

        // read type
        mapval_readType[k] = ReadType(ToBeSignedBytes);
        copyBytes(bytes, mapval_readType[k])
        mapval_readType[k].pos <== pos_loop_1[k];
        mapval_v[k] <== mapval_readType[k].v;
        mapval_type[k] <== mapval_readType[k].type;
        pos_loop_2[k] <== mapval_readType[k].nextpos;

        // decode uint
        mapval_decodeUint[k] = DecodeUint(ToBeSignedBytes);
        mapval_decodeUint[k].v <== mapval_v[k];
        copyBytes(bytes, mapval_decodeUint[k])
        mapval_decodeUint[k].pos <== pos_loop_2[k];
        pos_loop_3[k] <== mapval_decodeUint[k].nextpos;
        mapval_value[k] <== mapval_decodeUint[k].value;

        // is current value a string?
        mapval_isString[k] = IsEqual();
        mapval_isString[k].in[0] <== mapval_type[k];
        mapval_isString[k].in[1] <== MAJOR_TYPE_STRING;

        // skip value for next iteration
        mapval_skipValue[k] = SkipValue(ToBeSignedBytes);
        mapval_skipValue[k].pos <== pos_loop_3[k] + (mapval_value[k] * mapval_isString[k].out);
        copyBytes(bytes, mapval_skipValue[k])
        if (k != MAX_CWT_MAP_LEN - 1) {
            pos_loop_1[k + 1] <== mapval_skipValue[k].finalpos;
        }


        // is current value interpreted as a string is a "vc" string?
        mapval_isNeedleString[k] = StringEquals(ToBeSignedBytes, ConstBytes, ConstBytesLen);
        copyBytes(bytes, mapval_isNeedleString[k])
        mapval_isNeedleString[k].pos <== pos_loop_3[k]; // pos before skipping
        mapval_isNeedleString[k].len <== mapval_value[k];

        mapval_withinMaplen[k] = LessThan(8);
        mapval_withinMaplen[k].in[0] <== k;
        mapval_withinMaplen[k].in[1] <== maplen;

        // is current value a "vc" string?
        mapval_isNeedle[k] <== mapval_isString[k].out * mapval_isNeedleString[k].out;

        // should we select this vc pos candidate?
        mapval_isAccepted[k] <== mapval_isNeedle[k] * mapval_withinMaplen[k].out;

        // put a vc pos candidate into CalculateTotal to be able to get vc pos outside of the loop
        calculateTotal_foundpos.nums[k] <== mapval_isAccepted[k] * (pos_loop_3[k] + mapval_value[k]);
    }

    needlepos <== calculateTotal_foundpos.sum;
}

template ReadMapLength(ToBeSignedBytes) {
    // read type
    signal input pos;
    signal input bytes[ToBeSignedBytes];
    signal output len;
    signal output nextpos;

    signal v;
    signal type;
    
    component readType = ReadType(ToBeSignedBytes);
    copyBytes(bytes, readType)
    readType.pos <== pos; // 27 bytes initial skip for example MoH pass
    readType.v ==> v;
    readType.type ==> type;
    nextpos <== readType.nextpos;
    hardcore_assert(type, MAJOR_TYPE_MAP);

    // read map length
    signal x;
    component getX = GetX();
    getX.v <== v;
    getX.x ==> x;
    // TODO: should this be more generic and allow for x more than 23?
    assert(x <= 23); // only supporting maps with 23 or less entries

    len <== x;
}

template NZCP() {
    // TODO: dynamic
    var ToBeSignedBytes = TO_BE_SIGNED_BITS/8;

    signal input a[TO_BE_SIGNED_BITS];
    signal output c[256];
    signal output d;

    var k;

    // component sha256 = Sha256(TO_BE_SIGNED_BITS);

    // for (k=0; k<TO_BE_SIGNED_BITS; k++) {
    //     sha256.in[k] <== a[k];
    // }

    // for (k=0; k<256; k++) {
    //     c[k] <== sha256.out[k];
    // }


    // convert bits to bytes
    signal ToBeSigned[ToBeSignedBytes];
    for (k=0; k<ToBeSignedBytes; k++) {
        var lc1=0;

        var e2 = 1;
        for (var i = 7; i>=0; i--) {
            lc1 += a[k*8+i] * e2;
            e2 = e2 + e2;
        }

        lc1 ==> ToBeSigned[k];
    }

    /*
    component readMapLength = ReadMapLength(ToBeSignedBytes);
    copyBytes(ToBeSigned, readMapLength)
    readMapLength.pos <== CLAIMS_SKIP_EXAMPLE;

    // find "vc" key pos in the map
    signal vc_pos;
    component findVC = FindMapKey(ToBeSignedBytes, [118, 99], 2);
    copyBytes(ToBeSigned, findVC)
    findVC.pos <== readMapLength.nextpos;
    findVC.maplen <== readMapLength.len;
    vc_pos <== findVC.needlepos;
    log(vc_pos);
    */

    /*
    component readMapLength2 = ReadMapLength(ToBeSignedBytes);
    copyBytes(ToBeSigned, readMapLength2)
    readMapLength2.pos <== 76;

    signal credSubj_pos;
    component findCredSubj = FindMapKey(ToBeSignedBytes, [99, 114, 101, 100, 101, 110, 116, 105, 97, 108, 83, 117, 98, 106, 101, 99, 116], 17);
    copyBytes(ToBeSigned, findCredSubj)
    findCredSubj.pos <== readMapLength2.nextpos;
    findCredSubj.maplen <== readMapLength2.len;
    credSubj_pos <== findCredSubj.needlepos;
    log(credSubj_pos);
    */

    signal credSubj_pos;
    credSubj_pos <== 246;

    component readMapLength3 = ReadMapLength(ToBeSignedBytes);
    copyBytes(ToBeSigned, readMapLength3)
    readMapLength3.pos <== credSubj_pos;
    // log(readMapLength3.len);

    hardcore_assert(readMapLength3.len, CREDENTIAL_SUBJECT_MAP_LEN);


    var STRINGS_TO_CONCAT = 3;
    var CONCAT_MAX_LEN = STRINGS_TO_CONCAT*STRING_MAX_LEN;
    var CONCAT_SIZE_BITS = 5;


    signal mapval_pos[CREDENTIAL_SUBJECT_MAP_LEN];
    signal mapval_v[CREDENTIAL_SUBJECT_MAP_LEN];
    signal mapval_type[CREDENTIAL_SUBJECT_MAP_LEN];
    signal mapval_nextpos[CREDENTIAL_SUBJECT_MAP_LEN];
    signal mapval_x[CREDENTIAL_SUBJECT_MAP_LEN];
    signal mapval_stringValue[CREDENTIAL_SUBJECT_MAP_LEN][CONCAT_MAX_LEN];
    signal mapval_stringLen[CREDENTIAL_SUBJECT_MAP_LEN];

    component mapval_readType[CREDENTIAL_SUBJECT_MAP_LEN];// = ReadType(ToBeSignedBytes);
    component mapval_getX[CREDENTIAL_SUBJECT_MAP_LEN];// = ReadType(ToBeSignedBytes);

    component mapval_isGivenName[CREDENTIAL_SUBJECT_MAP_LEN];
    component mapval_isFamilyName[CREDENTIAL_SUBJECT_MAP_LEN];
    component mapval_isDOB[CREDENTIAL_SUBJECT_MAP_LEN];
    component mapval_decodeString[CREDENTIAL_SUBJECT_MAP_LEN];

    for(k = 0; k < CREDENTIAL_SUBJECT_MAP_LEN; k++) {

        // TODO: make this a template "ReadStringLength"
        mapval_readType[k] = ReadType(ToBeSignedBytes);
        copyBytes(ToBeSigned, mapval_readType[k])
        mapval_readType[k].pos <== k == 0 ? readMapLength3.nextpos : mapval_decodeString[k - 1].finalpos; // 27 bytes initial skip for example MoH pass
        mapval_readType[k].v ==> mapval_v[k];
        mapval_readType[k].type ==> mapval_type[k];
        // hardcore_assert(mapval_type[k], MAJOR_TYPE_MAP);

        // read map length
        mapval_getX[k] = GetX();
        mapval_getX[k].v <== mapval_v[k];
        mapval_getX[k].x ==> mapval_x[k];
        // TODO: should this be more generic and allow for string keys with length of more than 23? (but we DO now it won't be more than 9!)
        assert(mapval_x[k] <= 23); // only supporting strings with 23 or less entries


        

        mapval_isGivenName[k] = StringEquals(ToBeSignedBytes, GIVEN_NAME_STR, GIVEN_NAME_LEN);
        copyBytes(ToBeSigned, mapval_isGivenName[k])
        mapval_isGivenName[k].pos <== mapval_readType[k].nextpos; // pos before skipping
        mapval_isGivenName[k].len <== mapval_x[k];

        mapval_isFamilyName[k] = StringEquals(ToBeSignedBytes, FAMILY_NAME_STR, FAMILY_NAME_LEN);
        copyBytes(ToBeSigned, mapval_isFamilyName[k])
        mapval_isFamilyName[k].pos <== mapval_readType[k].nextpos; // pos before skipping
        mapval_isFamilyName[k].len <== mapval_x[k];

        mapval_isDOB[k] = StringEquals(ToBeSignedBytes, DOB_STR, DOB_LEN);
        copyBytes(ToBeSigned, mapval_isDOB[k])
        mapval_isDOB[k].pos <== mapval_readType[k].nextpos; // pos before skipping
        mapval_isDOB[k].len <== mapval_x[k];

        mapval_decodeString[k] = DecodeString(ToBeSignedBytes, STRING_MAX_LEN); // TODO: dynamic length? or sane default which can't crash
        copyBytes(ToBeSigned, mapval_decodeString[k])
        mapval_decodeString[k].pos <== mapval_readType[k].nextpos + mapval_x[k];
        for(var z = 0; z<STRING_MAX_LEN; z++) {  mapval_decodeString[k].outputbytes[z] ==> mapval_stringValue[k][z]; } // TODO: macro for this?
        for(var z = STRING_MAX_LEN; z < CONCAT_MAX_LEN; z++) { mapval_stringValue[k][z] <== 0; } // pad out the rest of the string with zeros to avoid invalid access
        mapval_stringLen[k] <== mapval_decodeString[k].len;

        log(mapval_isGivenName[k].out);
        log(mapval_isFamilyName[k].out);
        log(mapval_isDOB[k].out);

    }

    signal credSubj_concatString[CONCAT_MAX_LEN];

    component credSubj_isFirst[CONCAT_MAX_LEN];
    component credSubj_isUnderSecond[CONCAT_MAX_LEN];

    component credSubj_firstSelector[CONCAT_MAX_LEN];
    component credSubj_secondSelector[CONCAT_MAX_LEN];
    component credSubj_thirdSelector[CONCAT_MAX_LEN];

    signal credSubj_firstChar[CONCAT_MAX_LEN];
    signal credSubj_secondChar[CONCAT_MAX_LEN];
    signal credSubj_thirdChar[CONCAT_MAX_LEN];

    signal credSubj_notFirst[CONCAT_MAX_LEN];
    // signal credSubj_notUnderSecond[CONCAT_MAX_LEN];
    // signal credSubj_notUnderThird[CONCAT_MAX_LEN]; // not used

    signal credSubj_isSecond[CONCAT_MAX_LEN];
    signal credSubj_isThird[CONCAT_MAX_LEN];
    
    log(420);
    for(k = 0; k < CONCAT_MAX_LEN; k++) {
        credSubj_isFirst[k] = LessThan(CONCAT_SIZE_BITS);
        credSubj_isFirst[k].in[0] <== k;
        credSubj_isFirst[k].in[1] <== mapval_stringLen[0];

        credSubj_isUnderSecond[k] = LessThan(CONCAT_SIZE_BITS);
        credSubj_isUnderSecond[k].in[0] <== k;
        credSubj_isUnderSecond[k].in[1] <== mapval_stringLen[0] + mapval_stringLen[1];

        credSubj_firstSelector[k] = QuinSelector(CONCAT_MAX_LEN);
        for(var z = 0; z<CONCAT_MAX_LEN; z++) {  credSubj_firstSelector[k].in[z] <== mapval_stringValue[0][z]; } // TODO: macro for this?
        credSubj_firstSelector[k].index <== k;

        credSubj_secondSelector[k] = QuinSelector(CONCAT_MAX_LEN);
        for(var z = 0; z<CONCAT_MAX_LEN; z++) {  credSubj_secondSelector[k].in[z] <== mapval_stringValue[1][z]; } // TODO: macro for this?
        credSubj_secondSelector[k].index <== k - mapval_stringLen[0];

        credSubj_thirdSelector[k] = QuinSelector(CONCAT_MAX_LEN);
        for(var z = 0; z<CONCAT_MAX_LEN; z++) {  credSubj_thirdSelector[k].in[z] <== mapval_stringValue[2][z]; } // TODO: macro for this?
        credSubj_thirdSelector[k].index <== k - mapval_stringLen[0] - mapval_stringLen[1];
        
        credSubj_notFirst[k] <== NOT(credSubj_isFirst[k].out);
        credSubj_isSecond[k] <== credSubj_isUnderSecond[k].out * credSubj_notFirst[k];
        credSubj_isThird[k] <== NOT(credSubj_isUnderSecond[k].out);

        credSubj_firstChar[k] <== credSubj_isFirst[k].out * credSubj_firstSelector[k].out;
        credSubj_secondChar[k] <== credSubj_isSecond[k] * credSubj_secondSelector[k].out;
        credSubj_thirdChar[k] <== credSubj_isThird[k] * credSubj_thirdSelector[k].out;

        credSubj_concatString[k] <== credSubj_firstChar[k] + credSubj_secondChar[k] + credSubj_thirdChar[k];
        log(credSubj_concatString[k]);
        
    }

}

component main = NZCP();

