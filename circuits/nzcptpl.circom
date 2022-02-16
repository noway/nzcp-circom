pragma circom 2.0.0;

include "../sha256-var-circom-main/snark-jwt-verify/circomlib/circuits/comparators.circom";
include "../sha256-var-circom-main/circuits/sha256Var.circom";
include "./cbor.circom";

/* CBOR types */
#define MAJOR_TYPE_INT 0
#define MAJOR_TYPE_NEGATIVE_INT 1
#define MAJOR_TYPE_BYTES 2
#define MAJOR_TYPE_STRING 3
#define MAJOR_TYPE_ARRAY 4
#define MAJOR_TYPE_MAP 5
#define MAJOR_TYPE_TAG 6
#define MAJOR_TYPE_CONTENT_FREE 7

/* assert through constraint and assert */
#define hardcore_assert(a, b) a === b; assert(a == b)

/* assign bytes to a signal in one go */
#define copyBytes(b, a) for(var z = 0; z<ToBeSignedBytes; z++) { a.bytes[z] <== b[z]; }

#define NOT(in) (1 + in - 2*in)


template FindMapKey(ToBeSignedBytes, ConstBytes, ConstBytesLen) {
    // constants
    // usually is 5. TODO: allow for more?
    var MAX_CWT_MAP_LEN = 8;

    // i/o signals
    signal input maplen;
    signal input bytes[ToBeSignedBytes];
    signal input pos;

    signal output needlepos;

    // signals
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

    component calculateTotal_foundpos = NZCPCalculateTotal(MAX_CWT_MAP_LEN);

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
            pos_loop_1[k + 1] <== mapval_skipValue[k].nextpos;
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

        // put a vc pos candidate into NZCPCalculateTotal to be able to get vc pos outside of the loop
        calculateTotal_foundpos.nums[k] <== mapval_isAccepted[k] * (pos_loop_3[k] + mapval_value[k]);
    }

    needlepos <== calculateTotal_foundpos.sum;
}


template ReadCredSubj(ToBeSignedBytes, MaxBufferLen) {

    // constants
    var CREDENTIAL_SUBJECT_MAP_LEN = 3;
    var MaxStringLen = MaxBufferLen \ CREDENTIAL_SUBJECT_MAP_LEN;

    // strings
    var GIVEN_NAME_LEN = 9;
    var GIVEN_NAME_STR[GIVEN_NAME_LEN] = [103, 105, 118, 101, 110, 78, 97, 109, 101];
    var FAMILY_NAME_LEN = 10;
    var FAMILY_NAME_STR[FAMILY_NAME_LEN] = [102, 97, 109, 105, 108, 121, 78, 97, 109, 101];
    var DOB_LEN = 3;
    var DOB_STR[DOB_LEN] = [100, 111, 98];

    // TODO: pull out of template?

    // i/o signals
    signal input maplen;
    signal input bytes[ToBeSignedBytes];
    signal input pos;

    signal output givenName[MaxBufferLen];
    signal output givenNameLen;
    signal output familyName[MaxBufferLen];
    signal output familyNameLen;
    signal output dob[MaxBufferLen];
    signal output dobLen;



    // check that map length is exactly as per NZCP spec
    hardcore_assert(maplen, CREDENTIAL_SUBJECT_MAP_LEN);




    signal mapval_pos[CREDENTIAL_SUBJECT_MAP_LEN];
    signal mapval_v[CREDENTIAL_SUBJECT_MAP_LEN];
    signal mapval_type[CREDENTIAL_SUBJECT_MAP_LEN];
    signal mapval_nextpos[CREDENTIAL_SUBJECT_MAP_LEN];
    signal mapval_x[CREDENTIAL_SUBJECT_MAP_LEN];

    component mapval_readType[CREDENTIAL_SUBJECT_MAP_LEN];
    component mapval_getX[CREDENTIAL_SUBJECT_MAP_LEN];

    component mapval_isGivenName[CREDENTIAL_SUBJECT_MAP_LEN];
    component mapval_isFamilyName[CREDENTIAL_SUBJECT_MAP_LEN];
    component mapval_isDOB[CREDENTIAL_SUBJECT_MAP_LEN];
    component mapval_decodeString[CREDENTIAL_SUBJECT_MAP_LEN];

    for(var k = 0; k < CREDENTIAL_SUBJECT_MAP_LEN; k++) {

        // TODO: make this a template "ReadStringLength"
        mapval_readType[k] = ReadType(ToBeSignedBytes);
        copyBytes(bytes, mapval_readType[k])
        mapval_readType[k].pos <== k == 0 ? pos : mapval_decodeString[k - 1].nextpos; // 27 bytes initial skip for example MoH pass
        mapval_v[k] <== mapval_readType[k].v;
        mapval_type[k] <== mapval_readType[k].type;
        // hardcore_assert(mapval_type[k], MAJOR_TYPE_MAP);

        // read map length
        mapval_getX[k] = GetX();
        mapval_getX[k].v <== mapval_v[k];
        mapval_x[k] <== mapval_getX[k].x;
        // TODO: should this be more generic and allow for string keys with length of more than 23? (but we DO now it won't be more than 9!)
        assert(mapval_x[k] <= 23); // only supporting strings with 23 or less entries


        

        mapval_isGivenName[k] = StringEquals(ToBeSignedBytes, GIVEN_NAME_STR, GIVEN_NAME_LEN);
        copyBytes(bytes, mapval_isGivenName[k])
        mapval_isGivenName[k].pos <== mapval_readType[k].nextpos; // pos before skipping
        mapval_isGivenName[k].len <== mapval_x[k];

        mapval_isFamilyName[k] = StringEquals(ToBeSignedBytes, FAMILY_NAME_STR, FAMILY_NAME_LEN);
        copyBytes(bytes, mapval_isFamilyName[k])
        mapval_isFamilyName[k].pos <== mapval_readType[k].nextpos; // pos before skipping
        mapval_isFamilyName[k].len <== mapval_x[k];

        mapval_isDOB[k] = StringEquals(ToBeSignedBytes, DOB_STR, DOB_LEN);
        copyBytes(bytes, mapval_isDOB[k])
        mapval_isDOB[k].pos <== mapval_readType[k].nextpos; // pos before skipping
        mapval_isDOB[k].len <== mapval_x[k];

        mapval_decodeString[k] = DecodeString(ToBeSignedBytes, MaxStringLen); // TODO: dynamic length? or sane default which can't crash
        copyBytes(bytes, mapval_decodeString[k])
        mapval_decodeString[k].pos <== mapval_readType[k].nextpos + mapval_x[k];

    }


    // assign givenName
    component givenName_charsCalculateTotal[MaxStringLen];
    for(var h = 0; h<MaxStringLen; h++) {
        givenName_charsCalculateTotal[h] = NZCPCalculateTotal(CREDENTIAL_SUBJECT_MAP_LEN);
        for(var i = 0; i < CREDENTIAL_SUBJECT_MAP_LEN; i++) {
            givenName_charsCalculateTotal[h].nums[i] <== mapval_isGivenName[i].out * mapval_decodeString[i].outbytes[h];
        }
        givenName[h] <== givenName_charsCalculateTotal[h].sum;
    }
    for(var h = MaxStringLen; h < MaxBufferLen; h++) { givenName[h] <== 0; } // pad out the rest of the string with zeros to avoid invalid access
    component givenName_lenCalculateTotal;
    givenName_lenCalculateTotal = NZCPCalculateTotal(CREDENTIAL_SUBJECT_MAP_LEN);
    for(var i = 0; i < CREDENTIAL_SUBJECT_MAP_LEN; i++) {
        givenName_lenCalculateTotal.nums[i] <== mapval_isGivenName[i].out * mapval_decodeString[i].len;
    }
    givenNameLen <== givenName_lenCalculateTotal.sum;


    // assign familyName
    component familyName_charsCalculateTotal[MaxStringLen];
    for(var h = 0; h<MaxStringLen; h++) {
        familyName_charsCalculateTotal[h] = NZCPCalculateTotal(CREDENTIAL_SUBJECT_MAP_LEN);
        for(var i = 0; i < CREDENTIAL_SUBJECT_MAP_LEN; i++) {
            familyName_charsCalculateTotal[h].nums[i] <== mapval_isFamilyName[i].out * mapval_decodeString[i].outbytes[h];
        }
        familyName[h] <== familyName_charsCalculateTotal[h].sum;
    }
    for(var h = MaxStringLen; h < MaxBufferLen; h++) { familyName[h] <== 0; } // pad out the rest of the string with zeros to avoid invalid access
    component familyName_lenCalculateTotal;
    familyName_lenCalculateTotal = NZCPCalculateTotal(CREDENTIAL_SUBJECT_MAP_LEN);
    for(var i = 0; i < CREDENTIAL_SUBJECT_MAP_LEN; i++) {
        familyName_lenCalculateTotal.nums[i] <== mapval_isFamilyName[i].out * mapval_decodeString[i].len;
    }
    familyNameLen <== familyName_lenCalculateTotal.sum;


    // assign dob
    component dob_charsCalculateTotal[MaxStringLen];
    for(var h = 0; h<MaxStringLen; h++) {
        dob_charsCalculateTotal[h] = NZCPCalculateTotal(CREDENTIAL_SUBJECT_MAP_LEN);
        for(var i = 0; i < CREDENTIAL_SUBJECT_MAP_LEN; i++) {
            dob_charsCalculateTotal[h].nums[i] <== mapval_isDOB[i].out * mapval_decodeString[i].outbytes[h];
        }
        dob[h] <== dob_charsCalculateTotal[h].sum;
    }
    for(var h = MaxStringLen; h < MaxBufferLen; h++) { dob[h] <== 0; } // pad out the rest of the string with zeros to avoid invalid access
    component dob_lenCalculateTotal;
    dob_lenCalculateTotal = NZCPCalculateTotal(CREDENTIAL_SUBJECT_MAP_LEN);
    for(var i = 0; i < CREDENTIAL_SUBJECT_MAP_LEN; i++) {
        dob_lenCalculateTotal.nums[i] <== mapval_isDOB[i].out * mapval_decodeString[i].len;
    }
    dobLen <== dob_lenCalculateTotal.sum;

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
    v <== readType.v;
    type <== readType.type;
    nextpos <== readType.nextpos;
    hardcore_assert(type, MAJOR_TYPE_MAP);

    // read map length
    signal x;
    component getX = GetX();
    getX.v <== v;
    x <== getX.x;
    // TODO: should this be more generic and allow for x more than 23?
    assert(x <= 23); // only supporting maps with 23 or less entries

    len <== x;
}

// TODO: check that inputs are bytes
template NZCP() {
    // constants
    var CLAIMS_SKIP_EXAMPLE = 27;

    // TODO: dynamic
    var ToBeSignedBytes = 314;
    var ToBeSignedBits = ToBeSignedBytes * 8;

    signal input a[ToBeSignedBits];
    signal output c[256];
    signal output d;

    var k;


    // convert bits to bytes
    // TODO: use bits2num?
    signal ToBeSigned[ToBeSignedBytes];
    for (k=0; k<ToBeSignedBytes; k++) {
        var lc1=0;

        var e2 = 1;
        for (var i = 7; i>=0; i--) {
            lc1 += a[k*8+i] * e2;
            e2 = e2 + e2;
        }

        ToBeSigned[k] <== lc1;
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



    // read cred subj map length
    component readMapLength3 = ReadMapLength(ToBeSignedBytes);
    copyBytes(ToBeSigned, readMapLength3)
    readMapLength3.pos <== credSubj_pos;


    // read cred subj map
    var CONCAT_SIZE_BITS = 5; // TODO: make bigger?
    var MaxBufferLen = pow(2, CONCAT_SIZE_BITS);
    component readCredSubj = ReadCredSubj(ToBeSignedBytes, MaxBufferLen);
    copyBytes(ToBeSigned, readCredSubj)
    readCredSubj.pos <== readMapLength3.nextpos;
    readCredSubj.maplen <== readMapLength3.len;
    signal givenName[MaxBufferLen];
    signal givenNameLen;
    signal familyName[MaxBufferLen];
    signal familyNameLen;
    signal dob[MaxBufferLen];
    signal dobLen;
    givenNameLen <== readCredSubj.givenNameLen;
    familyNameLen <== readCredSubj.familyNameLen;
    dobLen <== readCredSubj.dobLen;
    for (var i = 0; i < MaxBufferLen; i++) { givenName[i] <== readCredSubj.givenName[i]; }
    for (var i = 0; i < MaxBufferLen; i++) { familyName[i] <== readCredSubj.familyName[i]; }
    for (var i = 0; i < MaxBufferLen; i++) { dob[i] <== readCredSubj.dob[i]; }


    // concat givenName, familyName, dob
    var COMMA_CHAR = 44;

    signal credSubj_concatString[MaxBufferLen];

    component credSubj_isGivenName[MaxBufferLen];
    component credSubj_isUnderSep1[MaxBufferLen];
    component credSubj_isUnderFamilyName[MaxBufferLen];
    component credSubj_isUnderSep2[MaxBufferLen];

    component credSubj_givenNameSelector[MaxBufferLen];
    component credSubj_familyNameSelector[MaxBufferLen];
    component credSubj_dobSelector[MaxBufferLen];

    signal credSubj_notGivenName[MaxBufferLen];
    signal credSubj_isSep1[MaxBufferLen];
    signal credSubj_isFamilyName[MaxBufferLen];
    signal credSubj_isSep2[MaxBufferLen];
    signal credSubj_isDOB[MaxBufferLen];

    signal credSubj_givenNameChar[MaxBufferLen];
    signal credSubj_sep1Char[MaxBufferLen];
    signal credSubj_familyNameChar[MaxBufferLen];
    signal credSubj_sep2Char[MaxBufferLen];
    signal credSubj_dobChar[MaxBufferLen];
    
    for(k = 0; k < MaxBufferLen; k++) {
        credSubj_isGivenName[k] = LessThan(CONCAT_SIZE_BITS);
        credSubj_isGivenName[k].in[0] <== k;
        credSubj_isGivenName[k].in[1] <== givenNameLen;

        credSubj_isUnderSep1[k] = LessThan(CONCAT_SIZE_BITS);
        credSubj_isUnderSep1[k].in[0] <== k;
        credSubj_isUnderSep1[k].in[1] <== givenNameLen + 1;

        credSubj_isUnderFamilyName[k] = LessThan(CONCAT_SIZE_BITS);
        credSubj_isUnderFamilyName[k].in[0] <== k;
        credSubj_isUnderFamilyName[k].in[1] <== givenNameLen + 1 + familyNameLen;

        credSubj_isUnderSep2[k] = LessThan(CONCAT_SIZE_BITS);
        credSubj_isUnderSep2[k].in[0] <== k;
        credSubj_isUnderSep2[k].in[1] <== givenNameLen + 1 + familyNameLen + 1;

        credSubj_givenNameSelector[k] = QuinSelector(MaxBufferLen);
        for(var z = 0; z<MaxBufferLen; z++) {  credSubj_givenNameSelector[k].in[z] <== givenName[z]; } // TODO: macro for this?
        credSubj_givenNameSelector[k].index <== k;

        credSubj_familyNameSelector[k] = QuinSelector(MaxBufferLen);
        for(var z = 0; z<MaxBufferLen; z++) {  credSubj_familyNameSelector[k].in[z] <== familyName[z]; } // TODO: macro for this?
        credSubj_familyNameSelector[k].index <== k - givenNameLen - 1;

        credSubj_dobSelector[k] = QuinSelector(MaxBufferLen);
        for(var z = 0; z<MaxBufferLen; z++) {  credSubj_dobSelector[k].in[z] <== dob[z]; } // TODO: macro for this?
        credSubj_dobSelector[k].index <== k - givenNameLen - 1 - familyNameLen - 1;
        
        credSubj_notGivenName[k] <== NOT(credSubj_isGivenName[k].out);
        credSubj_isSep1[k] <== credSubj_isUnderSep1[k].out * credSubj_notGivenName[k];
        credSubj_isFamilyName[k] <== credSubj_isUnderFamilyName[k].out * NOT(credSubj_isUnderSep1[k].out);
        credSubj_isSep2[k] <== credSubj_isUnderSep2[k].out * NOT(credSubj_isUnderFamilyName[k].out);
        credSubj_isDOB[k] <== NOT(credSubj_isUnderSep2[k].out);

        credSubj_givenNameChar[k] <== credSubj_isGivenName[k].out * credSubj_givenNameSelector[k].out;
        credSubj_sep1Char[k] <== credSubj_isSep1[k] * COMMA_CHAR;
        credSubj_familyNameChar[k] <== credSubj_isFamilyName[k] * credSubj_familyNameSelector[k].out;
        credSubj_sep2Char[k] <== credSubj_isSep2[k] * COMMA_CHAR;
        credSubj_dobChar[k] <== credSubj_isDOB[k] * credSubj_dobSelector[k].out;

        credSubj_concatString[k] <== credSubj_givenNameChar[k] + credSubj_sep1Char[k] + credSubj_familyNameChar[k] + credSubj_sep2Char[k] + credSubj_dobChar[k];
        
    }


    // convert concat string into bits
    var CONCAT_MAX_LEN_BITS = MaxBufferLen * 8;
    component n2b[MaxBufferLen];
    signal bits[CONCAT_MAX_LEN_BITS];
    for(k = 0; k < MaxBufferLen; k++) {
        n2b[k] = Num2Bits(8);
        n2b[k].in <== credSubj_concatString[k];
        for (var j = 0; j < 8; j++) {
            bits[k*8 + (7 - j)] <== n2b[k].out[j];
        }
    }

    // calculate sha256 of the concat string
    signal concatLen;
    concatLen <== givenNameLen + 1 + familyNameLen + 1 + dobLen;

    var BlockSpace = 1;
    var BLOCK_SIZE = 512;
    var BlockCount = pow(2, BlockSpace);
    var MaxBits = BLOCK_SIZE * BlockCount;
    component sha256 = Sha256Var(BlockSpace);
    sha256.len <== concatLen * 8;
    for (k=0; k<CONCAT_MAX_LEN_BITS; k++) {
        sha256.in[k] <== bits[k];
    }
    for (k = CONCAT_MAX_LEN_BITS; k < MaxBits; k++) {
        sha256.in[k] <== 0;
    }

    // export the sha256 hash
    for (k=0; k<256; k++) {
        c[k] <== sha256.out[k];
    }

}

component main = NZCP();

