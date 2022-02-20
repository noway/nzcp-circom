pragma circom 2.0.0;

include "../sha256-var-circom-main/snark-jwt-verify/circomlib/circuits/gates.circom";
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

/* check through constraint and assert */
#define hardcore_assert(a, b) a === b; assert(a == b)

/* assign bytes to a signal in one go */
#define copyBytes(b, a, c) for(var z = 0; z < c; z++) { a[z] <== b[z]; }

/* from https://github.com/iden3/circomlib/blob/master/circuits/gates.circom#L45 */
#define NOT(in) (1 + in - 2*in)



template FindVCAndExp(BytesLen, MaxCborArrayLen, MaxCborMapLen) {
    // constants
    var ConstBytesLen = 2;
    var ConstBytes[ConstBytesLen] = [118, 99];

    // i/o signals
    signal input maplen;
    signal input bytes[BytesLen];
    signal input pos;

    signal output needlepos;
    signal output expPos;

    // signals
    signal mapval_v[MaxCborMapLen];
    signal mapval_type[MaxCborMapLen];
    signal mapval_value[MaxCborMapLen];
    signal mapval_isNeedle[MaxCborMapLen];
    signal mapval_isExp[MaxCborMapLen];
    signal mapval_isAccepted[MaxCborMapLen];
    signal mapval_isExpAccepted[MaxCborMapLen];

    component mapval_readType[MaxCborMapLen];
    component mapval_decodeUint[MaxCborMapLen];
    component mapval_decodeUintValue[MaxCborMapLen];
    component mapval_skipValue[MaxCborMapLen];
    component mapval_isString[MaxCborMapLen];
    component mapval_isInt[MaxCborMapLen];
    component mapval_isNeedleString[MaxCborMapLen];
    component mapval_is4Int[MaxCborMapLen];
    component mapval_withinMaplen[MaxCborMapLen];

    component calculateTotal_foundpos = NZCPCalculateTotal(MaxCborMapLen);
    component calculateTotal_exppos = NZCPCalculateTotal(MaxCborMapLen);

    for (var k = 0; k < MaxCborMapLen; k++) { 

        // read type
        mapval_readType[k] = ReadType(BytesLen);
        copyBytes(bytes, mapval_readType[k].bytes, BytesLen)
        mapval_readType[k].pos <== k == 0 ? pos : mapval_skipValue[k - 1].nextPos;
        mapval_v[k] <== mapval_readType[k].v;
        mapval_type[k] <== mapval_readType[k].type;

        // decode uint
        mapval_decodeUint[k] = DecodeUint(BytesLen);
        mapval_decodeUint[k].v <== mapval_v[k];
        copyBytes(bytes, mapval_decodeUint[k].bytes, BytesLen)
        mapval_decodeUint[k].pos <== mapval_readType[k].nextPos;
        mapval_value[k] <== mapval_decodeUint[k].value;

        // is current value a string?
        mapval_isString[k] = IsEqual();
        mapval_isString[k].in[0] <== mapval_type[k];
        mapval_isString[k].in[1] <== MAJOR_TYPE_STRING;

        // is current value an integer?
        mapval_isInt[k] = IsEqual();
        mapval_isInt[k].in[0] <== mapval_type[k];
        mapval_isInt[k].in[1] <== MAJOR_TYPE_INT;

        // skip value for next iteration
        mapval_skipValue[k] = SkipValue(BytesLen, MaxCborArrayLen);
        mapval_skipValue[k].pos <== mapval_decodeUint[k].nextPos + (mapval_value[k] * mapval_isString[k].out);
        copyBytes(bytes, mapval_skipValue[k].bytes, BytesLen)

        // is current value interpreted as a string is a "vc" string?
        mapval_isNeedleString[k] = StringEquals(BytesLen, ConstBytes, ConstBytesLen);
        copyBytes(bytes, mapval_isNeedleString[k].bytes, BytesLen)
        mapval_isNeedleString[k].pos <== mapval_decodeUint[k].nextPos; // pos before skipping
        mapval_isNeedleString[k].len <== mapval_value[k];

        // is current value interpreted as an integer is a 4 number?
        mapval_is4Int[k] = IsEqual();
        mapval_is4Int[k].in[0] <== 4;
        mapval_is4Int[k].in[1] <== mapval_value[k]; // pos before skipping

        // are we within map bounds?
        mapval_withinMaplen[k] = LessThan(8);
        mapval_withinMaplen[k].in[0] <== k;
        mapval_withinMaplen[k].in[1] <== maplen;

        // is current value a "vc" string?
        mapval_isNeedle[k] <== mapval_isString[k].out * mapval_isNeedleString[k].out;

        // is current value a 4 int?
        mapval_isExp[k] <== mapval_isInt[k].out * mapval_is4Int[k].out;

        // should we select this vc pos candidate?
        mapval_isAccepted[k] <== mapval_isNeedle[k] * mapval_withinMaplen[k].out;

        // should we select this exp candidate?
        mapval_isExpAccepted[k] <== mapval_isExp[k] * mapval_withinMaplen[k].out;

        // put a vc pos candidate into NZCPCalculateTotal to be able to get vc pos outside of the loop
        calculateTotal_foundpos.nums[k] <== mapval_isAccepted[k] * (mapval_decodeUint[k].nextPos + mapval_value[k]);
        
        // put a expPos candidate into NZCPCalculateTotal to be able to get exp pos outside of the loop
        calculateTotal_exppos.nums[k] <== mapval_isExpAccepted[k] * mapval_decodeUint[k].nextPos;
    }

    needlepos <== calculateTotal_foundpos.sum;
    expPos <== calculateTotal_exppos.sum;
}

template FindCredSubj(BytesLen, MaxCborArrayLen, MaxCborMapLen) {
    // constants
    var ConstBytesLen = 17;
    var ConstBytes[ConstBytesLen] = [99, 114, 101, 100, 101, 110, 116, 105, 97, 108, 83, 117, 98, 106, 101, 99, 116];

    // i/o signals
    signal input maplen;
    signal input bytes[BytesLen];
    signal input pos;

    signal output needlepos;

    // signals
    signal mapval_v[MaxCborMapLen];
    signal mapval_type[MaxCborMapLen];
    signal mapval_value[MaxCborMapLen];
    signal mapval_isNeedle[MaxCborMapLen];
    signal mapval_isAccepted[MaxCborMapLen];

    component mapval_readType[MaxCborMapLen];
    component mapval_decodeUint[MaxCborMapLen];
    component mapval_skipValue[MaxCborMapLen];
    component mapval_isString[MaxCborMapLen];
    component mapval_isNeedleString[MaxCborMapLen];
    component mapval_withinMaplen[MaxCborMapLen];

    component calculateTotal_foundpos = NZCPCalculateTotal(MaxCborMapLen);

    for (var k = 0; k < MaxCborMapLen; k++) { 

        // read type
        mapval_readType[k] = ReadType(BytesLen);
        copyBytes(bytes, mapval_readType[k].bytes, BytesLen)
        mapval_readType[k].pos <== k == 0 ? pos : mapval_skipValue[k - 1].nextPos;
        mapval_v[k] <== mapval_readType[k].v;
        mapval_type[k] <== mapval_readType[k].type;

        // decode uint
        mapval_decodeUint[k] = DecodeUint(BytesLen);
        mapval_decodeUint[k].v <== mapval_v[k];
        copyBytes(bytes, mapval_decodeUint[k].bytes, BytesLen)
        mapval_decodeUint[k].pos <== mapval_readType[k].nextPos;
        mapval_value[k] <== mapval_decodeUint[k].value;

        // is current value a string?
        mapval_isString[k] = IsEqual();
        mapval_isString[k].in[0] <== mapval_type[k];
        mapval_isString[k].in[1] <== MAJOR_TYPE_STRING;

        // skip value for next iteration
        mapval_skipValue[k] = SkipValue(BytesLen, MaxCborArrayLen);
        mapval_skipValue[k].pos <== mapval_decodeUint[k].nextPos + (mapval_value[k] * mapval_isString[k].out);
        copyBytes(bytes, mapval_skipValue[k].bytes, BytesLen)

        // is current value interpreted as a string is a "vc" string?
        mapval_isNeedleString[k] = StringEquals(BytesLen, ConstBytes, ConstBytesLen);
        copyBytes(bytes, mapval_isNeedleString[k].bytes, BytesLen)
        mapval_isNeedleString[k].pos <== mapval_decodeUint[k].nextPos; // pos before skipping
        mapval_isNeedleString[k].len <== mapval_value[k];

        mapval_withinMaplen[k] = LessThan(8);
        mapval_withinMaplen[k].in[0] <== k;
        mapval_withinMaplen[k].in[1] <== maplen;

        // is current value a "vc" string?
        mapval_isNeedle[k] <== mapval_isString[k].out * mapval_isNeedleString[k].out;

        // should we select this vc pos candidate?
        mapval_isAccepted[k] <== mapval_isNeedle[k] * mapval_withinMaplen[k].out;

        // put a vc pos candidate into NZCPCalculateTotal to be able to get vc pos outside of the loop
        calculateTotal_foundpos.nums[k] <== mapval_isAccepted[k] * (mapval_decodeUint[k].nextPos + mapval_value[k]);
    }

    needlepos <== calculateTotal_foundpos.sum;
}


template ReadCredSubj(BytesLen, MaxBufferLen) {

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

    // i/o signals
    signal input maplen;
    signal input bytes[BytesLen];
    signal input pos;

    signal output givenName[MaxBufferLen];
    signal output givenNameLen;
    signal output familyName[MaxBufferLen];
    signal output familyNameLen;
    signal output dob[MaxBufferLen];
    signal output dobLen;



    // check that map length is exactly as per NZCP spec
    hardcore_assert(maplen, CREDENTIAL_SUBJECT_MAP_LEN);


    component mapval_readStringLength[CREDENTIAL_SUBJECT_MAP_LEN];

    component mapval_isGivenName[CREDENTIAL_SUBJECT_MAP_LEN];
    component mapval_isFamilyName[CREDENTIAL_SUBJECT_MAP_LEN];
    component mapval_isDOB[CREDENTIAL_SUBJECT_MAP_LEN];
    component mapval_copyString[CREDENTIAL_SUBJECT_MAP_LEN];

    for(var k = 0; k < CREDENTIAL_SUBJECT_MAP_LEN; k++) {

        mapval_readStringLength[k] = ReadStringLength(BytesLen);
        copyBytes(bytes, mapval_readStringLength[k].bytes, BytesLen)
        mapval_readStringLength[k].pos <== k == 0 ? pos : mapval_copyString[k - 1].nextPos;

        mapval_isGivenName[k] = StringEquals(BytesLen, GIVEN_NAME_STR, GIVEN_NAME_LEN);
        copyBytes(bytes, mapval_isGivenName[k].bytes, BytesLen)
        mapval_isGivenName[k].pos <== mapval_readStringLength[k].nextPos; // pos before skipping
        mapval_isGivenName[k].len <== mapval_readStringLength[k].len;

        mapval_isFamilyName[k] = StringEquals(BytesLen, FAMILY_NAME_STR, FAMILY_NAME_LEN);
        copyBytes(bytes, mapval_isFamilyName[k].bytes, BytesLen)
        mapval_isFamilyName[k].pos <== mapval_readStringLength[k].nextPos; // pos before skipping
        mapval_isFamilyName[k].len <== mapval_readStringLength[k].len;

        mapval_isDOB[k] = StringEquals(BytesLen, DOB_STR, DOB_LEN);
        copyBytes(bytes, mapval_isDOB[k].bytes, BytesLen)
        mapval_isDOB[k].pos <== mapval_readStringLength[k].nextPos; // pos before skipping
        mapval_isDOB[k].len <== mapval_readStringLength[k].len;

        mapval_copyString[k] = CopyString(BytesLen, MaxStringLen);
        copyBytes(bytes, mapval_copyString[k].bytes, BytesLen)
        mapval_copyString[k].pos <== mapval_readStringLength[k].nextPos + mapval_readStringLength[k].len;

    }


    // assign givenName
    component givenName_charsCalculateTotal[MaxStringLen];
    for(var h = 0; h<MaxStringLen; h++) {
        givenName_charsCalculateTotal[h] = NZCPCalculateTotal(CREDENTIAL_SUBJECT_MAP_LEN);
        for(var i = 0; i < CREDENTIAL_SUBJECT_MAP_LEN; i++) {
            givenName_charsCalculateTotal[h].nums[i] <== mapval_isGivenName[i].out * mapval_copyString[i].outbytes[h];
        }
        givenName[h] <== givenName_charsCalculateTotal[h].sum;
    }
    for(var h = MaxStringLen; h < MaxBufferLen; h++) { givenName[h] <== 0; } // pad out the rest of the string with zeros to avoid invalid access
    component givenName_lenCalculateTotal;
    givenName_lenCalculateTotal = NZCPCalculateTotal(CREDENTIAL_SUBJECT_MAP_LEN);
    for(var i = 0; i < CREDENTIAL_SUBJECT_MAP_LEN; i++) {
        givenName_lenCalculateTotal.nums[i] <== mapval_isGivenName[i].out * mapval_copyString[i].len;
    }
    givenNameLen <== givenName_lenCalculateTotal.sum;


    // assign familyName
    component familyName_charsCalculateTotal[MaxStringLen];
    for(var h = 0; h<MaxStringLen; h++) {
        familyName_charsCalculateTotal[h] = NZCPCalculateTotal(CREDENTIAL_SUBJECT_MAP_LEN);
        for(var i = 0; i < CREDENTIAL_SUBJECT_MAP_LEN; i++) {
            familyName_charsCalculateTotal[h].nums[i] <== mapval_isFamilyName[i].out * mapval_copyString[i].outbytes[h];
        }
        familyName[h] <== familyName_charsCalculateTotal[h].sum;
    }
    for(var h = MaxStringLen; h < MaxBufferLen; h++) { familyName[h] <== 0; } // pad out the rest of the string with zeros to avoid invalid access
    component familyName_lenCalculateTotal;
    familyName_lenCalculateTotal = NZCPCalculateTotal(CREDENTIAL_SUBJECT_MAP_LEN);
    for(var i = 0; i < CREDENTIAL_SUBJECT_MAP_LEN; i++) {
        familyName_lenCalculateTotal.nums[i] <== mapval_isFamilyName[i].out * mapval_copyString[i].len;
    }
    familyNameLen <== familyName_lenCalculateTotal.sum;


    // assign dob
    component dob_charsCalculateTotal[MaxStringLen];
    for(var h = 0; h<MaxStringLen; h++) {
        dob_charsCalculateTotal[h] = NZCPCalculateTotal(CREDENTIAL_SUBJECT_MAP_LEN);
        for(var i = 0; i < CREDENTIAL_SUBJECT_MAP_LEN; i++) {
            dob_charsCalculateTotal[h].nums[i] <== mapval_isDOB[i].out * mapval_copyString[i].outbytes[h];
        }
        dob[h] <== dob_charsCalculateTotal[h].sum;
    }
    for(var h = MaxStringLen; h < MaxBufferLen; h++) { dob[h] <== 0; } // pad out the rest of the string with zeros to avoid invalid access
    component dob_lenCalculateTotal;
    dob_lenCalculateTotal = NZCPCalculateTotal(CREDENTIAL_SUBJECT_MAP_LEN);
    for(var i = 0; i < CREDENTIAL_SUBJECT_MAP_LEN; i++) {
        dob_lenCalculateTotal.nums[i] <== mapval_isDOB[i].out * mapval_copyString[i].len;
    }
    dobLen <== dob_lenCalculateTotal.sum;

}

// concat givenName, familyName and dob with comma as separator
template ConcatCredSubj(MaxBufferLen) {
    var COMMA_CHAR = 44;
    var ConcatSizeBits = log2(MaxBufferLen) + 1;

    signal input givenName[MaxBufferLen];
    signal input givenNameLen;
    signal input familyName[MaxBufferLen];
    signal input familyNameLen;
    signal input dob[MaxBufferLen];
    signal input dobLen;
    signal output result[MaxBufferLen];
    signal output resultLen;

    component isGivenName[MaxBufferLen];
    component isUnderSep1[MaxBufferLen];
    component isUnderFamilyName[MaxBufferLen];
    component isUnderSep2[MaxBufferLen];

    component givenNameSelector[MaxBufferLen];
    component familyNameSelector[MaxBufferLen];
    component dobSelector[MaxBufferLen];

    signal notGivenName[MaxBufferLen];
    signal isSep1[MaxBufferLen];
    signal isFamilyName[MaxBufferLen];
    signal isSep2[MaxBufferLen];
    signal isDOB[MaxBufferLen];

    signal givenNameChar[MaxBufferLen];
    signal sep1Char[MaxBufferLen];
    signal familyNameChar[MaxBufferLen];
    signal sep2Char[MaxBufferLen];
    signal dobChar[MaxBufferLen];
    
    for(var k = 0; k < MaxBufferLen; k++) {
        isGivenName[k] = LessThan(ConcatSizeBits);
        isGivenName[k].in[0] <== k;
        isGivenName[k].in[1] <== givenNameLen;

        isUnderSep1[k] = LessThan(ConcatSizeBits);
        isUnderSep1[k].in[0] <== k;
        isUnderSep1[k].in[1] <== givenNameLen + 1;

        isUnderFamilyName[k] = LessThan(ConcatSizeBits);
        isUnderFamilyName[k].in[0] <== k;
        isUnderFamilyName[k].in[1] <== givenNameLen + 1 + familyNameLen;

        isUnderSep2[k] = LessThan(ConcatSizeBits);
        isUnderSep2[k].in[0] <== k;
        isUnderSep2[k].in[1] <== givenNameLen + 1 + familyNameLen + 1;

        givenNameSelector[k] = QuinSelector(MaxBufferLen);
        for(var z = 0; z < MaxBufferLen; z++) { givenNameSelector[k].in[z] <== givenName[z]; }
        givenNameSelector[k].index <== k;

        familyNameSelector[k] = QuinSelector(MaxBufferLen);
        for(var z = 0; z < MaxBufferLen; z++) { familyNameSelector[k].in[z] <== familyName[z]; }
        familyNameSelector[k].index <== k - givenNameLen - 1;

        dobSelector[k] = QuinSelector(MaxBufferLen);
        for(var z = 0; z < MaxBufferLen; z++) { dobSelector[k].in[z] <== dob[z]; }
        dobSelector[k].index <== k - givenNameLen - 1 - familyNameLen - 1;
        
        notGivenName[k] <== NOT(isGivenName[k].out);
        isSep1[k] <== isUnderSep1[k].out * notGivenName[k];
        isFamilyName[k] <== isUnderFamilyName[k].out * NOT(isUnderSep1[k].out);
        isSep2[k] <== isUnderSep2[k].out * NOT(isUnderFamilyName[k].out);
        isDOB[k] <== NOT(isUnderSep2[k].out);

        givenNameChar[k] <== isGivenName[k].out * givenNameSelector[k].out;
        sep1Char[k] <== isSep1[k] * COMMA_CHAR;
        familyNameChar[k] <== isFamilyName[k] * familyNameSelector[k].out;
        sep2Char[k] <== isSep2[k] * COMMA_CHAR;
        dobChar[k] <== isDOB[k] * dobSelector[k].out;

        result[k] <== givenNameChar[k] + sep1Char[k] + familyNameChar[k] + sep2Char[k] + dobChar[k];
    }
    resultLen <== givenNameLen + 1 + familyNameLen + 1 + dobLen;
}

template NZCPPubIdentity(IsLive, MaxToBeSignedBytes, MaxCborArrayLen, MaxCborMapLen, CredSubjMaxBufferSpace) {
    // constants
    var SHA256_LEN = 256;
    var BLOCK_SIZE = 512;
    var CLAIMS_SKIP_EXAMPLE = 27;
    var CLAIMS_SKIP_LIVE = 30;


    // compile time parameters
    var ClaimsSkip = IsLive ? CLAIMS_SKIP_LIVE : CLAIMS_SKIP_EXAMPLE;

    // ToBeSigned hash
    var MaxToBeSignedBits = MaxToBeSignedBytes * 8;

    var ToBeSignedBlockSpace = 3; // max 503 characters
    var ToBeSignedBlockCount = pow(2, ToBeSignedBlockSpace);
    var ToBeSignedMaxBits = BLOCK_SIZE * ToBeSignedBlockCount;

    assert(MaxToBeSignedBits <= ToBeSignedMaxBits); // compile time check

    // Credential Subject hash
    var CredSubjMaxBufferLen = pow(2, CredSubjMaxBufferSpace);
    var CredSubjMaxBufferLenBits = CredSubjMaxBufferLen * 8;

    var CredSubjBlockSpace = 1;
    var CredSubjBlockCount = pow(2, CredSubjBlockSpace);
    var CredSubjHashMaxBits = BLOCK_SIZE * CredSubjBlockCount;

    assert(CredSubjMaxBufferLenBits <= CredSubjHashMaxBits); // compile time check

    // i/o signals
    signal input toBeSigned[MaxToBeSignedBits]; // gets zero-outted beyond length
    signal input toBeSignedLen; // length of toBeSigned in bytes
    signal output credSubjSha256[SHA256_LEN];
    signal output toBeSignedSha256[SHA256_LEN];
    signal output exp;


    // check that input is only bits (0 or 1) (hardcore assert)
    for (var i = 0; i < MaxToBeSignedBits; i++ ) {
        toBeSigned[i] * (toBeSigned[i] - 1) === 0;
        assert(toBeSigned[i] == 0 || toBeSigned[i] == 1);
    }


    // hardcore assert that toBeSignedLen is less than MaxToBeSignedBytes
    var MaxToBeSignedBytesPlusOne = MaxToBeSignedBytes + 1;
    component lteMaxToBeSignedBytes = LessThan(log2(MaxToBeSignedBytesPlusOne) + 1);
    lteMaxToBeSignedBytes.in[0] <== toBeSignedLen;
    lteMaxToBeSignedBytes.in[1] <== MaxToBeSignedBytesPlusOne;
    assert(toBeSignedLen < MaxToBeSignedBytesPlusOne);
    lteMaxToBeSignedBytes.out === 1;


    // calculate ToBeSigned sha256 hash
    component tbsSha256 = Sha256Var(ToBeSignedBlockSpace);
    tbsSha256.len <== toBeSignedLen * 8;
    for (var i = 0; i < MaxToBeSignedBits; i++) {
        tbsSha256.in[i] <== toBeSigned[i];
    }
    for (var i = MaxToBeSignedBits; i < ToBeSignedMaxBits; i++) {
        tbsSha256.in[i] <== 0;
    }

    // export the ToBeSigned sha256 hash
    for (var i = 0; i < SHA256_LEN; i++) {
        toBeSignedSha256[i] <== tbsSha256.out[i];
    }



    // convert ToBeSigned bits to bytes
    // zero-out everything after the length
    signal ToBeSigned[MaxToBeSignedBytes];
    component b2n[MaxToBeSignedBytes];
    component ltLen[MaxToBeSignedBytes];
    for (var k = 0; k < MaxToBeSignedBytes; k++) {
        b2n[k] = Bits2Num(8);
        for (var i = 0; i < 8; i++) {
            b2n[k].in[i] <== toBeSigned[k * 8 + (7 - i)];
        }
        ltLen[k] = LessThan(log2(MaxToBeSignedBytes) + 1);
        ltLen[k].in[0] <== k;
        ltLen[k].in[1] <== toBeSignedLen;
        ToBeSigned[k] <== b2n[k].out * ltLen[k].out;
    }

    component readMapLength = ReadMapLength(MaxToBeSignedBytes);
    copyBytes(ToBeSigned, readMapLength.bytes, MaxToBeSignedBytes)
    readMapLength.pos <== ClaimsSkip;

    // find "vc" key pos in the map
    signal vcPos;
    signal expPos;
    component findVC = FindVCAndExp(MaxToBeSignedBytes, MaxCborArrayLen, MaxCborMapLen);
    copyBytes(ToBeSigned, findVC.bytes, MaxToBeSignedBytes)
    findVC.pos <== readMapLength.nextPos;
    findVC.maplen <== readMapLength.len;
    vcPos <== findVC.needlepos;
    expPos <== findVC.expPos;

    // read exp field in the map
    component expReadType = ReadType(MaxToBeSignedBytes);
    copyBytes(ToBeSigned, expReadType.bytes, MaxToBeSignedBytes)
    expReadType.pos <== expPos;
    component expDecodeUint = DecodeUint(MaxToBeSignedBytes);
    expDecodeUint.v <== expReadType.v;
    copyBytes(ToBeSigned, expDecodeUint.bytes, MaxToBeSignedBytes)
    expDecodeUint.pos <== expReadType.nextPos;
    exp <== expDecodeUint.value;


    // find credential subject
    component readMapLength2 = ReadMapLength(MaxToBeSignedBytes);
    copyBytes(ToBeSigned, readMapLength2.bytes, MaxToBeSignedBytes)
    readMapLength2.pos <== vcPos;

    signal credSubjPos;
    component findCredSubj = FindCredSubj(MaxToBeSignedBytes, MaxCborArrayLen, MaxCborMapLen);
    copyBytes(ToBeSigned, findCredSubj.bytes, MaxToBeSignedBytes)
    findCredSubj.pos <== readMapLength2.nextPos;
    findCredSubj.maplen <== readMapLength2.len;
    credSubjPos <== findCredSubj.needlepos;

    // read credential subject map length
    component readMapLength3 = ReadMapLength(MaxToBeSignedBytes);
    copyBytes(ToBeSigned, readMapLength3.bytes, MaxToBeSignedBytes)
    readMapLength3.pos <== credSubjPos;


    // read credential subject map
    component readCredSubj = ReadCredSubj(MaxToBeSignedBytes, CredSubjMaxBufferLen);
    copyBytes(ToBeSigned, readCredSubj.bytes, MaxToBeSignedBytes)
    readCredSubj.pos <== readMapLength3.nextPos;
    readCredSubj.maplen <== readMapLength3.len;

    // concat given name, family name and dob
    component concatCredSubj = ConcatCredSubj(CredSubjMaxBufferLen);
    concatCredSubj.givenNameLen <== readCredSubj.givenNameLen;
    concatCredSubj.familyNameLen <== readCredSubj.familyNameLen;
    concatCredSubj.dobLen <== readCredSubj.dobLen;
    for (var i = 0; i < CredSubjMaxBufferLen; i++) { concatCredSubj.givenName[i] <== readCredSubj.givenName[i]; }
    for (var i = 0; i < CredSubjMaxBufferLen; i++) { concatCredSubj.familyName[i] <== readCredSubj.familyName[i]; }
    for (var i = 0; i < CredSubjMaxBufferLen; i++) { concatCredSubj.dob[i] <== readCredSubj.dob[i]; }
    
    // convert concat string into bits
    component n2b[CredSubjMaxBufferLen];
    signal bits[CredSubjMaxBufferLenBits];
    for(var k = 0; k < CredSubjMaxBufferLen; k++) {
        n2b[k] = Num2Bits(8);
        n2b[k].in <== concatCredSubj.result[k];
        for (var j = 0; j < 8; j++) {
            bits[k*8 + (7 - j)] <== n2b[k].out[j];
        }
    }

    // calculate sha256 of the concat string
    component sha256 = Sha256Var(CredSubjBlockSpace);
    sha256.len <== concatCredSubj.resultLen * 8;
    for (var i = 0; i < CredSubjMaxBufferLenBits; i++) {
        sha256.in[i] <== bits[i];
    }
    for (var i = CredSubjMaxBufferLenBits; i < CredSubjHashMaxBits; i++) {
        sha256.in[i] <== 0;
    }

    // export the sha256 hash of the concat string
    for (var i = 0; i < SHA256_LEN; i++) {
        credSubjSha256[i] <== sha256.out[i];
    }

}


