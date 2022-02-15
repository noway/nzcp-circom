pragma circom 2.0.0;

include "../sha256-var-circom-main/snark-jwt-verify/circomlib/circuits/comparators.circom";
include "./incrementalQuinTree.circom";

/* assert through constraint and assert */
#define hardcore_assert(a, b) a === b; assert(a == b)

#define copyBytes(b, a) for(var z = 0; z<ToBeSignedBytes; z++) { a.bytes[z] <== b[z]; }

/* CBOR types */
#define MAJOR_TYPE_INT 0
#define MAJOR_TYPE_NEGATIVE_INT 1
#define MAJOR_TYPE_BYTES 2
#define MAJOR_TYPE_STRING 3
#define MAJOR_TYPE_ARRAY 4
#define MAJOR_TYPE_MAP 5
#define MAJOR_TYPE_TAG 6
#define MAJOR_TYPE_CONTENT_FREE 7


// returns the value of v bit shifted to the right by 5 bits
template GetType() {
    // TODO: use Num2Bits?
    // TODO: assert 8 bits here and in all other places
    signal input v;
    signal output type;
    // assign type signal
    // shift 0bXXXYYYYY to 0b00000XXX
    type <-- v >> 5;
    signal check_v;
    check_v <== type * 32;
    // we need full 8 bits to check, otherwise in[0] might get stripped
    component lessThan = LessThan(8); 
    lessThan.in[0] <== v - check_v;
    lessThan.in[1] <== 32;
    lessThan.out === 1;
}

// returns the 5 lowest bits of v
template GetX() {
    // TODO: assert 8 bits
    signal input v;
    signal output x;
    // the code bellow is a quadratic equivalent of:
    // x <== v & 31; // 0b00011111
    component num2Bits = Num2Bits(8);
    num2Bits.in <== v;
    signal vbits[8];
    for(var k = 0; k < 8; k++) {
        vbits[k] <== num2Bits.out[k];
    }
    var lc1=0;
    var e2 = 1;
    for (var i = 0; i<5; i++) {
        lc1 += vbits[i] * e2;
        e2 = e2 + e2;
    }
    lc1 ==> x;
}

// TODO: rename to GetValue?
template GetV(ToBeSignedBytes) {
    signal input bytes[ToBeSignedBytes];
    signal input pos;
    signal output v;

    component quinSelector = QuinSelector(ToBeSignedBytes);
    for (var k=0; k<ToBeSignedBytes; k++) {
        quinSelector.in[k] <== bytes[k];
    }
    quinSelector.index <== pos;
    v <== quinSelector.out;
}

// Supports <=23 integers as well as 8bit, 16bit and 32bit integers
template DecodeUint(ToBeSignedBytes) {
    // TODO: only copy over 4 bytes for the lookahead
    signal input v;
    signal input bytes[ToBeSignedBytes];
    signal input pos;
    signal output value;
    signal output nextpos;

    signal x;
    component getX = GetX();
    getX.v <== v;
    getX.x ==> x;

    // if (x <= 23)
    signal value_23;
    value_23 <== x;
    signal nextpos_23;
    nextpos_23 <== pos;

    // if(x == 24)
    component getV_24 = GetV(ToBeSignedBytes);

    copyBytes(bytes, getV_24)
    getV_24.pos <== pos;
    signal value_24;
    value_24 <== getV_24.v;
    signal nextpos_24;
    nextpos_24 <== pos + 1;

    // if(x == 25)
    component getV1_25 = GetV(ToBeSignedBytes);
    component getV2_25 = GetV(ToBeSignedBytes);
    copyBytes(bytes, getV1_25)
    copyBytes(bytes, getV2_25)

    getV1_25.pos <== pos;
    signal value_1_25;
    value_1_25 <== getV1_25.v * 256; // 2**8

    getV2_25.pos <== pos + 1;
    signal value_2_25;
    value_2_25 <== getV2_25.v;

    signal value_25;
    value_25 <== value_1_25 + value_2_25;

    signal nextpos_25;
    nextpos_25 <== pos + 2;

    // if(x == 26)
    component getV1_26 = GetV(ToBeSignedBytes);
    component getV2_26 = GetV(ToBeSignedBytes);
    component getV3_26 = GetV(ToBeSignedBytes);
    component getV4_26 = GetV(ToBeSignedBytes);

    copyBytes(bytes, getV1_26)
    copyBytes(bytes, getV2_26)
    copyBytes(bytes, getV3_26)
    copyBytes(bytes, getV4_26)

    getV1_26.pos <== pos;
    signal value_1_26;
    value_1_26 <== getV1_26.v * 16777216; // 2**24

    getV2_26.pos <== pos + 1;
    signal value_2_26;
    value_2_26 <== getV2_26.v * 65536; // 2**16

    getV3_26.pos <== pos + 2;
    signal value_3_26;
    value_3_26 <== getV3_26.v * 256; // 2**8

    getV4_26.pos <== pos + 3;
    signal value_4_26;
    value_4_26 <== getV4_26.v;

    signal value_26;
    value_26 <== value_1_26 + value_2_26 + value_3_26 + value_4_26;

    signal nextpos_26;
    nextpos_26 <== pos + 4;


    // execture conditions
    component lessThan = LessThan(8); // 8 bits should be enough
    lessThan.in[0] <== x;
    lessThan.in[1] <== 24;
    signal condition_23;
    lessThan.out ==> condition_23;

    component isEqual24 = IsEqual();
    isEqual24.in[0] <== x;
    isEqual24.in[1] <== 24;
    signal condition_24;
    isEqual24.out ==> condition_24;

    component isEqual25 = IsEqual();
    isEqual25.in[0] <== x;
    isEqual25.in[1] <== 25;
    signal condition_25;
    isEqual25.out ==> condition_25;

    component isEqual26 = IsEqual();
    isEqual26.in[0] <== x;
    isEqual26.in[1] <== 26;
    signal condition_26;
    isEqual26.out ==> condition_26;


    // return
    component calculateTotal_value = NZCPCalculateTotal(4);
    calculateTotal_value.nums[0] <== condition_23 * value_23;
    calculateTotal_value.nums[1] <== condition_24 * value_24;
    calculateTotal_value.nums[2] <== condition_25 * value_25;
    calculateTotal_value.nums[3] <== condition_26 * value_26;
    value <== calculateTotal_value.sum;

    component calculateTotal_nextpos = NZCPCalculateTotal(4);
    calculateTotal_nextpos.nums[0] <== condition_23 * nextpos_23;
    calculateTotal_nextpos.nums[1] <== condition_24 * nextpos_24;
    calculateTotal_nextpos.nums[2] <== condition_25 * nextpos_25;
    calculateTotal_nextpos.nums[3] <== condition_26 * nextpos_26;
    nextpos <== calculateTotal_nextpos.sum;
}

// TODO: test
template ReadType(ToBeSignedBytes) {

    signal input bytes[ToBeSignedBytes];
    signal input pos;
    signal output nextpos;
    signal output type;
    signal output v;

    component getV = GetV(ToBeSignedBytes);
    copyBytes(bytes, getV)
    getV.pos <== pos;
    getV.v ==> v;

    component getType = GetType();
    getType.v <== v;
    getType.type ==> type;

    pos + 1 ==> nextpos;
}

// TODO: test
// Skips a scalar value, only ints and strings are supported atm.
template SkipValueScalar(ToBeSignedBytes) {

    // signals
    signal input bytes[ToBeSignedBytes];
    signal input pos;

    signal output nextpos;

    // read type
    component readType = ReadType(ToBeSignedBytes);
    copyBytes(bytes, readType)
    readType.pos <== pos;

    // decode uint
    component decodeUint = DecodeUint(ToBeSignedBytes);
    decodeUint.v <== readType.v;
    copyBytes(bytes, decodeUint)
    decodeUint.pos <== readType.nextpos;

    // decide between int and string
    component isInt = IsEqual();
    isInt.in[0] <== readType.type;
    isInt.in[1] <== MAJOR_TYPE_INT;

    component isString = IsEqual();
    isString.in[0] <== readType.type;
    isString.in[1] <== MAJOR_TYPE_STRING;

    // return
    component calculateTotal = NZCPCalculateTotal(2);
    calculateTotal.nums[0] <== isInt.out * decodeUint.nextpos;
    calculateTotal.nums[1] <== isString.out * (decodeUint.nextpos + decodeUint.value);
    nextpos <== calculateTotal.sum;
}


// TODO: test
// TODO: rename ToBeSignedBytes to byteslen or len
template SkipValue(ToBeSignedBytes) {

    // constants
    // TODO: bigger?
    var MAX_ARRAY_LEN = 4;

    // i/o signals
    signal input bytes[ToBeSignedBytes];
    signal input pos;

    signal output nextpos;

    // read type
    component readType = ReadType(ToBeSignedBytes);
    copyBytes(bytes, readType)
    readType.pos <== pos;

    // decode uint
    component decodeUint = DecodeUint(ToBeSignedBytes);
    decodeUint.v <== readType.v;
    copyBytes(bytes, decodeUint)
    decodeUint.pos <== readType.nextpos;


    // calculate nextpos if an array
    signal nextposarray[MAX_ARRAY_LEN];
    component skipValue[MAX_ARRAY_LEN];
    component qs = QuinSelectorUnchecked(MAX_ARRAY_LEN);
    for (var i = 0; i < MAX_ARRAY_LEN; i++) {
        skipValue[i] = SkipValueScalar(ToBeSignedBytes);
        copyBytes(bytes, skipValue[i])
        skipValue[i].pos <== i == 0 ? decodeUint.nextpos : nextposarray[i - 1];
        skipValue[i].nextpos ==> nextposarray[i];
        qs.in[i] <== skipValue[i].nextpos;
    }
    qs.index <== decodeUint.value - 1;

    // if (cbortype == MAJOR_TYPE_INT) 
    component isInt = IsEqual();
    isInt.in[0] <== readType.type;
    isInt.in[1] <== MAJOR_TYPE_INT;

    // else if (cbortype == MAJOR_TYPE_STRING)
    component isString = IsEqual();
    isString.in[0] <== readType.type;
    isString.in[1] <== MAJOR_TYPE_STRING;

    // else if (cbortype == MAJOR_TYPE_ARRAY)
    component isArray = IsEqual();
    isArray.in[0] <== readType.type;
    isArray.in[1] <== MAJOR_TYPE_ARRAY;

    // return
    component calculateTotal = NZCPCalculateTotal(3);
    calculateTotal.nums[0] <== isInt.out * decodeUint.nextpos;
    calculateTotal.nums[1] <== isString.out * (decodeUint.nextpos + decodeUint.value);
    calculateTotal.nums[2] <== isArray.out * qs.out;
    nextpos <== calculateTotal.sum;
}

// TODO: test
// check if a string is equal to a given string
template StringEquals(ToBeSignedBytes, ConstBytes, ConstBytesLen) {
    signal input bytes[ToBeSignedBytes];
    signal input pos;
    signal input len;
    
    signal output out;

    component isSameLen = IsEqual();
    isSameLen.in[0] <== len;
    isSameLen.in[1] <== ConstBytesLen;

    var conditionsSum = isSameLen.out;
    component isEqual[ConstBytesLen];
    component getV[ConstBytesLen];
    for (var i = 0; i < ConstBytesLen; i++) {
        isEqual[i] = IsEqual();
        isEqual[i].in[0] <== ConstBytes[i];

        getV[i] = GetV(ToBeSignedBytes);
        copyBytes(bytes, getV[i])
        getV[i].pos <== pos + i;
        getV[i].v ==> isEqual[i].in[1];

        conditionsSum = conditionsSum + isEqual[i].out;
    }

    var allConditionsAreTrue = ConstBytesLen + 1;
    component isZero = IsZero();
    isZero.in <== allConditionsAreTrue - conditionsSum;
    out <== isZero.out;
}

// TODO: test
template DecodeString(ToBeSignedBytes, MaxLen) {
    // i/o signals
    signal input bytes[ToBeSignedBytes];
    signal input pos;

    signal output outbytes[MaxLen];
    signal output nextpos;
    signal output len;

    // read type
    component readType = ReadType(ToBeSignedBytes);
    copyBytes(bytes, readType)
    readType.pos <== pos;

    // assert that it is a string
    hardcore_assert(readType.type, MAJOR_TYPE_STRING);

    // decode uint
    component decodeUint = DecodeUint(ToBeSignedBytes);
    decodeUint.v <== readType.v;
    copyBytes(bytes, decodeUint)
    decodeUint.pos <== readType.nextpos;

    // read bytes
    component getV[MaxLen];
    for (var i = 0; i < MaxLen; i++) {
        getV[i] = GetV(ToBeSignedBytes);
        copyBytes(bytes, getV[i])
        getV[i].pos <== decodeUint.nextpos + i;
        getV[i].v ==> outbytes[i];
    }

    // return
    nextpos <== decodeUint.nextpos + decodeUint.value;
    len <== decodeUint.value;
}