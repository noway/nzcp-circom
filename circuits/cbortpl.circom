pragma circom 2.0.0;

include "../sha256-var-circom-main/snark-jwt-verify/circomlib/circuits/comparators.circom";
include "../sha256-var-circom-main/snark-jwt-verify/circomlib/circuits/sha256/shift.circom";
include "./incrementalQuinTree.circom";

/* assert through constraint and assert */
#define hardcore_assert(a, b) a === b; assert(a == b)

#define copyBytes(b, a, c) for(var z = 0; z<c; z++) { a[z] <== b[z]; }

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
    // TODO: assert 8 bits here and in all other places
    // constants
    var InputBits = 8;
    var ShiftBits = 5;
    var ResultBits = InputBits - ShiftBits;

    // i/o signals
    signal input v;
    signal output type;

    // convert v to bits
    component n2b = Num2Bits(InputBits);
    n2b.in <== v;

    // shift
    component shr = ShR(InputBits, ShiftBits); // v >> 5
    for (var i = 0; i < InputBits; i++) {
        shr.in[i] <== n2b.out[i];
    }

    // convert back to number
    component b2n = Bits2Num(ResultBits);
    for (var i = 0; i < ResultBits; i++) {
        b2n.in[i] <== shr.out[i];
    }
    type <== b2n.out;
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
    component b2n = Bits2Num(5);
    for (var i = 0; i < 5; i++) {
        b2n.in[i] <== vbits[i];
    }
    x <== b2n.out;
}

template GetV(BytesLen) {
    signal input bytes[BytesLen];
    signal input pos;
    signal output v;

    component quinSelector = QuinSelector(BytesLen);
    for (var k=0; k<BytesLen; k++) {
        quinSelector.in[k] <== bytes[k];
    }
    quinSelector.index <== pos;
    v <== quinSelector.out;
}

// supports <=23 integers
template DecodeUint23() {
    signal input v;
    signal output value;

    component getX = GetX(); // can only return 8 bits
    getX.v <== v;

    component lt = LessThan(8);
    lt.in[0] <== getX.x;
    lt.in[1] <== 24;
    assert(getX.x < 24); // only supporting uint <= 23
    lt.out === 1;

    value <== getX.x;
}

// Supports <=23 integers as well as 8bit, 16bit and 32bit integers
template DecodeUint(BytesLen) {
    signal input v;
    signal input bytes[BytesLen];
    signal input pos;
    signal output value;
    signal output nextpos;

    signal x;
    component getX = GetX();
    getX.v <== v;
    x <== getX.x;

    // if (x <= 23)
    signal value_23;
    value_23 <== x;
    signal nextpos_23;
    nextpos_23 <== pos;

    // if(x == 24)
    component getV_24 = GetV(BytesLen);

    copyBytes(bytes, getV_24.bytes, BytesLen)
    getV_24.pos <== pos;
    signal value_24;
    value_24 <== getV_24.v;
    signal nextpos_24;
    nextpos_24 <== pos + 1;

    // if(x == 25)
    component getV1_25 = GetV(BytesLen);
    component getV2_25 = GetV(BytesLen);
    copyBytes(bytes, getV1_25.bytes, BytesLen)
    copyBytes(bytes, getV2_25.bytes, BytesLen)

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
    component getV1_26 = GetV(BytesLen);
    component getV2_26 = GetV(BytesLen);
    component getV3_26 = GetV(BytesLen);
    component getV4_26 = GetV(BytesLen);

    copyBytes(bytes, getV1_26.bytes, BytesLen)
    copyBytes(bytes, getV2_26.bytes, BytesLen)
    copyBytes(bytes, getV3_26.bytes, BytesLen)
    copyBytes(bytes, getV4_26.bytes, BytesLen)

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
    condition_23 <== lessThan.out;

    component isEqual24 = IsEqual();
    isEqual24.in[0] <== x;
    isEqual24.in[1] <== 24;
    signal condition_24;
    condition_24 <== isEqual24.out;

    component isEqual25 = IsEqual();
    isEqual25.in[0] <== x;
    isEqual25.in[1] <== 25;
    signal condition_25;
    condition_25 <== isEqual25.out;

    component isEqual26 = IsEqual();
    isEqual26.in[0] <== x;
    isEqual26.in[1] <== 26;
    signal condition_26;
    condition_26 <== isEqual26.out;


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
template ReadType(BytesLen) {

    signal input bytes[BytesLen];
    signal input pos;
    signal output nextpos;
    signal output type;
    signal output v;

    component getV = GetV(BytesLen);
    copyBytes(bytes, getV.bytes, BytesLen)
    getV.pos <== pos;
    v <== getV.v;

    component getType = GetType();
    getType.v <== v;
    type <== getType.type;

    nextpos <== pos + 1;
}

// TODO: test
// Skips a scalar value, only ints and strings are supported atm.
template SkipValueScalar(BytesLen) {

    // signals
    signal input bytes[BytesLen];
    signal input pos;

    signal output nextpos;

    // read type
    component readType = ReadType(BytesLen);
    copyBytes(bytes, readType.bytes, BytesLen)
    readType.pos <== pos;

    // decode uint
    component decodeUint = DecodeUint(BytesLen);
    decodeUint.v <== readType.v;
    copyBytes(bytes, decodeUint.bytes, BytesLen)
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
template SkipValue(BytesLen) {

    // constants
    // TODO: bigger? (yep that works ok)
    var MAX_ARRAY_LEN = 4;

    // i/o signals
    signal input bytes[BytesLen];
    signal input pos;

    signal output nextpos;

    // read type
    component readType = ReadType(BytesLen);
    copyBytes(bytes, readType.bytes, BytesLen)
    readType.pos <== pos;

    // decode uint
    component decodeUint = DecodeUint(BytesLen);
    decodeUint.v <== readType.v;
    copyBytes(bytes, decodeUint.bytes, BytesLen)
    decodeUint.pos <== readType.nextpos;


    // calculate nextpos if an array
    signal nextposarray[MAX_ARRAY_LEN];
    component skipValue[MAX_ARRAY_LEN];
    component qs = QuinSelectorUnchecked(MAX_ARRAY_LEN);
    for (var i = 0; i < MAX_ARRAY_LEN; i++) {
        skipValue[i] = SkipValueScalar(BytesLen);
        copyBytes(bytes, skipValue[i].bytes, BytesLen)
        skipValue[i].pos <== i == 0 ? decodeUint.nextpos : nextposarray[i - 1];
        nextposarray[i] <== skipValue[i].nextpos;
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
template StringEquals(BytesLen, ConstBytes, ConstBytesLen) {
    signal input bytes[BytesLen];
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

        getV[i] = GetV(BytesLen);
        copyBytes(bytes, getV[i].bytes, BytesLen)
        getV[i].pos <== pos + i;
        isEqual[i].in[1] <== getV[i].v;

        conditionsSum = conditionsSum + isEqual[i].out;
    }

    var allConditionsAreTrue = ConstBytesLen + 1;
    component isZero = IsZero();
    isZero.in <== allConditionsAreTrue - conditionsSum;
    out <== isZero.out;
}

template IntEquals(BytesLen, ConstInt) {
    signal input bytes[BytesLen];
    signal input pos;
    signal input len;
    
    signal output out;

    var conditionsSum = 0;
    component isEqual;
    // component getV;
    isEqual = IsEqual();
    isEqual.in[0] <== ConstInt;

    // TODO: decode uint
    // getV = GetV(BytesLen);
    // copyBytes(bytes, getV.bytes, BytesLen)
    // getV.pos <== pos;
    // isEqual.in[1] <== getV.v;

    conditionsSum = conditionsSum + isEqual.out;

    var allConditionsAreTrue = 1;
    component isZero = IsZero();
    isZero.in <== allConditionsAreTrue - conditionsSum;
    out <== isZero.out;
}

template ReadStringLength(BytesLen) {
    // i/o signals
    signal input bytes[BytesLen];
    signal input pos;
    signal output len;
    signal output nextpos;

    // read type
    component readType = ReadType(BytesLen);
    copyBytes(bytes, readType.bytes, BytesLen)
    readType.pos <== pos; // 27 bytes initial skip for example MoH pass
    nextpos <== readType.nextpos;
    hardcore_assert(readType.type, MAJOR_TYPE_STRING);

    // read string length
    component dUint = DecodeUint(BytesLen);
    copyBytes(bytes, dUint.bytes, BytesLen)
    dUint.pos <== readType.nextpos;
    dUint.v <== readType.v;
    len <== dUint.value;
}

template ReadMapLength(ToBeSignedBytes) {
    // i/o signals
    signal input pos;
    signal input bytes[ToBeSignedBytes];
    signal output len;
    signal output nextpos;

    // read type
    component readType = ReadType(ToBeSignedBytes);
    copyBytes(bytes, readType.bytes, ToBeSignedBytes)
    readType.pos <== pos; // 27 bytes initial skip for example MoH pass
    nextpos <== readType.nextpos;
    hardcore_assert(readType.type, MAJOR_TYPE_MAP);

    // read map length
    // only supporting maps with 23 or less entries
    component dUint23 = DecodeUint23();
    dUint23.v <== readType.v;
    len <== dUint23.value;
}

// TODO: test
template DecodeString(BytesLen, MaxLen) {
    // i/o signals
    signal input bytes[BytesLen];
    signal input pos;

    signal output outbytes[MaxLen];
    signal output nextpos;
    signal output len;

    // read string length
    component readStrLen = ReadStringLength(BytesLen);
    copyBytes(bytes, readStrLen.bytes, BytesLen)
    readStrLen.pos <== pos;

    // read bytes
    component getV[MaxLen];
    component lt[MaxLen];
    for (var i = 0; i < MaxLen; i++) {
        getV[i] = GetV(BytesLen);
        copyBytes(bytes, getV[i].bytes, BytesLen)
        getV[i].pos <== readStrLen.nextpos + i;

        var bits = log2(MaxLen) + 1;
        lt[i] = LessThan(bits);
        lt[i].in[0] <== i;
        lt[i].in[1] <== readStrLen.len;
        outbytes[i] <== getV[i].v * lt[i].out;
    }

    // return
    nextpos <== readStrLen.nextpos + readStrLen.len;
    len <== readStrLen.len;
}