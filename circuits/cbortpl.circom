pragma circom 2.0.0;

include "../sha256-var-circom-main/snark-jwt-verify/circomlib/circuits/comparators.circom";
include "../sha256-var-circom-main/snark-jwt-verify/circomlib/circuits/sha256/shift.circom";
include "./quinSelector.circom";

/* check through constraint and assert */
#define hardcore_assert(a, b) a === b; assert(a == b)

#define copyBytes(b, a, c) for(var z = 0; z < c; z++) { a[z] <== b[z]; }

/* CBOR types */
#define MAJOR_TYPE_INT 0
#define MAJOR_TYPE_NEGATIVE_INT 1
#define MAJOR_TYPE_BYTES 2
#define MAJOR_TYPE_STRING 3
#define MAJOR_TYPE_ARRAY 4
#define MAJOR_TYPE_MAP 5
#define MAJOR_TYPE_TAG 6
#define MAJOR_TYPE_CONTENT_FREE 7


// @dev get CBOR type
// CBOR type is the value of v bit shifted to the right by 5 bits
// input MUST be a byte
template GetType() {
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

// @dev get CBOR x value
// CBOR x value is the 5 lowest bits of v
// input MUST be a byte
template GetX() {
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

// @dev get CBOR v
// CBOR v is the element of array `bytes` at index `pos`
// input MUST be a byte array
// @param BytesLen - length of the byte array
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

// @dev decode a CBOR integer
// supports <=23 integers
// input MUST be a byte
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

// @dev decode a CBOR integer
// Supports <=23 integers as well as 8-bit, 16-bit and 32-bit integers
// input MUST be a byte array
// @param BytesLen - length of the cbor buffer
template DecodeUint(BytesLen) {
    signal input v;
    signal input bytes[BytesLen];
    signal input pos;
    signal output value;
    signal output nextPos;

    signal x;
    component getX = GetX();
    getX.v <== v;
    x <== getX.x;

    // prepare conditions
    component lessThan = LessThan(8); // 8 bits should be enough
    lessThan.in[0] <== x;
    lessThan.in[1] <== 24;
    signal condition23;
    condition23 <== lessThan.out;

    component isEqual24 = IsEqual();
    isEqual24.in[0] <== x;
    isEqual24.in[1] <== 24;
    signal condition24;
    condition24 <== isEqual24.out;

    component isEqual25 = IsEqual();
    isEqual25.in[0] <== x;
    isEqual25.in[1] <== 25;
    signal condition25;
    condition25 <== isEqual25.out;

    component isEqual26 = IsEqual();
    isEqual26.in[0] <== x;
    isEqual26.in[1] <== 26;
    signal condition26;
    condition26 <== isEqual26.out;

    // if (x <= 23)
    signal value23;
    value23 <== x;
    signal nextPos23;
    nextPos23 <== pos;

    // if(x == 24)
    component getV_24 = GetV(BytesLen);

    copyBytes(bytes, getV_24.bytes, BytesLen)
    getV_24.pos <== condition24 * pos;
    signal value24;
    value24 <== getV_24.v;
    signal nextPos24;
    nextPos24 <== pos + 1;

    // if(x == 25)
    component getV1_25 = GetV(BytesLen);
    component getV2_25 = GetV(BytesLen);
    copyBytes(bytes, getV1_25.bytes, BytesLen)
    copyBytes(bytes, getV2_25.bytes, BytesLen)

    getV1_25.pos <== condition25 * pos;
    signal value1_25;
    value1_25 <== getV1_25.v * 256; // 2**8

    getV2_25.pos <== condition25 * (pos + 1);
    signal value2_25;
    value2_25 <== getV2_25.v;

    signal value25;
    value25 <== value1_25 + value2_25;

    signal nextPos25;
    nextPos25 <== pos + 2;

    // if(x == 26)
    component getV1_26 = GetV(BytesLen);
    component getV2_26 = GetV(BytesLen);
    component getV3_26 = GetV(BytesLen);
    component getV4_26 = GetV(BytesLen);

    copyBytes(bytes, getV1_26.bytes, BytesLen)
    copyBytes(bytes, getV2_26.bytes, BytesLen)
    copyBytes(bytes, getV3_26.bytes, BytesLen)
    copyBytes(bytes, getV4_26.bytes, BytesLen)

    getV1_26.pos <== condition26 * pos;
    signal value1_26;
    value1_26 <== getV1_26.v * 16777216; // 2**24

    getV2_26.pos <== condition26 * (pos + 1);
    signal value2_26;
    value2_26 <== getV2_26.v * 65536; // 2**16

    getV3_26.pos <== condition26 * (pos + 2);
    signal value3_26;
    value3_26 <== getV3_26.v * 256; // 2**8

    getV4_26.pos <== condition26 * (pos + 3);
    signal value4_26;
    value4_26 <== getV4_26.v;

    signal value26;
    value26 <== value1_26 + value2_26 + value3_26 + value4_26;

    signal nextPos26;
    nextPos26 <== pos + 4;



    // return
    component valueTally = CalculateTotal(4);
    valueTally.nums[0] <== condition23 * value23;
    valueTally.nums[1] <== condition24 * value24;
    valueTally.nums[2] <== condition25 * value25;
    valueTally.nums[3] <== condition26 * value26;
    value <== valueTally.sum;

    component nextPosTally = CalculateTotal(4);
    nextPosTally.nums[0] <== condition23 * nextPos23;
    nextPosTally.nums[1] <== condition24 * nextPos24;
    nextPosTally.nums[2] <== condition25 * nextPos25;
    nextPosTally.nums[3] <== condition26 * nextPos26;
    nextPos <== nextPosTally.sum;
}

// @dev read a CBOR type
// returns the next position and v
// input MUST be a byte array
// @param BytesLen - length of the cbor buffer
template ReadType(BytesLen) {

    signal input bytes[BytesLen];
    signal input pos;
    signal output nextPos;
    signal output type;
    signal output v;

    component getV = GetV(BytesLen);
    copyBytes(bytes, getV.bytes, BytesLen)
    getV.pos <== pos;
    v <== getV.v;

    component getType = GetType();
    getType.v <== v;
    type <== getType.type;

    nextPos <== pos + 1;
}

// @dev skip a scalar CBOR value, only ints and strings are supported atm.
// input MUST be a byte array
// @param BytesLen - length of the cbor buffer
template SkipValueScalar(BytesLen) {

    // signals
    signal input bytes[BytesLen];
    signal input pos;

    signal output nextPos;

    // read type
    component readType = ReadType(BytesLen);
    copyBytes(bytes, readType.bytes, BytesLen)
    readType.pos <== pos;

    // decode uint
    component decodeUint = DecodeUint(BytesLen);
    decodeUint.v <== readType.v;
    copyBytes(bytes, decodeUint.bytes, BytesLen)
    decodeUint.pos <== readType.nextPos;

    // decide between int and string
    component isInt = IsEqual();
    isInt.in[0] <== readType.type;
    isInt.in[1] <== MAJOR_TYPE_INT;

    component isString = IsEqual();
    isString.in[0] <== readType.type;
    isString.in[1] <== MAJOR_TYPE_STRING;

    // return
    component calculateTotal = CalculateTotal(2);
    calculateTotal.nums[0] <== isInt.out * decodeUint.nextPos;
    calculateTotal.nums[1] <== isString.out * (decodeUint.nextPos + decodeUint.value);
    nextPos <== calculateTotal.sum;
}


// @dev skip a CBOR value. supports everything that SkipValueScalar supports plus arrays
// input MUST be a byte array
// @param BytesLen - length of the cbor buffer
// @param MaxArrayLen - maximum number of elements in the CBOR array
template SkipValue(BytesLen, MaxArrayLen) {
    // i/o signals
    signal input bytes[BytesLen];
    signal input pos;

    signal output nextPos;

    // read type
    component readType = ReadType(BytesLen);
    copyBytes(bytes, readType.bytes, BytesLen)
    readType.pos <== pos;

    // decode uint
    component decodeUint = DecodeUint(BytesLen);
    decodeUint.v <== readType.v;
    copyBytes(bytes, decodeUint.bytes, BytesLen)
    decodeUint.pos <== readType.nextPos;


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

    // calculate nextPos if an array
    signal nextPosArray[MaxArrayLen];
    component skipValue[MaxArrayLen];
    component qs = QuinSelector(MaxArrayLen);
    
    component lt[MaxArrayLen];
    signal shouldConsider[MaxArrayLen];
    for (var i = 0; i < MaxArrayLen; i++) {
        var bits = log2(MaxArrayLen) + 1;
        lt[i] = LessThan(bits);
        lt[i].in[0] <== i;
        lt[i].in[1] <== isArray.out * decodeUint.value;
        shouldConsider[i] <== isArray.out * lt[i].out;
        
        skipValue[i] = SkipValueScalar(BytesLen);
        copyBytes(bytes, skipValue[i].bytes, BytesLen)
        skipValue[i].pos <== i == 0 ? decodeUint.nextPos * shouldConsider[i] : nextPosArray[i - 1] * shouldConsider[i];
        nextPosArray[i] <== skipValue[i].nextPos;
        qs.in[i] <== skipValue[i].nextPos;
    }
    qs.index <== isArray.out * (decodeUint.value - 1);

    // return
    component calculateTotal = CalculateTotal(3);
    calculateTotal.nums[0] <== isInt.out * decodeUint.nextPos;
    calculateTotal.nums[1] <== isString.out * (decodeUint.nextPos + decodeUint.value);
    calculateTotal.nums[2] <== isArray.out * qs.out;
    nextPos <== calculateTotal.sum;
}

// @dev check if a CBOR string equals to a given string
// input MUST be a byte array
// @param BytesLen - length of the cbor buffer
// @param ConstBytes - constant byte array to compare to
// @param ConstBytesLen - length of the constant byte array
template StringEquals(BytesLen, ConstBytes, ConstBytesLen) {

    assert(ConstBytesLen <= BytesLen);

    // i/o signals
    signal input bytes[BytesLen];
    signal input pos;
    signal input len;
    signal output out;

    // check if length matches
    component isSameLen = IsEqual();
    isSameLen.in[0] <== len;
    isSameLen.in[1] <== ConstBytesLen;

    // compare every character
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

    // return
    var allConditionsAreTrue = ConstBytesLen + 1;
    component isZero = IsZero();
    isZero.in <== allConditionsAreTrue - conditionsSum;
    out <== isZero.out;
}

// @dev reads CBOR string length
// returns the next position and string length
// input MUST be a byte array
// @param BytesLen - length of the cbor buffer
template ReadStringLength(BytesLen) {
    // i/o signals
    signal input bytes[BytesLen];
    signal input pos;
    signal output len;
    signal output nextPos;

    // read type
    component readType = ReadType(BytesLen);
    copyBytes(bytes, readType.bytes, BytesLen)
    readType.pos <== pos; // 27 bytes initial skip for example MoH pass
    nextPos <== readType.nextPos;
    hardcore_assert(readType.type, MAJOR_TYPE_STRING);

    // read string length
    component dUint = DecodeUint(BytesLen);
    copyBytes(bytes, dUint.bytes, BytesLen)
    dUint.pos <== readType.nextPos;
    dUint.v <== readType.v;
    len <== dUint.value;
}

// @dev reads CBOR map length
// returns the next position and map length
// input MUST be a byte array
// @param BytesLen - length of the cbor buffer
template ReadMapLength(BytesLen) {
    // i/o signals
    signal input pos;
    signal input bytes[BytesLen];
    signal output len;
    signal output nextPos;

    // read type
    component readType = ReadType(BytesLen);
    copyBytes(bytes, readType.bytes, BytesLen)
    readType.pos <== pos; // 27 bytes initial skip for example MoH pass
    nextPos <== readType.nextPos;
    hardcore_assert(readType.type, MAJOR_TYPE_MAP);

    // read map length
    // only supporting maps with 23 or less entries
    component dUint23 = DecodeUint23();
    dUint23.v <== readType.v;
    len <== dUint23.value;
}

// @dev copies over a CBOR string value to a given array `outbytes`
// returns the next position and string length
// input MUST be a byte array
// @param BytesLen - length of the cbor buffer
// @param MaxLen - maximum length of the output array
template CopyString(BytesLen, MaxLen) {

    assert(MaxLen <= BytesLen);

    // i/o signals
    signal input bytes[BytesLen];
    signal input pos;

    signal output outbytes[MaxLen];
    signal output nextPos;
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
        getV[i].pos <== readStrLen.nextPos + i;

        var bits = log2(MaxLen) + 1;
        lt[i] = LessThan(bits);
        lt[i].in[0] <== i;
        lt[i].in[1] <== readStrLen.len;
        outbytes[i] <== getV[i].v * lt[i].out;
    }

    // return
    nextPos <== readStrLen.nextPos + readStrLen.len;
    len <== readStrLen.len;
}