pragma circom 2.0.0;

include "./circomlib-master/circuits/sha256/sha256.circom";
include "./circomlib-master/circuits/comparators.circom";
include "./incrementalQuinTree.circom";


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

// usually is 5. TODO: allow for more?
#define MAX_CWT_MAP_LEN 5

/* assert through constraint and assert */
#define hardcore_assert(a, b) a === b; assert(a == b)


// returns the value of v bit shifted to the right by 5 bits
template GetType() {
    // TODO: use Num2Bits?
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

template DecodeUint(ToBeSignedBytes) {
    // TODO: get v as input
    signal input x;
    signal input bytes[ToBeSignedBytes];
    signal input pos;
    signal output value;
    signal output nextpos;


    // if (x <= 23)
    signal value_23;
    value_23 <== x;
    signal nextpos_23;
    nextpos_23 <== pos;

    // if(x == 24)
    component getV_24 = GetV(ToBeSignedBytes);
    for (var j = 0; j < ToBeSignedBytes; j++) {
        getV_24.bytes[j] <== bytes[j];
    }
    getV_24.pos <== pos;
    signal value_24;
    value_24 <== getV_24.v;
    signal nextpos_24;
    nextpos_24 <== pos + 1;

    // if(x == 25)
    component getV1_25 = GetV(ToBeSignedBytes);
    component getV2_25 = GetV(ToBeSignedBytes);
    for (var j = 0; j < ToBeSignedBytes; j++) {
        getV1_25.bytes[j] <== bytes[j];
        getV2_25.bytes[j] <== bytes[j];
    }
    getV1_25.pos <== pos;
    signal value_1_25;
    value_1_25 <== getV1_25.v * 256;

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
    for (var j = 0; j < ToBeSignedBytes; j++) {
        getV1_26.bytes[j] <== bytes[j];
        getV2_26.bytes[j] <== bytes[j];
        getV3_26.bytes[j] <== bytes[j];
        getV4_26.bytes[j] <== bytes[j];
    }
    getV1_26.pos <== pos;
    signal value_1_26;
    value_1_26 <== getV1_26.v * 16777216;

    getV2_26.pos <== pos + 1;
    signal value_2_26;
    value_2_26 <== getV2_26.v * 65536;

    getV3_26.pos <== pos + 2;
    signal value_3_26;
    value_3_26 <== getV3_26.v * 256;

    getV4_26.pos <== pos + 3;
    signal value_4_26;
    value_4_26 <== getV4_26.v;

    signal value_26;
    value_26 <== value_1_26 + value_2_26 + value_3_26 + value_4_26;

    signal nextpos_26;
    nextpos_26 <== pos + 4;


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


    component calculateTotal_value = CalculateTotal(4);
    calculateTotal_value.nums[0] <== condition_23 * value_23;
    calculateTotal_value.nums[1] <== condition_24 * value_24;
    calculateTotal_value.nums[2] <== condition_25 * value_25;
    calculateTotal_value.nums[3] <== condition_26 * value_26;
    value <== calculateTotal_value.sum;

    component calculateTotal_nextpos = CalculateTotal(4);
    calculateTotal_nextpos.nums[0] <== condition_23 * nextpos_23;
    calculateTotal_nextpos.nums[1] <== condition_24 * nextpos_24;
    calculateTotal_nextpos.nums[2] <== condition_25 * nextpos_25;
    calculateTotal_nextpos.nums[3] <== condition_26 * nextpos_26;
    nextpos <== calculateTotal_nextpos.sum;
}

template NZCP() {




    // TODO: dynamic
    var ToBeSignedBits = 2512;
    var ToBeSignedBytes = ToBeSignedBits/8;

    signal input a[ToBeSignedBits];
    signal output c[256];
    signal output d;

    var k;

    // component sha256 = Sha256(ToBeSignedBits);

    // for (k=0; k<ToBeSignedBits; k++) {
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

    var pos;
    pos = 27; // 27 bytes initial skip for example MoH pass

    signal v;

    // GetV(ToBeSignedBytes) (ToBeSigned, pos, v);
    component getV = GetV(ToBeSignedBytes);
    for(k=0; k<ToBeSignedBytes; k++) {
        getV.bytes[k] <== ToBeSigned[k];
    }
    getV.pos <== pos;
    getV.v ==> v;

    log(v);


    signal type;
    component getType = GetType();
    getType.v <== v;
    getType.type ==> type;
    pos++;

    log(type);

    hardcore_assert(type, MAJOR_TYPE_MAP);


    signal x;
    component get5LowerBits = GetX();
    get5LowerBits.v <== v;
    get5LowerBits.x ==> x;

    // TODO: should this be more generic and allow for x more than 23?
    assert(x <= 23); // only supporting maps with 23 or less entries

    signal maplen;
    maplen <== x;


    log(maplen);

    signal mapval_v[MAX_CWT_MAP_LEN];
    signal mapval_type[MAX_CWT_MAP_LEN];
    signal mapval_x[MAX_CWT_MAP_LEN];
    signal mapval_value[MAX_CWT_MAP_LEN];
    component mapval_getV[MAX_CWT_MAP_LEN];
    component mapval_getType[MAX_CWT_MAP_LEN];
    component mapval_getX[MAX_CWT_MAP_LEN];
    component mapval_decodeUint[MAX_CWT_MAP_LEN];

    for (k = 0; k < MAX_CWT_MAP_LEN; k++) { 
        mapval_getV[k] = GetV(ToBeSignedBytes);
        for(var j=0; j<ToBeSignedBytes; j++) {
            mapval_getV[k].bytes[j] <== ToBeSigned[j];
        }
        mapval_getV[k].pos <== pos;
        mapval_getV[k].v ==> mapval_v[k];

        mapval_getType[k] = GetType();
        mapval_getType[k].v <== mapval_v[k];
        mapval_getType[k].type ==> mapval_type[k];

        pos++;



        mapval_getX[k] = GetX();        
        mapval_getX[k].v <== mapval_v[k];
        mapval_getX[k].x ==> mapval_x[k];


        mapval_decodeUint[k] = DecodeUint(ToBeSignedBytes);
        mapval_decodeUint[k].x <== mapval_x[k];
        for(var j=0; j<ToBeSignedBytes; j++) {
            mapval_decodeUint[k].bytes[j] <== ToBeSigned[j];
        }
        mapval_decodeUint[k].pos <== pos;

        mapval_value[k] <== mapval_decodeUint[k].value;


        log(mapval_x[k]);


    }

}

component main = NZCP();

