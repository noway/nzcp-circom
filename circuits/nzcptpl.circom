pragma circom 2.0.0;

include "../circomlib-master/circuits/sha256/sha256.circom";
include "../circomlib-master/circuits/comparators.circom";
include "./incrementalQuinTree.circom";
include "./cbor.circom";

// TODO: only use <== not ==>

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

/* assign bytes to a signal in one go */
#define copyBytes(b, a) for(var z = 0; z<ToBeSignedBytes; z++) { a.bytes[z] <== b[z]; }


template FindMapKey(ToBeSignedBytes, ConstBytes, ConstBytesLen) {
    signal input maplen;
    signal input bytes[ToBeSignedBytes];
    signal input pos;

    signal output nextpos;


    signal mapval_v[MAX_CWT_MAP_LEN];
    signal mapval_type[MAX_CWT_MAP_LEN];
    signal mapval_value[MAX_CWT_MAP_LEN];
    signal mapval_isVC[MAX_CWT_MAP_LEN];
    signal mapval_isAccepted[MAX_CWT_MAP_LEN];

    component mapval_readType[MAX_CWT_MAP_LEN];
    component mapval_decodeUint[MAX_CWT_MAP_LEN];
    component mapval_skipValue[MAX_CWT_MAP_LEN];
    component mapval_isString[MAX_CWT_MAP_LEN];
    component mapval_isVCString[MAX_CWT_MAP_LEN];
    component mapval_withinMaplen[MAX_CWT_MAP_LEN];

    signal pos_loop_1[MAX_CWT_MAP_LEN]; // TODO: better variable names?
    signal pos_loop_2[MAX_CWT_MAP_LEN];
    signal pos_loop_3[MAX_CWT_MAP_LEN];

    component calculateTotal_vc_pos = CalculateTotal(MAX_CWT_MAP_LEN);
    signal vc_pos;

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

        // skip value for next iteration
        mapval_skipValue[k] = SkipValue(ToBeSignedBytes);
        mapval_skipValue[k].pos <== pos_loop_3[k];
        copyBytes(bytes, mapval_skipValue[k])
        if (k != MAX_CWT_MAP_LEN - 1) {
            pos_loop_1[k + 1] <== mapval_skipValue[k].finalpos;
        }

        // is current value a string?
        mapval_isString[k] = IsEqual();
        mapval_isString[k].in[0] <== mapval_type[k];
        mapval_isString[k].in[1] <== MAJOR_TYPE_STRING;

        // is current value interpreted as a string is a "vc" string?
        mapval_isVCString[k] = StringEquals(ToBeSignedBytes, ConstBytes, ConstBytesLen);
        copyBytes(bytes, mapval_isVCString[k])
        mapval_isVCString[k].pos <== pos_loop_3[k]; // pos before skipping
        mapval_isVCString[k].len <== mapval_value[k];

        mapval_withinMaplen[k] = LessThan(8);
        mapval_withinMaplen[k].in[0] <== k;
        mapval_withinMaplen[k].in[1] <== maplen;

        // is current value a "vc" string?
        mapval_isVC[k] <== mapval_isString[k].out * mapval_isVCString[k].out;

        // should we select this vc pos candidate?
        mapval_isAccepted[k] <== mapval_isVC[k] * mapval_withinMaplen[k].out;

        // put a vc pos candidate into CalculateTotal to be able to get vc pos outside of the loop
        calculateTotal_vc_pos.nums[k] <== mapval_isAccepted[k] * (pos_loop_3[k] + mapval_value[k]);
    }
    calculateTotal_vc_pos.sum ==> vc_pos;

    nextpos <== vc_pos;
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

    component getV = GetV(ToBeSignedBytes);
    copyBytes(ToBeSigned, getV)
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
    component getX = GetX();
    getX.v <== v;
    getX.x ==> x;

    // TODO: should this be more generic and allow for x more than 23?
    assert(x <= 23); // only supporting maps with 23 or less entries

    signal maplen;
    maplen <== x;


    log(maplen);

    signal vc_pos;
    component findVC = FindMapKey(ToBeSignedBytes, [118, 99], 2);
    copyBytes(ToBeSigned, findVC)
    findVC.pos <== pos;
    findVC.maplen <== maplen;
    vc_pos <== findVC.nextpos;


    log(vc_pos);

}

component main = NZCP();

