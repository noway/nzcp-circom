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
    component mapval_getV[MAX_CWT_MAP_LEN];

    for (k = 0; k < MAX_CWT_MAP_LEN; k++) { 
        mapval_getV[k] = GetV(ToBeSignedBytes);
        for(var j=0; j<ToBeSignedBytes; j++) {
            mapval_getV[k].bytes[j] <== ToBeSigned[j];
        }
        mapval_getV[k].pos <== pos;
        mapval_getV[k].v ==> mapval_v[k];
        log(mapval_v[k]);


        pos++;
    }

}

component main = NZCP();

