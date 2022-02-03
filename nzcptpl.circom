pragma circom 2.0.0;

include "./circomlib-master/circuits/sha256/sha256.circom";
include "./circomlib-master/circuits/comparators.circom";
include "./incrementalQuinTree.circom";
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

#define CREDENTIAL_SUBJECT_PATH_LEN 2

// usually is 5. TODO: allow for more?
#define MAX_CWT_MAP_LEN 5

/* assert through constraint and assert */
#define hardcore_assert(a, b) a === b; assert(a == b)

/* assign bytes to a signal in one go */
#define copyBytes(b, a) for(var i = 0; i<ToBeSignedBytes; i++) { a.bytes[i] <== b[i]; }


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
        copyBytes(ToBeSigned, mapval_getV[k])
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
        copyBytes(ToBeSigned, mapval_decodeUint[k])
        mapval_decodeUint[k].pos <== pos;

        mapval_value[k] <== mapval_decodeUint[k].value;


        log(mapval_value[k]);


    }

}

component main = NZCP();

