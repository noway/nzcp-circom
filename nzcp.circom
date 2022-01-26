pragma circom 2.0.0;

include "./circomlib-master/circuits/sha256/sha256.circom";


function readType(a) {
    // return (input >> 5, input);
    return a >> 5;
}

template NZCP() {
    var MAJOR_TYPE_MAP = 5; // constnat
    var ToBeSignedBits = 2512;
    var ToBeSignedBytes = ToBeSignedBits/8;

    signal input a[ToBeSignedBits];
    signal output c[256];

    // component sha256 = Sha256(ToBeSignedBits);

    var k;

    // for (k=0; k<ToBeSignedBits; k++) {
    //     sha256.in[k] <== a[k];
    // }

    // for (k=0; k<256; k++) {
    //     c[k] <== sha256.out[k];
    // }


    var ToBeSigned[ToBeSignedBytes];
    for (k=0; k<ToBeSignedBytes; k++) {
        ToBeSigned[k] = a[k*8+7] * 1 | a[k*8+6] * 2 | a[k*8+5] * 4 | a[k*8+4] * 8 | a[k*8+3] * 16 | a[k*8+2] * 32 | a[k*8+1] * 64 | a[k*8+0] * 128;
    }

    var pos;
    pos = 27; // 27 bytes to skip;

    // for (k=pos; k<ToBeSignedBytes - pos; k++) {
    //     // ToBeSigned[k] = a[k*8+7] * 1 | a[k*8+6] * 2 | a[k*8+5] * 4 | a[k*8+4] * 8 | a[k*8+3] * 16 | a[k*8+2] * 32 | a[k*8+1] * 64 | a[k*8+0] * 128;
    //     log(ToBeSigned[k]);
    //     // log(a[k*8+0]);
    // }

    var type = readType(ToBeSigned[pos]);
    pos++;
    assert(type == MAJOR_TYPE_MAP);
    log(type);
    // if (

}

component main = NZCP();

