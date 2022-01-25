pragma circom 2.0.0;

include "./circomlib-master/circuits/sha256/sha256.circom";


template NZCP() {
    var ToBeSignedBits = 2512;
    var ToBeSignedBytes = ToBeSignedBits/8;

    signal input a[ToBeSignedBits];
    signal output c[256];

    component sha256 = Sha256(ToBeSignedBits);

    var k;

    for (k=0; k<ToBeSignedBits; k++) {
        sha256.in[k] <== a[k];
    }

    for (k=0; k<256; k++) {
        c[k] <== sha256.out[k];
    }
}

component main = NZCP();

