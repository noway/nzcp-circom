pragma circom 2.0.0;

include "./circomlib-master/circuits/sha256/sha256.circom";


template Multiplier2() {
    var ToBeSignedLen = 2512;

    signal input a[ToBeSignedLen];
    signal output c[256];

    component sha256 = Sha256(ToBeSignedLen);

    var k;

    for (k=0; k<ToBeSignedLen; k++) {
        sha256.in[k] <== a[k];
    }

    for (k=0; k<256; k++) {
        c[k] <== sha256.out[k];
    }
}

component main = Multiplier2();

