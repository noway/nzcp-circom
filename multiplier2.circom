pragma circom 2.0.0;

include "./circomlib-master/circuits/sha256/sha256.circom";


template Multiplier2() {
    signal input a[2512];
    signal output c[256];

    component sha256 = Sha256(2512);

    var k;

    for (k=0; k<2512; k++) {
        sha256.in[k] <== a[k];
    }


    // sha256.in <== a;

    // c <== sha256.out;

    for (k=0; k<256; k++) {
        c[k] <== sha256.out[k];
    }
}

component main = Multiplier2();

