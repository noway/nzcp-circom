pragma circom 2.0.0;

include "../snark-jwt-verify-master/circuits/sha256.circom";

template Sha256Test() {
    signal input in[512];
    signal input len;
    signal output out[256];

    var L_bits = 9;

    component sha256_unsafe = Sha256_unsafe(1);
    for (var i=0; i<512 - L_bits; i++) {
        sha256_unsafe.in[0][i] <== in[i];
    }
    
    component n2b = Num2Bits(L_bits);
    n2b.in <== len * 8;

    for (var i=512-L_bits; i<512; i++) {
        sha256_unsafe.in[0][i] <== n2b.out[(L_bits - 1) - (i - 512 + L_bits)];
    }
    sha256_unsafe.tBlock <== 1;

    for (var i=0; i<256; i++) {
        out[i] <== sha256_unsafe.out[i];
    }
}
component main = Sha256Test();
