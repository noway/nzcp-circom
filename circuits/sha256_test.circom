pragma circom 2.0.0;

include "../snark-jwt-verify-master/circuits/sha256.circom";
include "../circomlib-master/circuits/mux1.circom";

template Sha256Test() {
    signal input in[512];
    signal input len;
    signal output out[256];

    var L_bits = 9;
    var first_pass_count = 512 - L_bits;

    component sha256_unsafe = Sha256_unsafe(1);
    component ie[first_pass_count];
    component mux[first_pass_count];
    for (var i=0; i<first_pass_count; i++) {
        ie[i] = IsEqual();
        ie[i].in[0] <== i;
        ie[i].in[1] <== len * 8;

        mux[i] = Mux1();
        mux[i].c[0] <== in[i];
        mux[i].c[1] <== 1;
        mux[i].s <== ie[i].out;

        sha256_unsafe.in[0][i] <== mux[i].out;
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
