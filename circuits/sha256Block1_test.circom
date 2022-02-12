pragma circom 2.0.0;

// include "../snark-jwt-verify-master/circuits/sha256.circom";
// include "../circomlib-master/circuits/mux1.circom";

include "./sha256Var.circom";

/*
template Sha256Block1Test() {
    var BLOCK_LEN = 512;
    var SHA256_LEN = 256;
    var BYTE_BITS = 8;
    var L_BITS = 9; // enough bits to hold 512 value
    var first_pass_count = BLOCK_LEN - L_BITS;

    signal input in[BLOCK_LEN];
    signal input len;
    signal output out[SHA256_LEN];

    // copy over the block
    component sha256_unsafe = Sha256_unsafe(1);
    component ie[first_pass_count];
    component mux[first_pass_count];
    for (var i=0; i<first_pass_count; i++) {
        ie[i] = IsEqual();
        ie[i].in[0] <== i;
        ie[i].in[1] <== len * BYTE_BITS;

        mux[i] = Mux1();
        mux[i].c[0] <== in[i];
        mux[i].c[1] <== 1;
        mux[i].s <== ie[i].out;

        sha256_unsafe.in[0][i] <== mux[i].out;
    }
    
    // add L
    component n2b = Num2Bits(L_BITS);
    n2b.in <== len * BYTE_BITS;
    for (var i=first_pass_count; i<BLOCK_LEN; i++) {
        sha256_unsafe.in[0][i] <== n2b.out[BLOCK_LEN - 1 - i];
    }
    sha256_unsafe.tBlock <== 1;

    // export
    for (var i=0; i<SHA256_LEN; i++) {
        out[i] <== sha256_unsafe.out[i];
    }
}
*/
component main = Sha256Var(1);
