pragma circom 2.0.0;

include "../snark-jwt-verify-master/circuits/sha256.circom";
include "../circomlib-master/circuits/mux1.circom";

template Sha256Block2Test() {
    var BLOCK_LEN = 512;
    var SHA256_LEN = 256;
    var BYTE_BITS = 8;
    var L_BITS = 16; // enough bits to hold 1024 value // TODO: try 64 to conform the spec?
    var first_pass_count = BLOCK_LEN - L_BITS;

    signal input in[BLOCK_LEN*2];
    signal input len;
    signal output out[SHA256_LEN];

    // copy over the block 1
    component sha256_unsafe = Sha256_unsafe(2);
    for (var i=0; i<BLOCK_LEN; i++) {
        sha256_unsafe.in[0][i] <== in[i];
    }
    
    // copy over the block 2
    component ie[first_pass_count];
    component mux[first_pass_count];
    for (var i=0; i<first_pass_count; i++) {
        ie[i] = IsEqual();
        ie[i].in[0] <== i;
        ie[i].in[1] <== len * BYTE_BITS;

        mux[i] = Mux1();
        mux[i].c[0] <== in[i + BLOCK_LEN /*skip first block*/];
        mux[i].c[1] <== 1;
        mux[i].s <== ie[i].out;

        sha256_unsafe.in[1][i] <== mux[i].out;
    }
    
    // add L
    component n2b = Num2Bits(L_BITS);
    n2b.in <== len * BYTE_BITS;
    for (var i=first_pass_count; i<BLOCK_LEN; i++) {
        sha256_unsafe.in[1][i] <== n2b.out[BLOCK_LEN - 1 - i];
    }
    sha256_unsafe.tBlock <== 2;

    // export
    for (var i=0; i<SHA256_LEN; i++) {
        out[i] <== sha256_unsafe.out[i];
    }
}
component main = Sha256Block2Test();
