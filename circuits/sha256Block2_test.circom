pragma circom 2.0.0;

include "../snark-jwt-verify-master/circuits/sha256.circom";
include "../circomlib-master/circuits/mux1.circom";

template CopyOverBlock(ToCopyBits) {
    signal input L_pos;
    signal input in[ToCopyBits];
    signal output out[ToCopyBits];

    component ie[ToCopyBits];
    component mux[ToCopyBits];
    for (var i=0; i<ToCopyBits; i++) {
        ie[i] = IsEqual();
        ie[i].in[0] <== i;
        ie[i].in[1] <== L_pos;

        mux[i] = Mux1();
        mux[i].c[0] <== in[i];
        mux[i].c[1] <== 1;
        mux[i].s <== ie[i].out;

        out[i] <== mux[i].out;
    }

}

template Sha256Block2Test() {
    var BLOCK_LEN = 512;
    var SHA256_LEN = 256;
    var BYTE_BITS = 8;
    var L_BITS = 16; // enough bits to hold 1024 value // TODO: try 64 to conform the spec?
    var first_pass_count = BLOCK_LEN - L_BITS;

    signal input in[BLOCK_LEN*2];
    signal input len;
    signal output out[SHA256_LEN];

    component sha256_unsafe = Sha256_unsafe(2);

    component cob1 = CopyOverBlock(BLOCK_LEN);
    cob1.L_pos <== len * BYTE_BITS;
    for (var i=0; i<BLOCK_LEN; i++) { cob1.in[i] <== in[i]; }
    for (var i=0; i<BLOCK_LEN; i++) { sha256_unsafe.in[0][i] <== cob1.out[i]; }
    
    component cob2 = CopyOverBlock(first_pass_count);
    cob2.L_pos <== len * BYTE_BITS;
    for (var i=0; i<first_pass_count; i++) { cob2.in[i] <== in[i + BLOCK_LEN]; }
    for (var i=0; i<first_pass_count; i++) { sha256_unsafe.in[1][i] <== cob2.out[i]; }
    

    // // copy over the block 1
    // for (var i=0; i<BLOCK_LEN; i++) {
    //     sha256_unsafe.in[0][i] <== in[i];
    // }
    
    // // copy over the block 2
    // component ie[first_pass_count];
    // component mux[first_pass_count];
    // for (var i=0; i<first_pass_count; i++) {
    //     ie[i] = IsEqual();
    //     ie[i].in[0] <== i;
    //     ie[i].in[1] <== len * BYTE_BITS;

    //     mux[i] = Mux1();
    //     mux[i].c[0] <== in[i + BLOCK_LEN /*skip first block*/];
    //     mux[i].c[1] <== 1;
    //     mux[i].s <== ie[i].out;

    //     sha256_unsafe.in[1][i] <== mux[i].out;
    // }
    
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
