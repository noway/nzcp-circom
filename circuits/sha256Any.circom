pragma circom 2.0.0;

include "./sha256Var.circom";

// limited to 2 blocks
template Sha256Any() {

    var BLOCK_LEN = 512;
    var MAX_BLOCK_COUNT = 2;
    var SHA256_LEN = 256;
    var ALL_BITS = BLOCK_LEN * MAX_BLOCK_COUNT;

    var LEN_MAX_BITS = 10; // can hold up to 1024 value

    signal input in[ALL_BITS];
    signal input len;
    signal output out[SHA256_LEN];

    // calcualte sha256 as if it was 1 block
    component sha256_1block = Sha256Var(1);
    sha256_1block.len <== len;
    for (var i = 0; i < BLOCK_LEN * 1; i++) { sha256_1block.in[i] <== in[i]; }

    // calcualte sha256 as if it was 2 blocks
    component sha256_2block = Sha256Var(2);
    sha256_2block.len <== len;
    for (var i = 0; i < BLOCK_LEN * 2; i++) { sha256_2block.in[i] <== in[i]; }

    component mux1 = MultiMux1(SHA256_LEN);
    for(var i = 0; i < SHA256_LEN; i++) {
        mux1.c[i][0] <== sha256_1block.out[i];
        mux1.c[i][1] <== sha256_2block.out[i];
    }

    signal len_plus_64;
    len_plus_64 <== len + 64;

    component n2b = Num2Bits(LEN_MAX_BITS);
    n2b.in <== len_plus_64;
    component shr = ShR(LEN_MAX_BITS, 9); // len_plus_64 >> 9
    for (var i = 0; i < LEN_MAX_BITS; i++) {
        shr.in[i] <== n2b.out[i];
    }

    log(42);
    mux1.s <== shr.out[0];
    log(mux1.s);
    for(var i = 0; i < SHA256_LEN; i++) {
        out[i] <== mux1.out[i];
    }


}

