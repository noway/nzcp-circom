pragma circom 2.0.0;

include "./sha256Var.circom";
include "../circomlib-master/circuits/mux1.circom";
include "../circomlib-master/circuits/mux2.circom";
include "../circomlib-master/circuits/mux3.circom";
include "../circomlib-master/circuits/mux4.circom";

// limited to 2 blocks

function pow(x, y) {
    if (y == 0) {
        return 1;
    } else {
        return x * pow(x, y - 1);
    }
}

template Sha256Any(BlockAddressSpace) {

    var MaxBlockCount = pow(2, BlockAddressSpace);

    var BLOCK_LEN = 512;
    var SHA256_LEN = 256;
    var ALL_BITS = BLOCK_LEN * MaxBlockCount;

    var LenMaxBits = 9 + BlockAddressSpace; // can hold from 2 ^ 10 to 2 ^ 13

    signal input in[ALL_BITS];
    signal input len;
    signal output out[SHA256_LEN];

    component sha256_j_block[MaxBlockCount];
    for (var j = 0; j < MaxBlockCount; j++) {
        var blocks = j + 1;
        sha256_j_block[j] = Sha256Var(blocks);
        // calcualte sha256 as if it was blocks blocks
        sha256_j_block[j].len <== len;
        for (var i = 0; i < BLOCK_LEN * blocks; i++) { sha256_j_block[j].in[i] <== in[i]; }
    }

    signal len_plus_64;
    len_plus_64 <== len + 64;

    component n2b = Num2Bits(LenMaxBits);
    n2b.in <== len_plus_64;
    component shr = ShR(LenMaxBits, 9); // len_plus_64 >> 9
    for (var i = 0; i < LenMaxBits; i++) {
        shr.in[i] <== n2b.out[i];
    }

    // switch between sha256 of blocks based on (len_plus_64 >> 9)
    component mux = MultiMux2(SHA256_LEN);

    for (var j = 0; j < MaxBlockCount; j++) {
        for (var i = 0; i < SHA256_LEN; i++) { mux.c[i][j] <== sha256_j_block[j].out[i]; }
    }
    for (var k = 0; k < BlockAddressSpace; k++) { mux.s[k] <== shr.out[k]; }
    for(var i = 0; i < SHA256_LEN; i++) { out[i] <== mux.out[i]; }


}

