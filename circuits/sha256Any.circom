pragma circom 2.0.0;

include "./sha256Var.circom";
include "../circomlib-master/circuits/mux1.circom";
include "../circomlib-master/circuits/mux2.circom";
include "../circomlib-master/circuits/mux3.circom";
include "../circomlib-master/circuits/mux4.circom";

function pow(x, y) {
    if (y == 0) {
        return 1;
    } else {
        return x * pow(x, y - 1);
    }
}

template MultiMultiMux(MuxSpace, n) {
    var MaxVariants = pow(2, MuxSpace);

    signal input in[MaxVariants][n];
    signal input selector[MuxSpace];
    signal output out[n];

    component mux1 = MultiMux1(n);
    component mux2 = MultiMux2(n);
    component mux3 = MultiMux3(n);
    component mux4 = MultiMux4(n);

    if (MuxSpace == 1) {
        for (var j = 0; j < MaxVariants; j++) {
            for (var i = 0; i < n; i++) { mux1.c[i][j] <== in[j][i]; }
        }
        mux1.s <== selector[0];
        for (var i = 0; i < n; i++) { out[i] <== mux1.out[i]; }
    } 
    else if (MuxSpace == 2) {
        for (var j = 0; j < MaxVariants; j++) {
            for (var i = 0; i < n; i++) { mux2.c[i][j] <== in[j][i]; }
        }
        for (var k = 0; k < MuxSpace; k++) { mux2.s[k] <== selector[k]; }
        for (var i = 0; i < n; i++) { out[i] <== mux2.out[i]; }
    }
    else if (MuxSpace == 3) {
        for (var j = 0; j < MaxVariants; j++) {
            for (var i = 0; i < n; i++) { mux3.c[i][j] <== in[j][i]; }
        }
        for (var k = 0; k < MuxSpace; k++) { mux3.s[k] <== selector[k]; }
        for (var i = 0; i < n; i++) { out[i] <== mux3.out[i]; }
    }
    else if (MuxSpace == 4) {
        for (var j = 0; j < MaxVariants; j++) {
            for (var i = 0; i < n; i++) { mux4.c[i][j] <== in[j][i]; }
        }
        for (var k = 0; k < MuxSpace; k++) { mux4.s[k] <== selector[k]; }
        for (var i = 0; i < n; i++) { out[i] <== mux4.out[i]; }
    }
}

template Sha256Any(BlockSpace) {

    var BLOCK_LEN = 512;
    var SHA256_LEN = 256;

    var MaxBlockCount = pow(2, BlockSpace);
    var MaxBits = BLOCK_LEN * MaxBlockCount;
    var LenMaxBits = 9 + BlockSpace; // can hold from 2 ^ 10 to 2 ^ 13

    signal input in[MaxBits];
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

    component mmm = MultiMultiMux(BlockSpace, SHA256_LEN);
    for (var j = 0; j < MaxBlockCount; j++) {
        for (var i = 0; i < SHA256_LEN; i++) { mmm.in[j][i] <== sha256_j_block[j].out[i]; }
    }
    for (var k = 0; k < BlockSpace; k++) { mmm.selector[k] <== shr.out[k]; }
    for(var i = 0; i < SHA256_LEN; i++) { out[i] <== mmm.out[i]; }

}

