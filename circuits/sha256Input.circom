pragma circom 2.0.0;

include "../snark-jwt-verify-master/circuits/sha256.circom";
include "../circomlib-master/circuits/mux1.circom";

// Copy over 1 block of sha256 input
// Sets bit to 1 at L_pos
template CopyOverBlock(ToCopyBits) {
    signal input L_pos;
    signal input in[ToCopyBits];
    signal output out[ToCopyBits];

    component ie[ToCopyBits];
    component mux[ToCopyBits];
    for (var i = 0; i < ToCopyBits; i++) {
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

// Prepare sha256 input for Sha256_unsafe as if it had BlockCount blocks
template Sha256Input(BlockCount) {

    // constants
    var BLOCK_LEN = 512;
    var L_BITS = 64;

    // variables
    var PreLBlockLen = BLOCK_LEN - L_BITS;

    // signas
    signal input in[BLOCK_LEN * BlockCount];
    signal input len;
    signal output out[BLOCK_LEN * BlockCount];

    // copy over blocks
    component cob[BlockCount];
    for(var j = 0; j < BlockCount; j++) {
        var offset = j * BLOCK_LEN;
        if (j < BlockCount - 1) {
            // copy over block number j
            cob[j] = CopyOverBlock(BLOCK_LEN);
            cob[j].L_pos <== len - offset;
            for (var i = 0; i < BLOCK_LEN; i++) { cob[j].in[i] <== in[offset + i]; }
            for (var i = 0; i < BLOCK_LEN; i++) { out[j * BLOCK_LEN + i] <== cob[j].out[i]; }
        }
        else {
            // copy over pre-L block (last block before L)
            // this block is clipped because 64 bits are reserved for L
            cob[j] = CopyOverBlock(PreLBlockLen);
            cob[j].L_pos <== len - offset;
            for (var i = 0; i < PreLBlockLen; i++) { cob[j].in[i] <== in[offset + i]; }
            for (var i = 0; i < PreLBlockLen; i++) { out[j * BLOCK_LEN + i] <== cob[j].out[i]; }
        }
    }

    // add L
    component n2b = Num2Bits(L_BITS);
    n2b.in <== len;
    for (var i = PreLBlockLen; i < BLOCK_LEN; i++) {
        out[(BlockCount - 1) * BLOCK_LEN + i] <== n2b.out[BLOCK_LEN - 1 - i];
    }
}