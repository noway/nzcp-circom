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

template Sha256Block2Test(BlockCount) {
    var BLOCK_LEN = 512;
    var SHA256_LEN = 256;
    var BYTE_BITS = 8;
    var L_BITS = 64;
    var prelast_pass_count = BLOCK_LEN - L_BITS;

    signal input in[BLOCK_LEN * BlockCount];
    signal input len;
    signal output out[SHA256_LEN];

    component sha256_unsafe = Sha256_unsafe(BlockCount);

    component cob[BlockCount];
    for(var j = 0; j < BlockCount; j++) {
        var offset = j * BLOCK_LEN;
        if (j < BlockCount - 1) {
            // copy over block j + 1
            cob[j] = CopyOverBlock(BLOCK_LEN);
            cob[j].L_pos <== len * BYTE_BITS - offset;
            for (var i=0; i<BLOCK_LEN; i++) { cob[j].in[i] <== in[offset + i]; }
            for (var i=0; i<BLOCK_LEN; i++) { sha256_unsafe.in[j][i] <== cob[j].out[i]; }
        }
        else {
            // copy over last block
            cob[j] = CopyOverBlock(prelast_pass_count);
            cob[j].L_pos <== len * BYTE_BITS - offset;
            for (var i=0; i<prelast_pass_count; i++) { cob[j].in[i] <== in[offset + i]; }
            for (var i=0; i<prelast_pass_count; i++) { sha256_unsafe.in[j][i] <== cob[j].out[i]; }
        }
    }

    
    
    // add L
    component n2b = Num2Bits(L_BITS);
    n2b.in <== len * BYTE_BITS;
    for (var i=prelast_pass_count; i<BLOCK_LEN; i++) {
        sha256_unsafe.in[BlockCount - 1][i] <== n2b.out[BLOCK_LEN - 1 - i];
    }
    sha256_unsafe.tBlock <== BlockCount;

    // export
    for (var i=0; i<SHA256_LEN; i++) {
        out[i] <== sha256_unsafe.out[i];
    }
}
component main = Sha256Block2Test(2);
