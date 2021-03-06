pragma circom 2.0.3;

include "./log2.circom";
include "../sha256-var-circom-main/snark-jwt-verify/circuits/calculate_total.circom";


// Based on the following:
// https://github.com/appliedzkp/maci/blob/v1/circuits/circom/trees/incrementalQuinTree.circom
// Optimized + added support for any number of choises
// License: MIT
template QuinSelector(choices) {

    // i/o signals
    signal input in[choices];
    signal input index;
    signal output out;
    
    // Ensure that index < choices
    var bits = log2(choices) + 1;
    component lessThan = LessThan(bits);
    if (choices > 0) {
        lessThan.in[0] <== index;
        lessThan.in[1] <== choices;
        lessThan.out === 1;
    }

    component eqs[choices];
    signal sums[choices];

    // For each item, check whether its index equals the input index.
    for (var i = 0; i < choices; i ++) {
        eqs[i] = IsZero();
        eqs[i].in <== i - index;

        // eqs[i].out is 1 if the index matches. As such, at most one input to
        // out is not 0.
        sums[i] <== i == 0 ? eqs[i].out * in[i] : sums[i - 1] + (eqs[i].out * in[i]);
    }

    // Returns 0 + 0 + ... + item
    out <== choices > 0 ? sums[choices - 1] : 0;
}
