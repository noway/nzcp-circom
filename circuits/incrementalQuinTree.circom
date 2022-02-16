pragma circom 2.0.0;

include "./log2.circom";


// https://github.com/appliedzkp/maci/blob/v1/circuits/circom/trees/calculateTotal.circom
// License: MIT
template NZCPCalculateTotal(n) {
    signal input nums[n];
    signal output sum;

    signal sums[n];
    sums[0] <== nums[0];

    for (var i=1; i < n; i++) {
        sums[i] <== sums[i - 1] + nums[i];
    }

    sum <== sums[n - 1];
}


// https://github.com/appliedzkp/maci/blob/v1/circuits/circom/trees/incrementalQuinTree.circom
// License: MIT
template QuinSelector(choices) {
    signal input in[choices];
    signal input index;
    signal output out;
    
    // Ensure that index < choices
    var bits = log2(choices) + 1;
    log(bits);
    log(choices);
    component lessThan = LessThan(bits); // changed 3 to 9
    lessThan.in[0] <== index;
    lessThan.in[1] <== choices;
    lessThan.out === 1;

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
    out <== sums[choices - 1];
}

// Not checking for overflow
template QuinSelectorUnchecked(choices) {
    signal input in[choices];
    signal input index;
    signal output out;
    
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
    out <== sums[choices - 1];
}