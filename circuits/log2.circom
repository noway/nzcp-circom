pragma circom 2.0.0;

include "./pow.circom";


function log2(x) {
    var z = -1;
    while (x) {
        z = z + 1;
        x = x \ 2;
    }
    return z;
}

function log2ceil(x) {
    var z = NZCPpow(2, log2(x)) == x ? -1 : 0;
    while (x) {
        z = z + 1;
        x = x \ 2;
    }
    return z;
}