pragma circom 2.0.3;


// @dev Take base 2 logarithm of x
function log2(x) {
    var z = -1;
    while (x) {
        z = z + 1;
        x = x \ 2;
    }
    return z;
}
