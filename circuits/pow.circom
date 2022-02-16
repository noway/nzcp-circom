pragma circom 2.0.0;

function NZCPpow(x, y) {
    if (y == 0) {
        return 1;
    } else {
        return x * NZCPpow(x, y - 1);
    }
}
