pragma circom 2.0.0;

function pow(x, y) {
    if (y == 0) {
        return 1;
    } else {
        return x * pow(x, y - 1);
    }
}


function log2(x) {
    var z = -1;
    while (x) {
        z = z + 1;
        x = x \ 2;
    }
    return z;
}