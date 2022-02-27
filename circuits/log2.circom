pragma circom 2.0.0;


// TODO: document
function log2(x) {
    var z = -1;
    while (x) {
        z = z + 1;
        x = x \ 2;
    }
    return z;
}
