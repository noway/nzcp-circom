pragma circom 2.0.3;

// @dev x raised to the power of y
function pow(x, y) {
    if (y == 0) {
        return 1;
    } else {
        return x * pow(x, y - 1);
    }
}
