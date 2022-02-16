pragma circom 2.0.0;

include "./log2.circom";

template Main() {
    for (var i = 0; i < 100; i++) {
        var power = pow(2, i);
        assert(log2(power) == i);
    }
}
component main = Main();