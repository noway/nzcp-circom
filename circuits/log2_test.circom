pragma circom 2.0.0;

include "./log2.circom";
include "./pow.circom";

template Main() {
    // log2
    for (var i = 1; i < 100; i++) {
        var power = NZCPpow(2, i);
        assert(log2(power) == i);
        assert(log2(power + 1) == i);
    }
    assert(log2(1) == 0);
    assert(log2(2) == 1);
    assert(log2(3) == 1);
    assert(log2(4) == 2);
    assert(log2(5) == 2);
    assert(log2(6) == 2);
    assert(log2(7) == 2);
    assert(log2(8) == 3);

    // log2ceil
    for (var i = 1; i < 100; i++) {
        var power = NZCPpow(2, i);
        assert(log2ceil(power) == i);
        assert(log2ceil(power + 1) == i + 1);
    }
    assert(log2ceil(1) == 0);
    assert(log2ceil(2) == 1);
    assert(log2ceil(3) == 2);
    assert(log2ceil(4) == 2);
    assert(log2ceil(5) == 3);
    assert(log2ceil(6) == 3);
    assert(log2ceil(7) == 3);
    assert(log2ceil(8) == 3);

}


component main = Main();