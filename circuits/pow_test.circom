pragma circom 2.0.0;

include "./pow.circom";

template Main() {
    assert(pow(1, 0) == 1);
    assert(pow(1, 1) == 1);
    assert(pow(1, 2) == 1);

    assert(pow(2, 0) == 1);
    assert(pow(2, 1) == 2);
    assert(pow(2, 2) == 4);
    assert(pow(2, 3) == 8);
    assert(pow(2, 4) == 16);
    assert(pow(2, 5) == 32);
    assert(pow(2, 6) == 64);
    assert(pow(2, 7) == 128);
    assert(pow(2, 8) == 256);

    assert(pow(3, 0) == 1);
    assert(pow(3, 1) == 3);
    assert(pow(3, 2) == 9);
    assert(pow(3, 3) == 27);
    assert(pow(3, 4) == 81);
    assert(pow(3, 5) == 243);
    assert(pow(3, 6) == 729);
    assert(pow(3, 7) == 2187);
    assert(pow(3, 8) == 6561);
}


component main = Main();