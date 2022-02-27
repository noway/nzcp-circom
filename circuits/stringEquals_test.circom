pragma circom 2.0.3;

include "./cbor.circom";

component main = StringEquals(5, [97, 98, 99, 100, 101], 5);