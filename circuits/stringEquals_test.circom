pragma circom 2.0.0;

include "./cbor.circom";

component main = StringEquals(5, [97, 98, 99, 100, 101], 5);