pragma circom 2.0.0;

include "../sha256-var-circom-main/snark-jwt-verify/circomlib/circuits/comparators.circom";
include "./quinSelector.circom";

component main = QuinSelector(1);