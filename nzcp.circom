pragma circom 2.0.0;

include "./circomlib-master/circuits/sha256/sha256.circom";


function readType(v) {
    return v >> 5;
}

function decodeUint(buffer, pos, v)  {
    var x = v & 31;
    if (x <= 23) {
        return x;
    }
    else if (x == 24) {
        var value = buffer[pos];
        pos++;
        return value;
    }
    // Commented out to save gas
    // else if (x == 25) { // 16-bit
    //     var value;
    //     value = uint8(buffer[pos++]) << 8;
    //     value |= uint8(buffer[pos++]);
    //     return (pos, value);
    // }
    else if (x == 26) { // 32-bit
        var value;
        value = buffer[pos] << 24;
        pos++;
        value |= buffer[pos] << 16;
        pos++;
        value |= buffer[pos] << 8;
        pos++;
        value |= buffer[pos];
        pos++;
        return value;
    }
    else {
        // assert(0); // UnsupportedCBORUint
        return 0;
    }
}


template NZCP() {
    var MAJOR_TYPE_INT = 0; // constnat
    var MAJOR_TYPE_NEGATIVE_INT = 1; // constnat
    var MAJOR_TYPE_BYTES = 2; // constnat
    var MAJOR_TYPE_STRING = 3; // constant
    var MAJOR_TYPE_ARRAY = 4; // constant
    var MAJOR_TYPE_MAP = 5; // constnat
    var ToBeSignedBits = 2512;
    var ToBeSignedBytes = ToBeSignedBits/8;

    signal input a[ToBeSignedBits];
    signal output c[256];

    // component sha256 = Sha256(ToBeSignedBits);

    var k;

    // for (k=0; k<ToBeSignedBits; k++) {
    //     sha256.in[k] <== a[k];
    // }

    // for (k=0; k<256; k++) {
    //     c[k] <== sha256.out[k];
    // }


    var ToBeSigned[ToBeSignedBytes];
    for (k=0; k<ToBeSignedBytes; k++) {
        ToBeSigned[k] = a[k*8+7] * 1 | a[k*8+6] * 2 | a[k*8+5] * 4 | a[k*8+4] * 8 | a[k*8+3] * 16 | a[k*8+2] * 32 | a[k*8+1] * 64 | a[k*8+0] * 128;
    }

    var pos;
    pos = 27; // 27 bytes to skip;

    // for (k=pos; k<ToBeSignedBytes - pos; k++) {
    //     // ToBeSigned[k] = a[k*8+7] * 1 | a[k*8+6] * 2 | a[k*8+5] * 4 | a[k*8+4] * 8 | a[k*8+3] * 16 | a[k*8+2] * 32 | a[k*8+1] * 64 | a[k*8+0] * 128;
    //     log(ToBeSigned[k]);
    // }


    var v = ToBeSigned[pos];
    var type = readType(v);
    pos++;

    assert(type == MAJOR_TYPE_MAP);

    var maplen = decodeUint(ToBeSigned, pos, v);

    for (k=0; k<maplen; k++) {
        // (uint cbortype, uint v) = readType(stream);
        var v = ToBeSigned[pos];
        pos++;
        var cbortype = readType(v);
        log(cbortype);

        if (cbortype == MAJOR_TYPE_INT) {

        }
        else if (cbortype == MAJOR_TYPE_STRING) {

        }
        else {
            // assert(0); // UnsupportedCBORUint
        }

    }

}

component main = NZCP();

