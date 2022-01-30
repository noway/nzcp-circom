pragma circom 2.0.0;

include "./circomlib-master/circuits/sha256/sha256.circom";


/* CBOR types */
#define MAJOR_TYPE_INT 0
#define MAJOR_TYPE_NEGATIVE_INT 1
#define MAJOR_TYPE_BYTES 2
#define MAJOR_TYPE_STRING 3
#define MAJOR_TYPE_ARRAY 4
#define MAJOR_TYPE_MAP 5
#define MAJOR_TYPE_TAG 6
#define MAJOR_TYPE_CONTENT_FREE 7

#define CREDENTIAL_SUBJECT_PATH_LEN 2

#define readType(v,type,buffer,pos) \
    var v = buffer[pos]; \
    var type = v >> 5; \
    pos++;


template NZCP() {





    var ToBeSignedBits = 2512;
    var ToBeSignedBytes = ToBeSignedBits/8;

    signal input a[ToBeSignedBits];
    signal output c[256];
    signal output d;

    var k;

    // component sha256 = Sha256(ToBeSignedBits);

    // for (k=0; k<ToBeSignedBits; k++) {
    //     sha256.in[k] <== a[k];
    // }

    // for (k=0; k<256; k++) {
    //     c[k] <== sha256.out[k];
    // }


    // convert bits to bytes
    signal ToBeSigned[ToBeSignedBytes];
    for (k=0; k<ToBeSignedBytes; k++) {
        var lc1=0;

        var e2 = 1;
        for (var i = 7; i>=0; i--) {
            lc1 += a[k*8+i] * e2;
            e2 = e2 + e2;
        }

        lc1 ==> ToBeSigned[k];
    }

    signal v;
    v <== 168;

    signal type;

    type <-- v >> 5;

    signal check;
    // 0b11100000 = 0xE0
    check <-- v & 0xE0; // 3 upper bits only of v

    signal lower_bits; // we're checking that this can only be LESS THAN 32 (0b00011111)
    lower_bits <-- v - check;

    signal upper_bit_1;
    signal upper_bit_2;
    signal upper_bit_3;
    upper_bit_1 <-- lower_bits & 0x80; // 0b10000000
    upper_bit_2 <-- lower_bits & 0x40; // 0b01000000
    upper_bit_3 <-- lower_bits & 0x20; // 0b00100000
    upper_bit_1 === 0;
    upper_bit_2 === 0;
    upper_bit_3 === 0;

    // Right shift by n bits is the same as division by 2^n
    // 2^5 = 32
    type * 32 === check;


    // TODO: read type as signal (type, pos)

    d <== ToBeSigned[0];

}

component main = NZCP();

