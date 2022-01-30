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

    // TODO: are we sure that type,three_upper_bits,upper_bit_1,upper_bit_2,upper_bit_3 are 8 bits?
    signal type;

    // assign `type` signal
    // shift 0bXXXYYYYY to 0b00000XXX
    // v is a trusted signal
    type <-- v >> 5;

    // prepare constraint checking for `type`
    signal three_upper_bits;
    // 0b11100000 = 0xE0
    // v is trusted signal
    three_upper_bits <-- v & 0xE0; // 3 upper bits of v (0bXXX00000). v can only be 8 bits.

    // should_only_be_lower_bits is 0b000YYYYY
    // we get it by 0bXXXYYYYY - 0bXXX00000 to get 0b000YYYYY
    var should_only_be_lower_bits = v - three_upper_bits;
    // we're checking that should_only_be_lower_bits can only be LESS THAN 32 (0b00011111)
    // that verifies that three_upper_bits are pristine and were not messed with.
    // if someone were to mess with three_upper_bits, should_only_be_lower_bits would contain higher bits
    // and be more than 32 (0b00011111).
    // by doing that, we cryptographically assert that should_only_be_lower_bits is in the form of 0b000YYYYY
    signal upper_bit_1;
    signal upper_bit_2;
    signal upper_bit_3;
    upper_bit_1 <-- should_only_be_lower_bits & 0x80; // 0b10000000. This signal can be 0bX0000000
    upper_bit_2 <-- should_only_be_lower_bits & 0x40; // 0b01000000. This signal can be 0b0X000000
    upper_bit_3 <-- should_only_be_lower_bits & 0x20; // 0b00100000. This signal can be 0b00X00000
    upper_bit_1 === 0; // Assert that 0bX0000000 is 0b00000000
    upper_bit_2 === 0; // Assert that 0b0X000000 is 0b00000000
    upper_bit_3 === 0; // Assert that 0b00X00000 is 0b00000000

    // generate constraint for type signal
    // 2^5 = 32
    type * 32 === three_upper_bits;


    // TODO: read type as signal (type, pos)

    d <== ToBeSigned[0];

}

component main = NZCP();

