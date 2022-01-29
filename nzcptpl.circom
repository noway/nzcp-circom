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


#define decodeUint(value,buffer,pos,v) \
    var x = v & 31; \
    var value; \
    if (x <= 23) { \
        value = x; \
    } \
    else if (x == 24) { \
        value = buffer[pos]; \
        pos++; \
    } \
    else if (x == 25) { \
        value = buffer[pos] << 8; \
        pos++; \
        value |= buffer[pos]; \
        pos++; \
    } \
    else if (x == 26) { \
        value = buffer[pos] << 24; \
        pos++; \
        value |= buffer[pos] << 16; \
        pos++; \
        value |= buffer[pos] << 8; \
        pos++; \
        value |= buffer[pos]; \
        pos++; \
    } \
    else { \
        value = 0; \
    }
// TODO: else statement above is UnexpectedCBORType

function skipValue(buffer, pos) {
    readType(v,cbortype,buffer,pos)

    if (cbortype == MAJOR_TYPE_INT) {
        decodeUint(value,buffer,pos,v)
        return pos;
    }
    else if (cbortype == MAJOR_TYPE_STRING) {
        decodeUint(value,buffer,pos,v)
        return pos + value;
    }
    else if (cbortype == MAJOR_TYPE_ARRAY) {
        decodeUint(value,buffer,pos,v)
        log(4000);
        for (var i = 0; i < value; i++) {
            // TODO: need to fix this to proceed
            // pos = skipValue(buffer, pos);
        }
        return pos;
    }
    else {
        // TODO: UnexpectedCBORType error
        return pos;
    }
}
function strcmp(buffer, pos, str2, len) {
    var i = 0;
    for (i = 0; i < len; i++) {
        if (buffer[pos + i] != str2[i]) {
            return -1;
        }
    }
    return 0;
}

template NZCP() {


    #define VC_LEN 2
    var vc_str[VC_LEN] = [118, 99];

    #define CREDENTIAL_SUBJECT_LEN 17
    var credentialSubject_str[CREDENTIAL_SUBJECT_LEN] = [99, 114, 101, 100, 101, 110, 116, 105, 97, 108, 83, 117, 98, 106, 101, 99, 116];


    var ToBeSignedBits = 2512;
    var ToBeSignedBytes = ToBeSignedBits/8;

    signal input a[ToBeSignedBits];
    signal output c[256];

    var k;

    // component sha256 = Sha256(ToBeSignedBits);

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

    var j = 0;
    for (j = 0; j < CREDENTIAL_SUBJECT_PATH_LEN; j++) {

        readType(v,type,ToBeSigned,pos)

        

        assert(type == MAJOR_TYPE_MAP);

        decodeUint(maplen,ToBeSigned,pos,v)

        for (k=0; k<maplen-1; k++) { // TODO: idk why maplen - 1, fix?
            readType(v,cbortype,ToBeSigned,pos)


            decodeUint(value,ToBeSigned,pos,v)

            if (cbortype == MAJOR_TYPE_INT) {
                if (value == 4) {
                    readType(v,cbortype,ToBeSigned,pos)
                    decodeUint(exp,ToBeSigned,pos,v)
                    // Got expiration date
                    log(exp);
                }
                else {
                    pos = skipValue(ToBeSigned, pos);
                }            
            }
            else if (cbortype == MAJOR_TYPE_STRING) {

                if (j == 0 && strcmp(ToBeSigned, pos, vc_str, value) == 0) {
                    pos += value;
                    log(42);
                }
                else if (j == 1 && strcmp(ToBeSigned, pos, credentialSubject_str, value) == 0) {
                    pos += value;
                    log(69);
                }
                else {
                    pos += value;
                    pos = skipValue(ToBeSigned, pos);
                }
                

            }
            else {
                // assert(0); // UnsupportedCBORUint
            }

        }
    }

}

component main = NZCP();

