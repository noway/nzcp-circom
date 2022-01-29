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


#define _decodeUint(value,buffer,pos,v,x) \
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
#define decodeUint(value,buffer,pos,v) _decodeUint(value,buffer,pos,v,x##__COUNTER__) 
// TODO: else statement above is UnexpectedCBORType

function skipValueScalar(buffer, pos) {
    readType(v,cbortype,buffer,pos)

    if (cbortype == MAJOR_TYPE_INT) {
        decodeUint(value,buffer,pos,v)
        return pos;
    }
    else if (cbortype == MAJOR_TYPE_STRING) {
        decodeUint(value,buffer,pos,v)
        return pos + value;
    }
    else {
        // TODO: UnexpectedCBORType error
        log(666);
        return pos;
    }
}

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
        for (var i = 0; i < value; i++) {
            // we support only 1 level of deepness
            pos = skipValueScalar(buffer, pos);
        }
        return pos;
    }
    else {
        // TODO: UnexpectedCBORType error
        log(6667);
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

    var pos;
    pos = 27; // 27 bytes to skip;

    var j = 0;
    var credentialSubjectPosition;


    readType(v,type,ToBeSigned,pos)
    assert(type == MAJOR_TYPE_MAP);
    decodeUint(maplen,ToBeSigned,pos,v)

    // This is so bad lmao
    // TODO: idk why maplen - 1, fix?
    var maplen_actual = maplen - 1;

    for (k=0; k < maplen_actual; k++) { 
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
            if (strcmp(ToBeSigned, pos, vc_str, value) == 0) {
                pos += value;
                log(42);
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




    readType(v2,type2,ToBeSigned,pos)
    assert(type2 == MAJOR_TYPE_MAP);
    decodeUint(maplen2,ToBeSigned,pos,v2)

    maplen_actual = maplen2;

    for (k=0; k < maplen_actual; k++) { 
        readType(v2,cbortype,ToBeSigned,pos)
        decodeUint(value,ToBeSigned,pos,v2)
        if (cbortype == MAJOR_TYPE_INT) {
            if (value == 4) {
                readType(v2,cbortype,ToBeSigned,pos)
                decodeUint(exp,ToBeSigned,pos,v2)
                // Got expiration date
                log(exp);
            }
            else {
                pos = skipValue(ToBeSigned, pos);
            }            
        }
        else if (cbortype == MAJOR_TYPE_STRING) {
            if (strcmp(ToBeSigned, pos, credentialSubject_str, value) == 0) {
                pos += value;
                credentialSubjectPosition = pos;
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


    log(credentialSubjectPosition);

    d <== ToBeSigned[0];

}

component main = NZCP();

