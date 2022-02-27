const chai = require("chai");
const { wasm: wasm_tester } = require("circom_tester");
const chaiAsPromised = require("chai-as-promised");
chai.use(chaiAsPromised);
const { assert } = chai;

describe("CBOR getType", function () {
    let cir
    before(async () => {
        cir = await wasm_tester(`${__dirname}/../circuits/getType_test.circom`);
    })
    it ("getType(v) == v >> 5", async () => {
        // exhaustive test for 8 bits
        for (let v = 255; v >= 0; v--) {
            const witness = await cir.calculateWitness({ "v": v }, true);
            assert.equal(witness[1], v >> 5);
        }
    });
});

describe("CBOR getX", function () {
    let cir
    before(async () => {
        cir = await wasm_tester(`${__dirname}/../circuits/getX_test.circom`);
    })
    it ("getX(v) == v & 31", async () => {
        // exhaustive test for 8 bits
        for (let v = 255; v >= 0; v--) {
            const witness = await cir.calculateWitness({ "v": v }, true);
            assert.equal(witness[1], v & 31);
        }
    });
});

describe("CBOR getV(3)", function () {
    let cir
    before(async () => {
        cir = await wasm_tester(`${__dirname}/../circuits/getV3_test.circom`);
    })
    it ("getV([1, 2, 3], 0) == 1", async () => {
        const witness = await cir.calculateWitness({ "bytes": [1, 2, 3], pos: 0 }, true);
        assert.equal(witness[1], 1);
    });
    it ("getV([1, 2, 3], 1) == 2", async () => {
        const witness = await cir.calculateWitness({ "bytes": [1, 2, 3], pos: 1 }, true);
        assert.equal(witness[1], 2);
    });
    it ("getV([1, 2, 3], 2) == 3", async () => {
        const witness = await cir.calculateWitness({ "bytes": [1, 2, 3], pos: 2 }, true);
        assert.equal(witness[1], 3);
    });
});

describe("CBOR getV(4)", function () {
    let cir
    before(async () => {
        cir = await wasm_tester(`${__dirname}/../circuits/getV4_test.circom`);
    })
    it ("getV([1, 2, 3, 4], 0) == 1", async () => {
        const witness = await cir.calculateWitness({ "bytes": [1, 2, 3, 4], pos: 0 }, true);
        assert.equal(witness[1], 1);
    });
    it ("getV([1, 2, 3, 4], 1) == 2", async () => {
        const witness = await cir.calculateWitness({ "bytes": [1, 2, 3, 4], pos: 1 }, true);
        assert.equal(witness[1], 2);
    });
    it ("getV([1, 2, 3, 4], 2) == 3", async () => {
        const witness = await cir.calculateWitness({ "bytes": [1, 2, 3, 4], pos: 2 }, true);
        assert.equal(witness[1], 3);
    });
    it ("getV([1, 2, 3, 4], 3) == 4", async () => {
        const witness = await cir.calculateWitness({ "bytes": [1, 2, 3, 4], pos: 3 }, true);
        assert.equal(witness[1], 4);
    });
});

describe("CBOR getV(5)", function () {
    let cir
    before(async () => {
        cir = await wasm_tester(`${__dirname}/../circuits/getV5_test.circom`);
    })
    it ("getV([1, 2, 3, 4, 5], 0) == 1", async () => {
        const witness = await cir.calculateWitness({ "bytes": [1, 2, 3, 4, 5], pos: 0 }, true);
        assert.equal(witness[1], 1);
    });
    it ("getV([1, 2, 3, 4, 5], 1) == 2", async () => {
        const witness = await cir.calculateWitness({ "bytes": [1, 2, 3, 4, 5], pos: 1 }, true);
        assert.equal(witness[1], 2);
    });
    it ("getV([1, 2, 3, 4, 5], 2) == 3", async () => {
        const witness = await cir.calculateWitness({ "bytes": [1, 2, 3, 4, 5], pos: 2 }, true);
        assert.equal(witness[1], 3);
    });
    it ("getV([1, 2, 3, 4, 5], 3) == 4", async () => {
        const witness = await cir.calculateWitness({ "bytes": [1, 2, 3, 4, 5], pos: 3 }, true);
        assert.equal(witness[1], 4);
    });
    it ("getV([1, 2, 3, 4, 5], 4) == 5", async () => {
        const witness = await cir.calculateWitness({ "bytes": [1, 2, 3, 4, 5], pos: 4 }, true);
        assert.equal(witness[1], 5);
    });
});


describe("CBOR DecodeUin32", function () {
    let cir
    before(async () => {
        cir = await wasm_tester(`${__dirname}/../circuits/decodeUint32_test.circom`);
    })

    // if (x <= 23)
    it ("DecodeUint32(v) == v", async () => {
        for (let v = 0; v < 256; v++) {
            const x = v & 31;
            if (x <= 23) {
                const witness = await cir.calculateWitness({ v }, true);
                assert.equal(witness[1], x);
            }
            else {
                await assert.isRejected(cir.calculateWitness({ v }, true))
            }
        }
    });
})

describe("CBOR DecodeUint", function () {
    let cir
    before(async () => {
        cir = await wasm_tester(`${__dirname}/../circuits/decodeUint_test.circom`);
    })

    // if (x <= 23)
    it ("DecodeUint([0, 0, 0, 0], 0, 167) == 7", async () => {
        const witness = await cir.calculateWitness({ "bytes": [0, 0, 0, 0], pos: 0, v: 167 }, true);
        assert.equal(witness[1], 7);
    });

    it ("DecodeUint([0, 0, 0, 0], 0, 168) == 8", async () => {
        const witness = await cir.calculateWitness({ "bytes": [0, 0, 0, 0], pos: 0, v: 168 }, true);
        assert.equal(witness[1], 8);
    });

    // if(x == 24)
    it ("DecodeUint([31, 0, 0, 0], 0, 120) == 31", async () => {
        const witness = await cir.calculateWitness({ "bytes": [31, 0, 0, 0], pos: 0, v: 120 }, true);
        assert.equal(witness[1], 31);
    });

    it ("DecodeUint([38, 0, 0, 0], 0, 120) == 38", async () => {
        const witness = await cir.calculateWitness({ "bytes": [38, 0, 0, 0], pos: 0, v: 120 }, true);
        assert.equal(witness[1], 38);
    });

    // if(x == 25)
    it ("DecodeUint([42, 69, 0, 0], 0, 25) == 10821", async () => {
        const witness = await cir.calculateWitness({ "bytes": [42, 69, 0, 0], pos: 0, v: 25 }, true);
        assert.equal(witness[1], 10821);
    });

    it ("DecodeUint([69, 42, 0, 0], 0, 25) == 17706", async () => {
        const witness = await cir.calculateWitness({ "bytes": [69, 42, 0, 0], pos: 0, v: 25 }, true);
        assert.equal(witness[1], 17706);
    });

    // if(x == 26)
    it ("DecodeUint([97, 218, 192, 48], 0, 26) == 1641726000", async () => {
        const witness = await cir.calculateWitness({ "bytes": [97, 218, 192, 48], pos: 0, v: 26 }, true);
        assert.equal(witness[1], 1641726000);
    });

    it ("DecodeUint([98, 150, 3, 64], 0, 26) == 1653998400", async () => {
        const witness = await cir.calculateWitness({ "bytes": [98, 150, 3, 64], pos: 0, v: 26 }, true);
        assert.equal(witness[1], 1653998400);
    });

});

describe("CBOR ReadType", function () {
    let cir
    before(async () => {
        cir = await wasm_tester(`${__dirname}/../circuits/readType_test.circom`);
    })
    it ("ReadType([0, 0, v], 2) == (v >> 5, v)", async () => {
        for (var v = 0; v < 256; v++) {
            const pos = 2
            const bytes = [0, 0, v]
            const witness = await cir.calculateWitness({ bytes, pos }, true);
            assert.equal(witness[1], pos + 1);
            assert.equal(witness[2], v >> 5);
            assert.equal(witness[3], v);
        }
    });
    it ("ReadType([0, v, 0], 1) == (v >> 5, v)", async () => {
        for (var v = 0; v < 256; v++) {
            const pos = 1
            const bytes = [0, v, 0]
            const witness = await cir.calculateWitness({ bytes, pos }, true);
            assert.equal(witness[1], pos + 1);
            assert.equal(witness[2], v >> 5);
            assert.equal(witness[3], v);
        }
    });
    it ("ReadType([v, 0, 0], 2) == (v >> 5, v)", async () => {
        for (var v = 0; v < 256; v++) {
            const pos = 0
            const bytes = [v, 0, 0]
            const witness = await cir.calculateWitness({ bytes, pos }, true);
            assert.equal(witness[1], pos + 1);
            assert.equal(witness[2], v >> 5);
            assert.equal(witness[3], v);
        }
    });


});

var MAJOR_TYPE_INT = 0
var MAJOR_TYPE_NEGATIVE_INT = 1
var MAJOR_TYPE_BYTES = 2
var MAJOR_TYPE_STRING = 3
var MAJOR_TYPE_ARRAY = 4
var MAJOR_TYPE_MAP = 5
var MAJOR_TYPE_TAG = 6

function encodeUint(val) {
    if (val <= 23) {
        return [val];
    }
    else if (val >= 24 && val <= 0xFF) {
        return [24, val];
    }
    else if (val > 0xFF && val <= 0xFFFF) {
        return [25, val >> 8, val & 255];
    }
    else if (val > 0xFFFF && val <= 0xFFFFFFFF) {
        return [26, Number(BigInt(val) >> 24n), (val >> 16) & 255, (val >> 8) & 255, val & 255];
    }
    else if (val > 0xFFFFFFFF && val <= 0xFFFFFFFFFFFFFFFFn) {
        return [27, val >> 56, (val >> 48) & 255, (val >> 40) & 255, (val >> 32) & 255, (val >> 24) & 255, (val >> 16) & 255, (val >> 8) & 255, val & 255];
    }
    else {
        throw new Error('Value too large');
    }
}

// TODO: put into helper file?
function encodeInt(val) {
    const [x, ...rest] = encodeUint(val);
    return [(MAJOR_TYPE_INT << 5) | x, ...rest];
}

function encodeString(str) {
    const [x, ...rest] = encodeUint(str.length);
    return [(MAJOR_TYPE_STRING << 5) | x, ...rest, ...stringToArray(str)];
}

function stringToArray(str) {
    return str.split('').map(c => c.charCodeAt(0));
}

function encodeArray(arr) {
    const [x, ...rest] = encodeUint(arr.length);
    return [(MAJOR_TYPE_ARRAY << 5) | x, ...rest, ...arr.flat()];
}

function encodeMap(obj) {
    const [x, ...rest] = encodeUint(Object.keys(obj).length);
    return [(MAJOR_TYPE_MAP << 5) | x, ...rest, ...Object.entries(obj).map(entry => [parseInt(entry[0], 10), entry[1]].flat()).flat()];
}

function padArray(arr, len) {
    const extraZeroes = Math.max(len - arr.length, 0);
    return [...arr, ...Array(extraZeroes).fill(0)];
}
  
describe("CBOR SkipValueScalar (scalar)", function () {
    let cir
    before(async () => {
        cir = await wasm_tester(`${__dirname}/../circuits/skipValueScalar_test.circom`);
    })
    it ("SkipValueScalar string with strlen <= 4", async () => {
        for (var strlen = 0; strlen <= 4; strlen++) {
            const cbor = encodeString(Array(strlen).fill('a').join(''));
            const bytes = padArray(cbor, 5);
            const witness = await cir.calculateWitness({ bytes, pos: 0 }, true);
            assert.equal(witness[1], strlen + 1);    
        }
    });
    it ("SkipValueScalar int with decodeUint23", async () => {
        for (var value = 0; value <= 23; value++) {
            const cbor = encodeInt(value)
            const bytes = padArray(cbor, 5);
            const witness = await cir.calculateWitness({ bytes, pos: 0 }, true);
            assert.equal(witness[1], cbor.length);
        }
    });
    it ("SkipValueScalar int with decodeUint24", async () => {
        const cbor = encodeInt(0xFF)
        const bytes = padArray(cbor, 5);
        const witness = await cir.calculateWitness({ bytes, pos: 0 }, true);
        assert.equal(witness[1], cbor.length);
    });
    it ("SkipValueScalar int with decodeUint25", async () => {
        const cbor = encodeInt(0xFFFF)
        const bytes = padArray(cbor, 5);
        const witness = await cir.calculateWitness({ bytes, pos: 0 }, true);
        assert.equal(witness[1], cbor.length);
    });
    it ("SkipValueScalar int with decodeUint26", async () => {
        const cbor = encodeInt(0xFFFFFFFF)
        const bytes = padArray(cbor, 5);
        const witness = await cir.calculateWitness({ bytes, pos: 0 }, true);
        assert.equal(witness[1], cbor.length);
    });
});

describe("CBOR SkipValue (scalar)", function () {
    const MAX_LEN_5 = 5
    let cir5
    before(async () => {
        cir5 = await wasm_tester(`${__dirname}/../circuits/skipValue5_test.circom`);
    })
    it ("SkipValue string with strlen <= 4", async () => {
        for (var strlen = 0; strlen <= 4; strlen++) {
            const cbor = encodeString(Array(strlen).fill('a').join(''));
            const bytes = padArray(cbor, MAX_LEN_5);
            const witness = await cir5.calculateWitness({ bytes, pos: 0 }, true);
            assert.equal(witness[1], strlen + 1);    
        }
    });
    it ("SkipValue int with decodeUint23", async () => {
        for (var value = 0; value <= 23; value++) {
            const cbor = encodeInt(value)
            const bytes = padArray(cbor, MAX_LEN_5);
            const witness = await cir5.calculateWitness({ bytes, pos: 0 }, true);
            assert.equal(witness[1], cbor.length);
        }
    });
    it ("SkipValue int with decodeUint24", async () => {
        const cbor = encodeInt(0xFF)
        const bytes = padArray(cbor, MAX_LEN_5);
        const witness = await cir5.calculateWitness({ bytes, pos: 0 }, true);
        assert.equal(witness[1], cbor.length);
    });
    it ("SkipValue int with decodeUint25", async () => {
        const cbor = encodeInt(0xFFFF)
        const bytes = padArray(cbor, MAX_LEN_5);
        const witness = await cir5.calculateWitness({ bytes, pos: 0 }, true);
        assert.equal(witness[1], cbor.length);
    });
    it ("SkipValue int with decodeUint26", async () => {
        const cbor = encodeInt(0xFFFFFFFF)
        const bytes = padArray(cbor, MAX_LEN_5);
        const witness = await cir5.calculateWitness({ bytes, pos: 0 }, true);
        assert.equal(witness[1], cbor.length);
    });
});


describe("CBOR SkipValue (array)", function () {
    const MAX_LEN_5 = 5
    const MAX_LEN_6 = 6
    let cir5
    let cir6
    before(async () => {
        cir5 = await wasm_tester(`${__dirname}/../circuits/skipValue5_test.circom`);
        cir6 = await wasm_tester(`${__dirname}/../circuits/skipValue6_test.circom`);
    })
    it ("SkipValue array of 3 1-byte ints", async () => {
        const cbor = encodeArray([encodeInt(23), encodeInt(23), encodeInt(23)])
        const bytes = padArray(cbor, MAX_LEN_5);
        const witness = await cir5.calculateWitness({ bytes, pos: 0 }, true);
        assert.equal(witness[1], cbor.length);
    });
    it ("SkipValue array of 4 1-byte ints", async () => {
        const cbor = encodeArray([encodeInt(23), encodeInt(23), encodeInt(23), encodeInt(23)])
        const bytes = padArray(cbor, MAX_LEN_5);
        const witness = await cir5.calculateWitness({ bytes, pos: 0 }, true);
        assert.equal(witness[1], cbor.length);
    });
    it ("SkipValue array of 2 2-byte ints", async () => {
        const cbor = encodeArray([encodeInt(0xFF),encodeInt(0xFF)])
        const bytes = padArray(cbor, MAX_LEN_5);
        const witness = await cir5.calculateWitness({ bytes, pos: 0 }, true);
        assert.equal(witness[1], cbor.length);
    });
    it ("SkipValue array of 1 3-byte int", async () => {
        const cbor = encodeArray([encodeInt(0xFFFF)])
        const bytes = padArray(cbor, MAX_LEN_5);
        const witness = await cir5.calculateWitness({ bytes, pos: 0 }, true);
        assert.equal(witness[1], cbor.length);
    });
    it ("SkipValue array of 1 5-byte int", async () => {
        const cbor = encodeArray([encodeInt(0xFFFFFFFF)])
        const bytes = padArray(cbor, MAX_LEN_6);
        const witness = await cir6.calculateWitness({ bytes, pos: 0 }, true);
        assert.equal(witness[1], cbor.length);
    });
    it ("SkipValue array of 2 2-byte strings", async () => {
        const cbor = encodeArray([encodeString('q'), encodeString('q')])
        const bytes = padArray(cbor, MAX_LEN_5);
        const witness = await cir5.calculateWitness({ bytes, pos: 0 }, true);
        assert.equal(witness[1], cbor.length);
    });
    it ("SkipValue array of 1 4-byte string", async () => {
        const cbor = encodeArray([encodeString('qwe')])
        const bytes = padArray(cbor, MAX_LEN_5);
        const witness = await cir5.calculateWitness({ bytes, pos: 0 }, true);
        assert.equal(witness[1], cbor.length);
    });
    it ("SkipValue array of 1 2-byte string and 1 2-byte int", async () => {
        const cbor = encodeArray([encodeString('q'), encodeInt(0xFF)])
        const bytes = padArray(cbor, MAX_LEN_5);
        const witness = await cir5.calculateWitness({ bytes, pos: 0 }, true);
        assert.equal(witness[1], cbor.length);
    });
    it ("SkipValue array of 1 2-byte string and 2 1-byte ints", async () => {
        const cbor = encodeArray([encodeString('q'), encodeInt(23), encodeInt(23)])
        const bytes = padArray(cbor, MAX_LEN_5);
        const witness = await cir5.calculateWitness({ bytes, pos: 0 }, true);
        assert.equal(witness[1], cbor.length);
    });
});

describe("CBOR ReadStringLength", function () {
    let cir
    before(async () => {
        cir = await wasm_tester(`${__dirname}/../circuits/readStringLength_test.circom`);
    })
    it ("ReadStringLength string with strlen <= 4", async () => {
        for (var strlen = 0; strlen <= 4; strlen++) {
            const cbor = encodeString(Array(strlen).fill('a').join(''));
            const bytes = padArray(cbor, 5);
            const witness = await cir.calculateWitness({ bytes, pos: 0 }, true);
            assert.equal(witness[1], strlen);    
            assert.equal(witness[2], encodeInt(strlen).length);    
        }
    });
});

describe("CBOR StringEquals", function () {
    let cir
    before(async () => {
        cir = await wasm_tester(`${__dirname}/../circuits/stringEquals_test.circom`);
    })
    it ("StringEquals string 'abcde'", async () => {
        const strArray = stringToArray('abcde');
        const bytes = padArray(strArray, 5);
        const len = strArray.length
        const witness = await cir.calculateWitness({ bytes, len, pos: 0 }, true);
        assert.equal(witness[1], 1);    
    });
    it ("StringEquals not equal other strings", async () => {
        for (var strlen = 0; strlen <= 5; strlen++) {
            const strArray = stringToArray(Array(strlen).fill('b').join(''));
            const bytes = padArray(strArray, 5);
            const len = strArray.length
            const witness = await cir.calculateWitness({ bytes, len, pos: 0 }, true);
            assert.equal(witness[1], 0);    
        }
    });
});

describe("CBOR ReadMapLength", function () {
    let cir
    before(async () => {
        cir = await wasm_tester(`${__dirname}/../circuits/readMapLength_test.circom`);
    })
    it ("ReadMapLength 1 key", async () => {
        const cbor = encodeMap({ [encodeInt(4)]: encodeInt(5) })
        const bytes = padArray(cbor, 7);
        const witness = await cir.calculateWitness({ bytes, pos: 0 }, true);
        assert.equal(witness[1], 1);    
    });
    it ("ReadMapLength 2 keys", async () => {
        const cbor = encodeMap({ [encodeInt(4)]: encodeInt(5), [encodeInt(5)]: encodeInt(4) })
        const bytes = padArray(cbor, 7);
        const witness = await cir.calculateWitness({ bytes, pos: 0 }, true);
        assert.equal(witness[1], 2);    
    });
    it ("ReadMapLength 3 keys", async () => {
        const cbor = encodeMap({ [encodeInt(4)]: encodeInt(5), [encodeInt(5)]: encodeInt(4), [encodeInt(7)]: encodeInt(3) })
        const bytes = padArray(cbor, 7);
        const witness = await cir.calculateWitness({ bytes, pos: 0 }, true);
        assert.equal(witness[1], 3);    
    });
});



describe("CBOR CopyString", function () {
    let cir
    before(async () => {
        cir = await wasm_tester(`${__dirname}/../circuits/copyString_test.circom`);
    })
    it ("CopyString string ''", async () => {
        const str = '';
        const strArray = encodeString(str);
        const bytes = padArray(strArray, 5);
        const witness = await cir.calculateWitness({ bytes, pos: 0 }, true);
        assert.equal(witness[1], 0);    
        assert.equal(witness[2], 0);    
        assert.equal(witness[3], 0);    
        assert.equal(witness[4], 0);    
        assert.equal(witness[5], str.length + 1);    
        assert.equal(witness[6], str.length);    
    });
    it ("CopyString string 'ab'", async () => {
        const str = 'ab';
        const strArray = encodeString(str);
        const bytes = padArray(strArray, 5);
        const witness = await cir.calculateWitness({ bytes, pos: 0 }, true);
        assert.equal(witness[1], str[0].charCodeAt(0));    
        assert.equal(witness[2], str[1].charCodeAt(0));    
        assert.equal(witness[3], 0);    
        assert.equal(witness[4], 0);    
        assert.equal(witness[5], str.length + 1);    
        assert.equal(witness[6], str.length);    
    });
    it ("CopyString string 'abcd'", async () => {
        const str = 'abcd';
        const strArray = encodeString(str);
        const bytes = padArray(strArray, 5);
        const witness = await cir.calculateWitness({ bytes, pos: 0 }, true);
        assert.equal(witness[1], str[0].charCodeAt(0));    
        assert.equal(witness[2], str[1].charCodeAt(0));    
        assert.equal(witness[3], str[2].charCodeAt(0));    
        assert.equal(witness[4], str[3].charCodeAt(0));    
        assert.equal(witness[5], str.length + 1);    
        assert.equal(witness[6], str.length);    
    });
});
