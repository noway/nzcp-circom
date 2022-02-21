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
var MAJOR_TYPE_STRING = 3

function encodeUint(x) {
    if (x <= 23) {
        return [(MAJOR_TYPE_INT << 5) | x];
    }
    else if (x >= 24 && x <= 0xFF) {
        return [(MAJOR_TYPE_INT << 5) | 24, x];
    }
    else if (x > 0xFF && x <= 0xFFFF) {
        return [(MAJOR_TYPE_INT << 5) | 25, x >> 8, x & 255];
    }
    else if (x > 0xFFFF && x <= 0xFFFFFFFF) {
        return [(MAJOR_TYPE_INT << 5) | 26, x >> 24, (x >> 16) & 255, (x >> 8) & 255, x & 255];
    }
    else if (x > 0xFFFFFFFF && x <= 0xFFFFFFFFFFFFFFFFn) {
        return [(MAJOR_TYPE_INT << 5) | 27, x >> 56, (x >> 48) & 255, (x >> 40) & 255, (x >> 32) & 255, (x >> 24) & 255, (x >> 16) & 255, (x >> 8) & 255, x & 255];
    }
}

describe("CBOR SkipValueScalar", function () {
    let cirScalar
    let cirNormal
    before(async () => {
        cirScalar = await wasm_tester(`${__dirname}/../circuits/skipValueScalar_test.circom`);
        cirNormal = await wasm_tester(`${__dirname}/../circuits/skipValue_test.circom`);
    })
    it ("SkipValueScalar string with strlen <= 4", async () => {
        for (var strlen = 0; strlen <= 4; strlen++) {
            const bytes = [(MAJOR_TYPE_STRING << 5) | strlen, 0, 0, 0, 0];
            const pos = 0;
            const nextpos = strlen + 1
            const witness1 = await cirScalar.calculateWitness({ bytes, pos }, true);
            assert.equal(witness1[1], nextpos);    
            const witness2 = await cirNormal.calculateWitness({ bytes, pos }, true);
            assert.equal(witness2[1], nextpos);    
        }
    });

    it ("SkipValueScalar int with decodeUint23", async () => {
        for (var value = 0; value <= 23; value++) {
            const bytes = [...encodeUint(value), 0, 0, 0, 0];
            const pos = 0;
            const nextpos = 1
            const witness1 = await cirScalar.calculateWitness({ bytes, pos }, true);
            assert.equal(witness1[1], nextpos);
            const witness2 = await cirNormal.calculateWitness({ bytes, pos }, true);
            assert.equal(witness2[1], nextpos);
        }
    });
    it ("SkipValueScalar int with decodeUint24", async () => {
        const bytes = [...encodeUint(0xFF), 0, 0, 0];
        const pos = 0;
        const nextpos = 2;
        const witness1 = await cirScalar.calculateWitness({ bytes, pos }, true);
        assert.equal(witness1[1], nextpos);
        const witness2 = await cirNormal.calculateWitness({ bytes, pos }, true);
        assert.equal(witness2[1], nextpos);
    });
    it ("SkipValueScalar int with decodeUint25", async () => {
        const bytes = [...encodeUint(0xFFFF), 0, 0];
        const pos = 0;
        const nextpos = 3;
        const witness1 = await cirScalar.calculateWitness({ bytes, pos }, true);
        assert.equal(witness1[1], nextpos);
        const witness2 = await cirNormal.calculateWitness({ bytes, pos }, true);
        assert.equal(witness2[1], nextpos);
    });
    it ("SkipValueScalar int with decodeUint26", async () => {
        const bytes = [...encodeUint(0xFFFFFFFF)];
        const pos = 0;
        const nextpos = 5;
        const witness1 = await cirScalar.calculateWitness({ bytes, pos }, true);
        assert.equal(witness1[1], nextpos);
        const witness2 = await cirNormal.calculateWitness({ bytes, pos }, true);
        assert.equal(witness2[1], nextpos);
    });

});