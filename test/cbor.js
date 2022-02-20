const chai = require("chai");
const path = require("path");
const wasm_tester = require("circom_tester").wasm;

const assert = chai.assert;

describe("CBOR getType", function () {
    const p = path.join(__dirname, "../circuits/getType_test.circom")
    it ("getType(v) == v >> 5", async () => {
        // exhaustive test for 8 bits
        const cir = await wasm_tester(p);
        for (let v = 255; v >= 0; v--) {
            const witness = await cir.calculateWitness({ "v": v }, true);
            assert.equal(witness[1], v >> 5);
        }
    });
});

describe("CBOR getX", function () {
    const p = path.join(__dirname, "../circuits/getX_test.circom")
    it ("getX(v) == v & 31", async () => {
        // exhaustive test for 8 bits
        const cir = await wasm_tester(p);
        for (let v = 255; v >= 0; v--) {
            const witness = await cir.calculateWitness({ "v": v }, true);
            assert.equal(witness[1], v & 31);
        }
    });
});

describe("CBOR getV(3)", function () {
    const p = path.join(__dirname, "../circuits/getV3_test.circom")
    let cir
    before(async () => {
        cir = await wasm_tester(p);
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
    const p = path.join(__dirname, "../circuits/getV4_test.circom")
    let cir
    before(async () => {
        cir = await wasm_tester(p);
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
    const p = path.join(__dirname, "../circuits/getV5_test.circom")
    let cir
    before(async () => {
        cir = await wasm_tester(p);
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


describe("CBOR DecodeUint", function () {
    const p = path.join(__dirname, "../circuits/decodeUint_test.circom")

    // if (x <= 23)
    it ("DecodeUint([0, 0, 0, 0], 0, 167) == 7", async () => {
        const cir = await wasm_tester(p);
        const witness = await cir.calculateWitness({ "bytes": [0, 0, 0, 0], pos: 0, v: 167 }, true);
        assert.equal(witness[1], 7);
    });

    it ("DecodeUint([0, 0, 0, 0], 0, 168) == 8", async () => {
        const cir = await wasm_tester(p);
        const witness = await cir.calculateWitness({ "bytes": [0, 0, 0, 0], pos: 0, v: 168 }, true);
        assert.equal(witness[1], 8);
    });

    // if(x == 24)
    it ("DecodeUint([31, 0, 0, 0], 0, 120) == 31", async () => {
        const cir = await wasm_tester(p);
        const witness = await cir.calculateWitness({ "bytes": [31, 0, 0, 0], pos: 0, v: 120 }, true);
        assert.equal(witness[1], 31);
    });

    it ("DecodeUint([38, 0, 0, 0], 0, 120) == 38", async () => {
        const cir = await wasm_tester(p);
        const witness = await cir.calculateWitness({ "bytes": [38, 0, 0, 0], pos: 0, v: 120 }, true);
        assert.equal(witness[1], 38);
    });

    // if(x == 25)
    it ("DecodeUint([42, 69, 0, 0], 0, 25) == 10821", async () => {
        const cir = await wasm_tester(p);
        const witness = await cir.calculateWitness({ "bytes": [42, 69, 0, 0], pos: 0, v: 25 }, true);
        assert.equal(witness[1], 10821);
    });

    it ("DecodeUint([69, 42, 0, 0], 0, 25) == 17706", async () => {
        const cir = await wasm_tester(p);
        const witness = await cir.calculateWitness({ "bytes": [69, 42, 0, 0], pos: 0, v: 25 }, true);
        assert.equal(witness[1], 17706);
    });

    // if(x == 26)
    it ("DecodeUint([97, 218, 192, 48], 0, 26) == 1641726000", async () => {
        const cir = await wasm_tester(p);
        const witness = await cir.calculateWitness({ "bytes": [97, 218, 192, 48], pos: 0, v: 26 }, true);
        assert.equal(witness[1], 1641726000);
    });

    it ("DecodeUint([98, 150, 3, 64], 0, 26) == 1653998400", async () => {
        const cir = await wasm_tester(p);
        const witness = await cir.calculateWitness({ "bytes": [98, 150, 3, 64], pos: 0, v: 26 }, true);
        assert.equal(witness[1], 1653998400);
    });

});