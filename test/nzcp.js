const chai = require("chai");
const path = require("path");
const assert = chai.assert;

const wasm_tester = require("circom_tester").wasm;

const {buffer2bitArray, bitArray2buffer} = require("./helpers/utils");


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

function prepareNZCPCredSubjHashInput(input) {
    const maxLen = 314;
    const buffer = Buffer.alloc(maxLen).fill(0);
    input.copy(buffer, 0);
    return {toBeSigned: buffer2bitArray(buffer), toBeSignedLen: input.length}
}

describe("NZCP credential subject hash", function () {
    this.timeout(100000);
    it ("Should parse ToBeSigned", async () => {
        const p = path.join(__dirname, "../", "circuits", "nzcp_exampleTest.circom")
        const cir = await wasm_tester(p);
        console.log('calculating witness...');

        const toBeSignedByteArray = Buffer.from("846A5369676E6174757265314AA204456B65792D3101264059011FA501781E6469643A7765623A6E7A63702E636F76696431392E6865616C74682E6E7A051A61819A0A041A7450400A627663A46840636F6E7465787482782668747470733A2F2F7777772E77332E6F72672F323031382F63726564656E7469616C732F7631782A68747470733A2F2F6E7A63702E636F76696431392E6865616C74682E6E7A2F636F6E74657874732F76316776657273696F6E65312E302E306474797065827456657269666961626C6543726564656E7469616C6F5075626C6963436F766964506173737163726564656E7469616C5375626A656374A369676976656E4E616D65644A61636B6A66616D696C794E616D656753706172726F7763646F626A313936302D30342D3136075060A4F54D4E304332BE33AD78B1EAFA4B", "hex");

        const input = prepareNZCPCredSubjHashInput(toBeSignedByteArray);

        const witness = await cir.calculateWitness(input, true);

        const expectedCredSubjHash = "5fb355822221720ea4ce6734e5a09e459d452574a19310c0cea7c141f43a3dab"
        const credSubjHash = bitArray2buffer(witness.slice(1, 257)).toString("hex");
        assert.equal(credSubjHash, expectedCredSubjHash);

        const expectedToBeSignedHash = "271ce33d671a2d3b816d788135f4343e14bc66802f8cd841faac939e8c11f3ee"
        const toBeSignedHash = bitArray2buffer(witness.slice(257, 257+256)).toString("hex");
        assert.equal(toBeSignedHash, expectedToBeSignedHash);
    });
});

