const chai = require("chai");
const path = require("path");
const crypto = require("crypto");
const F1Field = require("ffjavascript").F1Field;
const Scalar = require("ffjavascript").Scalar;
// exports.p = Scalar.fromString("21888242871839275222246405745257275088548364400416034343698204186575808495617");
// const Fr = new F1Field(exports.p);

const assert = chai.assert;

const sha256 = require("./helpers/sha256");

const wasm_tester = require("circom_tester").wasm;

// const printSignal = require("./helpers/printsignal");


function buffer2bitArray(b) {
    const res = [];
    for (let i=0; i<b.length; i++) {
        for (let j=0; j<8; j++) {
            res.push((b[i] >> (7-j) &1));
        }
    }
    return res;
}

function bitArray2buffer(a) {
    const len = Math.floor((a.length -1 )/8)+1;
    const b = new Buffer.alloc(len);

    for (let i=0; i<a.length; i++) {
        const p = Math.floor(i/8);
        b[p] = b[p] | (Number(a[i]) << ( 7 - (i%8)  ));
    }
    return b;
}


describe("SHA256", function () {
    this.timeout(100000);
    /*
    it ("Should calculate a hash of ToBeSigned", async () => {
        const p = path.join(__dirname, "../", "nzcp.circom")
        console.log('p',p)
        const cir = await wasm_tester(p);

        const b = Buffer.from("846A5369676E6174757265314AA204456B65792D3101264059011FA501781E6469643A7765623A6E7A63702E636F76696431392E6865616C74682E6E7A051A61819A0A041A7450400A627663A46840636F6E7465787482782668747470733A2F2F7777772E77332E6F72672F323031382F63726564656E7469616C732F7631782A68747470733A2F2F6E7A63702E636F76696431392E6865616C74682E6E7A2F636F6E74657874732F76316776657273696F6E65312E302E306474797065827456657269666961626C6543726564656E7469616C6F5075626C6963436F766964506173737163726564656E7469616C5375626A656374A369676976656E4E616D65644A61636B6A66616D696C794E616D656753706172726F7763646F626A313936302D30342D3136075060A4F54D4E304332BE33AD78B1EAFA4B", "hex");

        const hash = crypto.createHash("sha256")
            .update(b)
            .digest("hex");

        const arrIn = buffer2bitArray(b);

        console.log('calculating witness...');

        const witness = await cir.calculateWitness({ "a": arrIn }, true);

        const arrOut = witness.slice(1, 257);
        const hash2 = bitArray2buffer(arrOut).toString("hex");
        console.log('hash',hash)
        console.log('hash2',hash2)

        assert.equal(hash, hash2);
    });
    */
});

describe("CBOR getType", function () {
    this.timeout(100000);
    const p = path.join(__dirname, "../circuits/getType_test.circom")
    it ("getType(168) == 5n", async () => {
        const cir = await wasm_tester(p);
        const witness = await cir.calculateWitness({ "v": 168 }, true);
        assert.equal(witness[1], 5n);
    });
    it ("getType(161) == 5n", async () => {
        const cir = await wasm_tester(p);
        const witness = await cir.calculateWitness({ "v": 161 }, true);
        assert.equal(witness[1], 5n);
    });
    it ("getType(130) == 4n", async () => {
        const cir = await wasm_tester(p);
        const witness = await cir.calculateWitness({ "v": 130 }, true);
        assert.equal(witness[1], 4n);
    });
    it ("getType(100) == 3n", async () => {
        const cir = await wasm_tester(p);
        const witness = await cir.calculateWitness({ "v": 100 }, true);
        assert.equal(witness[1], 3n);
    });
    it ("getType(90) == 2n", async () => {
        const cir = await wasm_tester(p);
        const witness = await cir.calculateWitness({ "v": 90 }, true);
        assert.equal(witness[1], 2n);
    });
    it ("getType(60) == 1n", async () => {
        const cir = await wasm_tester(p);
        const witness = await cir.calculateWitness({ "v": 60 }, true);
        assert.equal(witness[1], 1n);
    });
});

describe("NZCP", function () {
    this.timeout(100000);
    it ("Should parse ToBeSigned", async () => {
        const p = path.join(__dirname, "../", "circuits", "nzcp.circom")
        console.log('p',p)
        const cir = await wasm_tester(p);

        const b = Buffer.from("846A5369676E6174757265314AA204456B65792D3101264059011FA501781E6469643A7765623A6E7A63702E636F76696431392E6865616C74682E6E7A051A61819A0A041A7450400A627663A46840636F6E7465787482782668747470733A2F2F7777772E77332E6F72672F323031382F63726564656E7469616C732F7631782A68747470733A2F2F6E7A63702E636F76696431392E6865616C74682E6E7A2F636F6E74657874732F76316776657273696F6E65312E302E306474797065827456657269666961626C6543726564656E7469616C6F5075626C6963436F766964506173737163726564656E7469616C5375626A656374A369676976656E4E616D65644A61636B6A66616D696C794E616D656753706172726F7763646F626A313936302D30342D3136075060A4F54D4E304332BE33AD78B1EAFA4B", "hex");

        const arrIn = buffer2bitArray(b);

        console.log('calculating witness...');

        const witness = await cir.calculateWitness({ "a": arrIn }, true);

        const arrOut = witness.slice(1, 257);
        const hash2 = bitArray2buffer(arrOut).toString("hex");

        assert.equal("0000000000000000000000000000000000000000000000000000000000000000", hash2);
    });
});
