const chai = require("chai");
const path = require("path");
const assert = chai.assert;

const wasm_tester = require("circom_tester").wasm;

const {buffer2bitArray, bitArray2buffer} = require("./helpers/utils");

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

        const expectedExp = 1951416330
        const actualExp = witness[257+256]
        assert.equal(expectedExp, actualExp)
    });
});

