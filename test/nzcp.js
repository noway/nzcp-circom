const chai = require("chai");
const path = require("path");
const assert = chai.assert;
const { getToBeSignedAndRs } = require('./helpers/nzcp')

const wasm_tester = require("circom_tester").wasm;

const {buffer2bitArray, bitArray2buffer} = require("./helpers/utils");

function prepareNZCPCredSubjHashInput(input) {
    const maxLen = 314;
    const buffer = Buffer.alloc(maxLen).fill(0);
    input.copy(buffer, 0);
    return {toBeSigned: buffer2bitArray(buffer), toBeSignedLen: input.length}
}
const EXAMPLE_PASS_URI = "NZCP:/1/2KCEVIQEIVVWK6JNGEASNICZAEP2KALYDZSGSZB2O5SWEOTOPJRXALTDN53GSZBRHEXGQZLBNR2GQLTOPICRUYMBTIFAIGTUKBAAUYTWMOSGQQDDN5XHIZLYOSBHQJTIOR2HA4Z2F4XXO53XFZ3TGLTPOJTS6MRQGE4C6Y3SMVSGK3TUNFQWY4ZPOYYXQKTIOR2HA4Z2F4XW46TDOAXGG33WNFSDCOJONBSWC3DUNAXG46RPMNXW45DFPB2HGL3WGFTXMZLSONUW63TFGEXDALRQMR2HS4DFQJ2FMZLSNFTGSYLCNRSUG4TFMRSW45DJMFWG6UDVMJWGSY2DN53GSZCQMFZXG4LDOJSWIZLOORUWC3CTOVRGUZLDOSRWSZ3JOZSW4TTBNVSWISTBMNVWUZTBNVUWY6KOMFWWKZ2TOBQXE4TPO5RWI33CNIYTSNRQFUYDILJRGYDVAYFE6VGU4MCDGK7DHLLYWHVPUS2YIDJOA6Y524TD3AZRM263WTY2BE4DPKIF27WKF3UDNNVSVWRDYIYVJ65IRJJJ6Z25M2DO4YZLBHWFQGVQR5ZLIWEQJOZTS3IQ7JTNCFDX";

describe("NZCP credential subject hash", function () {
    this.timeout(100000);
    it ("Should parse ToBeSigned", async () => {
        const p = path.join(__dirname, "../", "circuits", "nzcp_exampleTest.circom")
        const cir = await wasm_tester(p);
        console.log('calculating witness...');

        const pass = getToBeSignedAndRs(EXAMPLE_PASS_URI)
        const toBeSignedByteArray = Buffer.from(pass.ToBeSigned, "hex");

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

