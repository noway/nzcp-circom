const chai = require("chai");
const path = require("path");
const crypto = require("crypto");
const wasm_tester = require("circom_tester").wasm;
const { verifyPassURIOffline, DID_DOCUMENTS } = require("@vaxxnz/nzcp");
const { getToBeSignedAndRs } = require('./helpers/nzcp');
const { buffer2bitArray, bitArray2buffer } = require("./helpers/utils");

require('dotenv').config()

const assert = chai.assert;


function prepareNZCPCredSubjHashInput(input, maxLen) {
    const buffer = Buffer.alloc(maxLen).fill(0);
    input.copy(buffer, 0);
    return {toBeSigned: buffer2bitArray(buffer), toBeSignedLen: input.length}
}

function sha256Hash(input) {
    return crypto.createHash('sha256').update(input).digest('hex');
}

const EXAMPLE_PASS_URI = "NZCP:/1/2KCEVIQEIVVWK6JNGEASNICZAEP2KALYDZSGSZB2O5SWEOTOPJRXALTDN53GSZBRHEXGQZLBNR2GQLTOPICRUYMBTIFAIGTUKBAAUYTWMOSGQQDDN5XHIZLYOSBHQJTIOR2HA4Z2F4XXO53XFZ3TGLTPOJTS6MRQGE4C6Y3SMVSGK3TUNFQWY4ZPOYYXQKTIOR2HA4Z2F4XW46TDOAXGG33WNFSDCOJONBSWC3DUNAXG46RPMNXW45DFPB2HGL3WGFTXMZLSONUW63TFGEXDALRQMR2HS4DFQJ2FMZLSNFTGSYLCNRSUG4TFMRSW45DJMFWG6UDVMJWGSY2DN53GSZCQMFZXG4LDOJSWIZLOORUWC3CTOVRGUZLDOSRWSZ3JOZSW4TTBNVSWISTBMNVWUZTBNVUWY6KOMFWWKZ2TOBQXE4TPO5RWI33CNIYTSNRQFUYDILJRGYDVAYFE6VGU4MCDGK7DHLLYWHVPUS2YIDJOA6Y524TD3AZRM263WTY2BE4DPKIF27WKF3UDNNVSVWRDYIYVJ65IRJJJ6Z25M2DO4YZLBHWFQGVQR5ZLIWEQJOZTS3IQ7JTNCFDX";

async function testNZCPCredSubjHash(cir, passURI, isLive, maxLen) {
    const SHA256_BITS = 256;
    const verificationResult = verifyPassURIOffline(passURI, { didDocument: isLive ? DID_DOCUMENTS.MOH_LIVE : DID_DOCUMENTS.MOH_EXAMPLE })
    const credSubj = verificationResult.credentialSubject;

    const credSubjConcat = `${credSubj.givenName},${credSubj.familyName},${credSubj.dob}`
    console.log('credSubjConcat', credSubjConcat);
    const toBeSignedByteArray = Buffer.from(getToBeSignedAndRs(passURI).ToBeSigned, "hex");

    const input = prepareNZCPCredSubjHashInput(toBeSignedByteArray, maxLen);
    const witness = await cir.calculateWitness(input, true);

    const expectedCredSubjHash = sha256Hash(credSubjConcat)
    const credSubjHash = bitArray2buffer(witness.slice(1, 1 + SHA256_BITS)).toString("hex");
    assert.equal(credSubjHash, expectedCredSubjHash);
    console.log('credSubjHash', credSubjHash);

    const expectedToBeSignedHash = sha256Hash(toBeSignedByteArray)
    const toBeSignedHash = bitArray2buffer(witness.slice(1 + SHA256_BITS, 1 + 2 * SHA256_BITS)).toString("hex");
    assert.equal(toBeSignedHash, expectedToBeSignedHash);
    console.log('toBeSignedHash', toBeSignedHash);

    const expectedExp = verificationResult.raw.exp
    const actualExp = witness[1 + 2 * SHA256_BITS]
    assert.equal(expectedExp, actualExp)
}

/*
describe("NZCP credential subject hash - example pass", function () {
    this.timeout(100000);

    let cir
    before(async () => {
        cir = await wasm_tester(path.join(__dirname, "../circuits/nzcp_exampleTest.circom"));
    })

    it ("Should parse ToBeSigned", async () => {
        console.log('calculating witness...');

        await testNZCPCredSubjHash(cir, EXAMPLE_PASS_URI, false, 314);
    });
});
*/

const LIVE_PASS_URI_1 = process.env.LIVE_PASS_URI_1;
const LIVE_PASS_URI_2 = process.env.LIVE_PASS_URI_2;
const LIVE_PASS_URI_3 = process.env.LIVE_PASS_URI_3;
const LIVE_PASS_URI_4 = process.env.LIVE_PASS_URI_4;

describe("NZCP credential subject hash - live pass", function () {
    this.timeout(100000);

    let cir
    before(async () => {
        cir = await wasm_tester(path.join(__dirname, "../circuits/nzcp_liveTest.circom"));
    })

    it ("Should generate credential hash and output exp for LIVE_PASS_URI_1", async () => {
        console.log('calculating witness...');
        await testNZCPCredSubjHash(cir, LIVE_PASS_URI_1, true, 355);
    });
    it ("Should generate credential hash and output exp for LIVE_PASS_URI_2", async () => {
        console.log('calculating witness...');
        await testNZCPCredSubjHash(cir, LIVE_PASS_URI_2, true, 355);
    });
    it ("Should generate credential hash and output exp for LIVE_PASS_URI_3", async () => {
        console.log('calculating witness...');
        await testNZCPCredSubjHash(cir, LIVE_PASS_URI_3, true, 355);
    });
    it ("Should generate credential hash and output exp for LIVE_PASS_URI_4", async () => {
        console.log('calculating witness...');
        await testNZCPCredSubjHash(cir, LIVE_PASS_URI_4, true, 355);
    });
});

