const crypto = require("crypto");
const { assert } = require("chai");
const { wasm: wasm_tester } = require("circom_tester");
const { verifyPassURIOffline, DID_DOCUMENTS } = require("@vaxxnz/nzcp");
const { buffer2bitArray, bitArray2buffer, bufferToBytes } = require("./helpers/utils");
const { getToBeSignedAndRs } = require('./helpers/nzcp');
const { encodeUint, stringToArray, padArray } = require('./helpers/cbor');

require('dotenv').config()

function prepareNZCPCredSubjHashInput(input, maxLen) {
    const bytes = Buffer.alloc(maxLen).fill(0);
    input.copy(bytes, 0);
    const byteslen = input.length;
    return { bytes, byteslen }
}

function getNZCPPubIdentity(passURI, isLive) {
    const verificationResult = verifyPassURIOffline(passURI, { didDocument: isLive ? DID_DOCUMENTS.MOH_LIVE : DID_DOCUMENTS.MOH_EXAMPLE })
    const { givenName, familyName, dob } = verificationResult.credentialSubject;
    const credSubjConcat = `${givenName},${familyName},${dob}`
    const toBeSignedByteArray = Buffer.from(getToBeSignedAndRs(passURI).ToBeSigned, "hex");
    const credSubjHash = crypto.createHash('sha256').update(credSubjConcat).digest('hex')
    const toBeSignedHash = crypto.createHash('sha256').update(toBeSignedByteArray).digest('hex')
    const exp = verificationResult.raw.exp
    const pubIdentity = { credSubjHash, toBeSignedHash, exp };
    console.log('credSubjConcat', credSubjConcat);
    console.log('pubIdentity', pubIdentity);
    return pubIdentity;
}

async function testNZCPCredSubjHash(cir, passURI, isLive, maxLen) {
    const SHA256_BITS = 256;

    const expected = getNZCPPubIdentity(passURI, isLive);

    const input = prepareNZCPCredSubjHashInput(Buffer.from(getToBeSignedAndRs(passURI).ToBeSigned, "hex"), maxLen);
    const witness = await cir.calculateWitness({ toBeSigned: buffer2bitArray(input.bytes), toBeSignedLen: input.byteslen }, true);

    const credSubjHash = bitArray2buffer(witness.slice(1, 1 + SHA256_BITS)).toString("hex");
    assert.equal(credSubjHash, expected.credSubjHash);

    const toBeSignedHash = bitArray2buffer(witness.slice(1 + SHA256_BITS, 1 + 2 * SHA256_BITS)).toString("hex");
    assert.equal(toBeSignedHash, expected.toBeSignedHash);

    const exp = witness[1 + 2 * SHA256_BITS];
    assert.equal(exp, expected.exp)
}

const EXAMPLE_PASS_URI = "NZCP:/1/2KCEVIQEIVVWK6JNGEASNICZAEP2KALYDZSGSZB2O5SWEOTOPJRXALTDN53GSZBRHEXGQZLBNR2GQLTOPICRUYMBTIFAIGTUKBAAUYTWMOSGQQDDN5XHIZLYOSBHQJTIOR2HA4Z2F4XXO53XFZ3TGLTPOJTS6MRQGE4C6Y3SMVSGK3TUNFQWY4ZPOYYXQKTIOR2HA4Z2F4XW46TDOAXGG33WNFSDCOJONBSWC3DUNAXG46RPMNXW45DFPB2HGL3WGFTXMZLSONUW63TFGEXDALRQMR2HS4DFQJ2FMZLSNFTGSYLCNRSUG4TFMRSW45DJMFWG6UDVMJWGSY2DN53GSZCQMFZXG4LDOJSWIZLOORUWC3CTOVRGUZLDOSRWSZ3JOZSW4TTBNVSWISTBMNVWUZTBNVUWY6KOMFWWKZ2TOBQXE4TPO5RWI33CNIYTSNRQFUYDILJRGYDVAYFE6VGU4MCDGK7DHLLYWHVPUS2YIDJOA6Y524TD3AZRM263WTY2BE4DPKIF27WKF3UDNNVSVWRDYIYVJ65IRJJJ6Z25M2DO4YZLBHWFQGVQR5ZLIWEQJOZTS3IQ7JTNCFDX";

const LIVE_PASS_URI_1 = process.env.LIVE_PASS_URI_1;
const LIVE_PASS_URI_2 = process.env.LIVE_PASS_URI_2;
const LIVE_PASS_URI_3 = process.env.LIVE_PASS_URI_3;
const LIVE_PASS_URI_4 = process.env.LIVE_PASS_URI_4;

// TODO: use false/true for isLive
async function testFindVCAndExp(cir, passURI, isLive, pos, maxLen, expectedVCPos, expectedExpPos) {

    const verificationResult = verifyPassURIOffline(passURI, { didDocument: isLive ? DID_DOCUMENTS.MOH_LIVE : DID_DOCUMENTS.MOH_EXAMPLE })
    const exp = verificationResult.raw.exp

    const maplen = 5;
    const input = prepareNZCPCredSubjHashInput(Buffer.from(getToBeSignedAndRs(passURI).ToBeSigned, "hex"), maxLen);
    const bytes = bufferToBytes(input.bytes)
    const witness = await cir.calculateWitness({ maplen, bytes, pos }, true);

    const actualVCPos = Number(witness[1]);
    assert.equal(actualVCPos, expectedVCPos);

    const actualExpPos = Number(witness[2]);
    assert.equal(actualExpPos, expectedExpPos);

    // assert that expiry date is at the right position
    // TODO: use slice or something?
    assert.equal(input.bytes[actualExpPos + 0], encodeUint(exp)[0]);
    assert.equal(input.bytes[actualExpPos + 1], encodeUint(exp)[1]);
    assert.equal(input.bytes[actualExpPos + 2], encodeUint(exp)[2]);
    assert.equal(input.bytes[actualExpPos + 3], encodeUint(exp)[3]);
    assert.equal(input.bytes[actualExpPos + 4], encodeUint(exp)[4]);

}
describe("NZCP find vc and exp - example pass", function () {
    this.timeout(100000);

    const maxLen = 314;
    let cir
    before(async () => {
        cir = await wasm_tester(`${__dirname}/../circuits/findVCAndExp_exampleTest.circom`);
    })

    it ("Should find vc and exp pos of EXAMPLE_PASS_URI", async () => {
        await testFindVCAndExp(cir, EXAMPLE_PASS_URI, 0, 28, maxLen, 76, 68);
    });
});

describe("NZCP find vc and exp - live pass", function () {
    this.timeout(100000);

    const maxLen = 355;
    let cir
    before(async () => {
        cir = await wasm_tester(`${__dirname}/../circuits/findVCAndExp_liveTest.circom`);
    })

    it ("Should find vc and exp pos of LIVE_PASS_URI_1", async () => {
        await testFindVCAndExp(cir, LIVE_PASS_URI_1, 1, 31, maxLen, 80, 72);
    });
    if (LIVE_PASS_URI_2) {
        it ("Should find vc and exp pos of LIVE_PASS_URI_2", async () => {
            await testFindVCAndExp(cir, LIVE_PASS_URI_2, 1, 31, maxLen, 80, 72);
        });
    }
    if (LIVE_PASS_URI_3) {
        it ("Should find vc and exp pos of LIVE_PASS_URI_3", async () => {
            await testFindVCAndExp(cir, LIVE_PASS_URI_3, 1, 31, maxLen, 80, 72);
        });
    }
    if (LIVE_PASS_URI_4) {
        it ("Should find vc and exp pos of LIVE_PASS_URI_4", async () => {
            await testFindVCAndExp(cir, LIVE_PASS_URI_4, 1, 31, maxLen, 80, 72);
        });
    }
});


async function testFindCredSubj(cir, passURI, pos, maxLen, expectedCredSubjPos) {

    const maplen = 4;
    const input = prepareNZCPCredSubjHashInput(Buffer.from(getToBeSignedAndRs(passURI).ToBeSigned, "hex"), maxLen);
    const bytes = bufferToBytes(input.bytes)
    const witness = await cir.calculateWitness({ maplen, bytes, pos }, true);

    const actualCredSubjPos = Number(witness[1]);
    assert.equal(actualCredSubjPos, expectedCredSubjPos);
}

describe("NZCP find credential subject - example pass", function () {
    this.timeout(100000);

    const maxLen = 314;
    let cir
    before(async () => {
        cir = await wasm_tester(`${__dirname}/../circuits/findCredSubj_exampleTest.circom`);
    })

    it ("Should find credential subject of EXAMPLE_PASS_URI", async () => {
        await testFindCredSubj(cir, EXAMPLE_PASS_URI, 77, maxLen, 246);
    });
});

describe("NZCP find credential subject - live pass", function () {
    this.timeout(100000);

    const maxLen = 355;
    let cir
    before(async () => {
        cir = await wasm_tester(`${__dirname}/../circuits/findCredSubj_liveTest.circom`);
    })

    it ("Should find credential subject of LIVE_PASS_URI_1", async () => {
        await testFindCredSubj(cir, LIVE_PASS_URI_1, 81, maxLen, 250);
    });

    if (LIVE_PASS_URI_2) {
        it ("Should find credential subject of LIVE_PASS_URI_2", async () => {
            await testFindCredSubj(cir, LIVE_PASS_URI_2, 81, maxLen, 250);
        });
    }

    if (LIVE_PASS_URI_3) {
        it ("Should find credential subject of LIVE_PASS_URI_3", async () => {
            await testFindCredSubj(cir, LIVE_PASS_URI_3, 81, maxLen, 250);
        });
    }

    if (LIVE_PASS_URI_4) {
        it ("Should find credential subject of LIVE_PASS_URI_4", async () => {
            await testFindCredSubj(cir, LIVE_PASS_URI_4, 81, maxLen, 250);
        });
    }
});

async function testReadCredSubj(cir, passURI, isLive, pos, maxLen, maxBufferLen) {

    const verificationResult = verifyPassURIOffline(passURI, { didDocument: isLive ? DID_DOCUMENTS.MOH_LIVE : DID_DOCUMENTS.MOH_EXAMPLE })
    const { givenName, familyName, dob } = verificationResult.credentialSubject;

    const maplen = 3;
    const input = prepareNZCPCredSubjHashInput(Buffer.from(getToBeSignedAndRs(passURI).ToBeSigned, "hex"), maxLen);
    const bytes = bufferToBytes(input.bytes)
    const witness = await cir.calculateWitness({ maplen, bytes, pos }, true);

    const actualGivenName = witness.slice(1, 1 + maxBufferLen).map(e => Number(e));
    const actualGivenNameLen = witness[1 + maxBufferLen];

    const actualFamilyName = witness.slice(2 + maxBufferLen, 2 + 2 * maxBufferLen).map(e => Number(e));
    const actualFamilyNameLen = witness[2 + 2 * maxBufferLen];

    assert.deepEqual(actualGivenName, padArray(stringToArray(givenName), maxBufferLen));
    assert.equal(actualGivenNameLen, givenName.length);

    assert.deepEqual(actualFamilyName, padArray(stringToArray(familyName), maxBufferLen));
    assert.equal(actualFamilyNameLen, familyName.length);
}
describe("NZCP read cred subj - example pass", function () {
    this.timeout(100000);

    let cir
    before(async () => {
        cir = await wasm_tester(`${__dirname}/../circuits/readCredSubj_exampleTest.circom`);
    })

    it ("Should parse ToBeSigned", async () => {
        await testReadCredSubj(cir, EXAMPLE_PASS_URI, 0, 247, 314, 32);
    });
});
// TODO: rename to pub identity
describe("NZCP credential subject hash - example pass", function () {
    this.timeout(100000);

    let cir
    before(async () => {
        cir = await wasm_tester(`${__dirname}/../circuits/nzcp_exampleTest.circom`);
    })

    it ("Should parse ToBeSigned", async () => {
        await testNZCPCredSubjHash(cir, EXAMPLE_PASS_URI, false, 314);
    });
});


describe("NZCP credential subject hash - live pass", function () {
    this.timeout(100000);

    let cir
    before(async () => {
        cir = await wasm_tester(`${__dirname}/../circuits/nzcp_liveTest.circom`);
    })

    it ("Should generate credential hash and output exp for LIVE_PASS_URI_1", async () => {
        await testNZCPCredSubjHash(cir, LIVE_PASS_URI_1, true, 355);
    });
    if (LIVE_PASS_URI_2) {
        it ("Should generate credential hash and output exp for LIVE_PASS_URI_2", async () => {
            await testNZCPCredSubjHash(cir, LIVE_PASS_URI_2, true, 355);
        });
    }
    if (LIVE_PASS_URI_3) {
        it ("Should generate credential hash and output exp for LIVE_PASS_URI_3", async () => {
            await testNZCPCredSubjHash(cir, LIVE_PASS_URI_3, true, 355);
        });
    }
    if (LIVE_PASS_URI_4) {
        it ("Should generate credential hash and output exp for LIVE_PASS_URI_4", async () => {
            await testNZCPCredSubjHash(cir, LIVE_PASS_URI_4, true, 355);
        });
    }
});

