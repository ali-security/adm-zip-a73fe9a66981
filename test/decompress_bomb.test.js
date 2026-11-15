"use strict";

const { expect } = require("chai");
const zlib = require("zlib");
const Zip = require("../adm-zip");
const Utils = require("../util");

// Regression test for CVE-2026-39244:
// adm-zip allocated the entry output buffer from the attacker-declared
// uncompressed size (central-directory / local-header size field) before any
// validation. A tiny crafted archive could declare a ~4 GB size and force a
// matching Buffer.alloc, OOM-killing the process. The allocation must be bound
// by the data actually present in the archive, not by the declared size.

const u16 = (n) => {
    const b = Buffer.alloc(2);
    b.writeUInt16LE(n >>> 0);
    return b;
};
const u32 = (n) => {
    const b = Buffer.alloc(4);
    b.writeUInt32LE(n >>> 0);
    return b;
};

// Build a single-entry zip that declares `declaredSize` uncompressed bytes while
// only carrying `content` bytes of (crc-invalid) payload. Pass `realCrc` to make
// the entry crc-valid, so only the declared size is lying.
function craftBomb(declaredSize, method, content, realCrc) {
    const name = Buffer.from("a");
    const crc = realCrc === undefined ? 0 : realCrc; // deliberately wrong by default: alloc used to happen before the crc check
    const lfh = Buffer.concat([
        u32(0x04034b50),
        u16(20),
        u16(0),
        u16(method),
        u16(0),
        u16(0),
        u32(crc),
        u32(content.length),
        u32(declaredSize),
        u16(name.length),
        u16(0),
        name,
        content
    ]);
    const cd = Buffer.concat([
        u32(0x02014b50),
        u16(20),
        u16(20),
        u16(0),
        u16(method),
        u16(0),
        u16(0),
        u32(crc),
        u32(content.length),
        u32(declaredSize),
        u16(name.length),
        u16(0),
        u16(0),
        u16(0),
        u16(0),
        u32(0),
        u32(0),
        name
    ]);
    const eocd = Buffer.concat([u32(0x06054b50), u16(0), u16(0), u16(1), u16(1), u32(cd.length), u32(lfh.length), u16(0)]);
    return Buffer.concat([lfh, cd, eocd]);
}

describe("decompression bomb (declared size) - CVE-2026-39244", () => {
    const DECLARED = 3 * 1024 * 1024 * 1024; // ~3 GB, far above any plausible RSS budget

    it("does not allocate the declared size for a STORED entry", () => {
        const zip = new Zip(craftBomb(DECLARED, 0 /* STORED */, Buffer.from("A")));
        const before = process.memoryUsage().rss;
        // invalid crc -> must throw, but crucially without committing gigabytes
        expect(() => zip.getEntries()[0].getData()).to.throw(/CRC32/);
        const grewMB = (process.memoryUsage().rss - before) / (1024 * 1024);
        expect(grewMB, "RSS growth must stay bounded by real data, not declared size").to.be.below(256);
    });

    it("does not allocate the declared size for a DEFLATED entry", () => {
        const zip = new Zip(craftBomb(DECLARED, 8 /* DEFLATED */, Buffer.from([0x00])));
        const before = process.memoryUsage().rss;
        // bogus deflate stream / crc -> must throw without a huge eager allocation
        expect(() => zip.getEntries()[0].getData()).to.throw();
        const grewMB = (process.memoryUsage().rss - before) / (1024 * 1024);
        expect(grewMB, "RSS growth must stay bounded by real data, not declared size").to.be.below(256);
    });

    it("still reads a legitimate STORED entry", () => {
        const zip = new Zip();
        zip.addFile("s.bin", Buffer.from([1, 2, 3, 4, 5]));
        const round = new Zip(zip.toBuffer());
        expect([...round.readFile("s.bin")]).to.eql([1, 2, 3, 4, 5]);
    });

    it("still reads a legitimate DEFLATED entry", () => {
        const zip = new Zip();
        const payload = Buffer.from("hello world ".repeat(5000));
        zip.addFile("d.txt", payload);
        const round = new Zip(zip.toBuffer());
        expect(round.readFile("d.txt").equals(payload)).to.equal(true);
    });
});

describe("decompression bomb (async size cap) - GHSA-c6fg-446q-cg94", () => {
    // Regression test for GHSA-c6fg-446q-cg94: getDataAsync() inflated through
    // zlib.createInflateRaw, whose streaming API ignores maxOutputLength, so an
    // entry declaring a tiny uncompressed size inflated without limit on the async
    // path while the synchronous getData() path was capped at the declared size.
    const nodeMajor = +(process.versions ? process.versions.node : "").split(".")[0] || 0;
    // 1 MB of repeated bytes deflates to ~1 KB and inflates over many zlib chunks
    const payload = Buffer.alloc(1024 * 1024, 0x41);
    const deflated = zlib.deflateRawSync(payload);
    const crc = Utils.crc32(payload);

    // the async read must fail with the size error and hand back no data
    const expectRejected = (data, err) => {
        expect(err, "async read must fail instead of inflating past the declared size").to.be.an("error");
        expect(err.message).to.contain("exceeds the declared uncompressed size");
        expect(data.length, "no inflated data may be returned").to.equal(0);
    };

    it("getDataAsync rejects an entry that inflates beyond its declared size, like getData", (done) => {
        const entry = new Zip(craftBomb(16, 8 /* DEFLATED */, deflated, crc)).getEntries()[0];
        if (nodeMajor >= 15) {
            // zlib supports maxOutputLength on Node >= 15 only: the sync path is capped there
            expect(() => entry.getData()).to.throw();
        }
        entry.getDataAsync((data, err) => {
            try {
                expectRejected(data, err);
                done();
            } catch (e) {
                done(e);
            }
        });
    });

    it("readFileAsync rejects a bomb that declares an uncompressed size of 0", (done) => {
        const zip = new Zip(craftBomb(0, 8 /* DEFLATED */, deflated, crc));
        zip.readFileAsync("a", (data, err) => {
            try {
                expectRejected(data, err);
                done();
            } catch (e) {
                done(e);
            }
        });
    });

    it("readAsTextAsync rejects an entry that inflates beyond its declared size", (done) => {
        const zip = new Zip(craftBomb(1024, 8 /* DEFLATED */, deflated, crc));
        zip.readAsTextAsync("a", (data, err) => {
            try {
                expectRejected(data, err);
                done();
            } catch (e) {
                done(e);
            }
        });
    });

    it("getDataAsync still inflates an entry whose data matches its declared size", (done) => {
        const entry = new Zip(craftBomb(payload.length, 8 /* DEFLATED */, deflated, crc)).getEntries()[0];
        expect(entry.getData().equals(payload)).to.equal(true);
        entry.getDataAsync((data, err) => {
            try {
                expect(err).to.equal(undefined);
                expect(data.equals(payload)).to.equal(true);
                done();
            } catch (e) {
                done(e);
            }
        });
    });

    it("still reads a genuinely empty DEFLATED entry that declares size 0", (done) => {
        const empty = zlib.deflateRawSync(Buffer.alloc(0));
        const entry = new Zip(craftBomb(0, 8 /* DEFLATED */, empty, Utils.crc32(Buffer.alloc(0)))).getEntries()[0];
        expect(entry.getData().length).to.equal(0);
        entry.getDataAsync((data, err) => {
            try {
                expect(err).to.equal(undefined);
                expect(data.length).to.equal(0);
                done();
            } catch (e) {
                done(e);
            }
        });
    });
});
