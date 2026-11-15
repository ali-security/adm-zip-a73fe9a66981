"use strict";

const { expect } = require("chai");
const pth = require("path");
const fs = require("fs");
const rimraf = require("rimraf");
const Zip = require("../adm-zip");
const { crc32 } = require("../util/utils");

// Regression test for GHSA-p634-w6r4-rjp2:
// a ZIP archive may list the same entry name more than once. adm-zip kept every
// entry in its entry list but only the last one in its name lookup table, so
// getEntry()/readFile() (table) and extractAllTo() (list) resolved the same name
// to different entries. An application validating an entry's bytes through
// getEntry() before extracting could approve one file while a different one was
// written to disk under that name. Such archives must now be rejected.

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

// Build a STORED zip whose central directory lists `entries` in the given order,
// names taken verbatim (duplicates included).
function craftZip(entries) {
    const locals = [];
    const centrals = [];
    let offset = 0;
    for (const { name, data } of entries) {
        const n = Buffer.from(name);
        const d = Buffer.from(data);
        const crc = crc32(d);
        const lfh = Buffer.concat([u32(0x04034b50), u16(20), u16(0), u16(0), u16(0), u16(0x21), u32(crc), u32(d.length), u32(d.length), u16(n.length), u16(0), n, d]);
        const cen = Buffer.concat([
            u32(0x02014b50),
            u16(20),
            u16(20),
            u16(0),
            u16(0),
            u16(0),
            u16(0x21),
            u32(crc),
            u32(d.length),
            u32(d.length),
            u16(n.length),
            u16(0),
            u16(0),
            u16(0),
            u16(0),
            u32(0),
            u32(offset),
            n
        ]);
        locals.push(lfh);
        centrals.push(cen);
        offset += lfh.length;
    }
    const cd = Buffer.concat(centrals);
    const eocd = Buffer.concat([u32(0x06054b50), u16(0), u16(0), u16(entries.length), u16(entries.length), u32(cd.length), u32(offset), u16(0)]);
    return Buffer.concat([...locals, cd, eocd]);
}

// the first "y.txt" is what extractAllTo() wrote, the last is what getEntry() returned
const exploit = () =>
    craftZip([
        { name: "y.txt", data: "EVIL" },
        { name: "y.txt", data: "SAFE" }
    ]);

describe("ADM-ZIP - duplicate entry names - GHSA-p634-w6r4-rjp2", () => {
    const destination = pth.join("test", "xxx");

    afterEach((done) => rimraf(destination, done));

    it("rejects an archive listing the same entry name twice on getEntry()", () => {
        const zip = new Zip(exploit());
        expect(() => zip.getEntry("y.txt")).to.throw(/Duplicate entry name/);
    });

    it("cannot approve one entry via getEntry() and write another via extractAllTo()", () => {
        const zip = new Zip(exploit());
        let approved = null;
        try {
            approved = zip.getEntry("y.txt").getData().toString();
        } catch (e) {
            // expected: the ambiguous archive is refused
        }
        expect(approved).to.equal(null);
        // swallowing the first error must not let the same instance extract anyway
        expect(() => zip.extractAllTo(destination)).to.throw(/Duplicate entry name/);
        expect(() => zip.getEntry("y.txt")).to.throw(/Duplicate entry name/);
        expect(fs.existsSync(pth.join(destination, "y.txt"))).to.equal(false);
    });

    it("extractAllTo() refuses the archive and writes nothing", () => {
        const zip = new Zip(exploit());
        expect(() => zip.extractAllTo(destination, false)).to.throw(/Duplicate entry name/);
        expect(fs.existsSync(pth.join(destination, "y.txt"))).to.equal(false);
    });

    it("extractAllToAsync() rejects the archive and writes nothing", () => {
        const zip = new Zip(exploit());
        return zip.extractAllToAsync(destination, false, false).then(
            () => {
                throw new Error("extractAllToAsync should have rejected");
            },
            (err) => {
                expect(err.message).to.match(/Duplicate entry name/);
                expect(fs.existsSync(pth.join(destination, "y.txt"))).to.equal(false);
            }
        );
    });

    it("readFile(), getEntries() and extractEntryTo() refuse the archive", () => {
        expect(() => new Zip(exploit()).readFile("y.txt")).to.throw(/Duplicate entry name/);
        expect(() => new Zip(exploit()).getEntries()).to.throw(/Duplicate entry name/);
        expect(() => new Zip(exploit()).extractEntryTo("y.txt", destination)).to.throw(/Duplicate entry name/);
        expect(fs.existsSync(pth.join(destination, "y.txt"))).to.equal(false);
    });

    it("rejects the archive eagerly when entries are read on load", () => {
        expect(() => new Zip(exploit(), { readEntries: true })).to.throw(/Duplicate entry name/);
    });

    it("rejects non-adjacent duplicates and duplicate directories", () => {
        const spread = craftZip([
            { name: "y.txt", data: "EVIL" },
            { name: "z.txt", data: "other" },
            { name: "y.txt", data: "SAFE" }
        ]);
        expect(() => new Zip(spread).getEntries()).to.throw(/Duplicate entry name/);

        const dirs = craftZip([
            { name: "dir/", data: "" },
            { name: "dir/a.txt", data: "A" },
            { name: "dir/", data: "" }
        ]);
        expect(() => new Zip(dirs).getEntries()).to.throw(/Duplicate entry name/);
    });

    it("does not mistake names of Object.prototype members for duplicates", () => {
        const names = ["constructor", "toString", "hasOwnProperty", "__proto__", "valueOf"];
        const zip = new Zip(craftZip(names.map((name) => ({ name, data: "data:" + name }))));
        expect(
            zip
                .getEntries()
                .map((e) => e.entryName)
                .sort()
        ).to.eql(names.slice().sort());
        for (const name of names) {
            expect(zip.readFile(name).toString()).to.equal("data:" + name);
        }
    });

    it("still loads archives with distinct names and updates re-added names in place", () => {
        const zip = new Zip(
            craftZip([
                { name: "a.txt", data: "A" },
                { name: "b.txt", data: "B" }
            ])
        );
        expect(zip.readFile("a.txt").toString()).to.equal("A");
        expect(zip.readFile("b.txt").toString()).to.equal("B");

        const built = new Zip();
        built.addFile("same.txt", Buffer.from("first"));
        built.addFile("same.txt", Buffer.from("second"));
        const round = new Zip(built.toBuffer());
        expect(round.getEntries().map((e) => e.entryName)).to.eql(["same.txt"]);
        expect(round.readFile("same.txt").toString()).to.equal("second");
    });
});
