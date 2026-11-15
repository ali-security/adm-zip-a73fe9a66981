"use strict";

const { expect } = require("chai");
const pth = require("path");
const fs = require("fs");
const rimraf = require("rimraf");
const Zip = require("../adm-zip");

// Regression test for CVE-2026-76845 (GHSA-vwc7-r8mq-g2x9):
// sanitize() only checks the textual entry path against the extraction root, it
// never looks at the filesystem. A symlink that already exists inside the target
// directory was therefore followed by mkdir()/open()/chmod(), and extraction wrote
// outside the root - without any "../" in the entry names. Extraction must now
// refuse to write through such a link, while a root that itself sits behind a
// link (e.g. /tmp on macOS) keeps working.

describe("ADM-ZIP - symlink in extraction target - CVE-2026-76845", () => {
    const base = pth.resolve("test", "xxx_symlink");
    const root = pth.join(base, "root");
    const outside = pth.join(base, "outside");
    const links = [];

    const IN_THE_WAY = /There is a file in the way/;

    // Directory links: junctions on Windows (no privilege needed); the type is ignored elsewhere.
    function linkDir(target, linkPath) {
        fs.symlinkSync(target, linkPath, "junction");
        links.push(linkPath);
    }

    // File symlinks may need privileges on Windows: skip the test there instead of failing.
    function linkFile(ctx, target, linkPath) {
        try {
            fs.symlinkSync(target, linkPath, "file");
        } catch (e) {
            if (e.code === "EPERM" || e.code === "EACCES" || e.code === "ENOSYS") ctx.skip();
            throw e;
        }
        links.push(linkPath);
    }

    // Build an archive from [name, data] pairs (data null => directory entry) and re-read it.
    function archive(entries) {
        const zip = new Zip();
        entries.forEach(function (e) {
            zip.addFile(e[0], e[1] === null ? null : Buffer.from(e[1]));
        });
        return new Zip(zip.toBuffer());
    }

    function rejection(promise) {
        return promise.then(
            function () {
                return null;
            },
            function (err) {
                return err;
            }
        );
    }

    beforeEach(() => {
        rimraf.sync(base);
        fs.mkdirSync(root, { recursive: true });
        fs.mkdirSync(outside, { recursive: true });
    });

    afterEach((done) => {
        // remove the links first so the cleanup can never follow them
        while (links.length) {
            const link = links.pop();
            try {
                fs.unlinkSync(link);
            } catch (e) {
                try {
                    fs.rmdirSync(link);
                } catch (e2) {
                    /* already gone */
                }
            }
        }
        rimraf(base, done);
    });

    describe("extractAllTo", () => {
        it("does not write a file through a symlinked directory", () => {
            linkDir(outside, pth.join(root, "sub"));
            const zip = archive([["sub/evil.txt", "EVIL"]]);

            expect(() => zip.extractAllTo(root)).to.throw(IN_THE_WAY);
            expect(fs.existsSync(pth.join(outside, "evil.txt"))).to.equal(false);
        });

        it("does not write a file through a symlinked nested directory", () => {
            fs.mkdirSync(pth.join(root, "a"));
            linkDir(outside, pth.join(root, "a", "b"));
            const zip = archive([["a/b/c/evil.txt", "EVIL"]]);

            expect(() => zip.extractAllTo(root, true)).to.throw(IN_THE_WAY);
            expect(fs.existsSync(pth.join(outside, "c"))).to.equal(false);
        });

        it("does not overwrite the target of a symlinked file", function () {
            const victim = pth.join(outside, "victim.txt");
            fs.writeFileSync(victim, "SAFE");
            linkFile(this, victim, pth.join(root, "a.txt"));
            const zip = archive([["a.txt", "EVIL"]]);

            expect(() => zip.extractAllTo(root, true)).to.throw(IN_THE_WAY);
            expect(fs.readFileSync(victim, "utf8")).to.equal("SAFE");
        });

        it("does not create a directory through a symlinked directory", () => {
            linkDir(outside, pth.join(root, "sub"));
            const zip = archive([["sub/newdir/", null]]);

            expect(() => zip.extractAllTo(root, true)).to.throw(IN_THE_WAY);
            expect(fs.existsSync(pth.join(outside, "newdir"))).to.equal(false);
        });
    });

    describe("extractEntryTo", () => {
        it("does not write a file entry through a symlinked directory", () => {
            linkDir(outside, pth.join(root, "sub"));
            const zip = archive([["sub/evil.txt", "EVIL"]]);

            expect(() => zip.extractEntryTo("sub/evil.txt", root, true, true)).to.throw(IN_THE_WAY);
            expect(fs.existsSync(pth.join(outside, "evil.txt"))).to.equal(false);
        });

        it("does not write an outFileName through a symlinked directory", () => {
            linkDir(outside, pth.join(root, "sub"));
            const zip = archive([["evil.txt", "EVIL"]]);

            expect(() => zip.extractEntryTo("evil.txt", root, false, true, false, "sub/renamed.txt")).to.throw(IN_THE_WAY);
            expect(fs.existsSync(pth.join(outside, "renamed.txt"))).to.equal(false);
        });

        it("does not overwrite the target of a symlinked file", function () {
            const victim = pth.join(outside, "victim.txt");
            fs.writeFileSync(victim, "SAFE");
            linkFile(this, victim, pth.join(root, "a.txt"));
            const zip = archive([["a.txt", "EVIL"]]);

            expect(() => zip.extractEntryTo("a.txt", root, true, true)).to.throw(IN_THE_WAY);
            expect(fs.readFileSync(victim, "utf8")).to.equal("SAFE");
        });

        it("does not write the children of a directory entry through a symlinked directory", () => {
            linkDir(outside, pth.join(root, "sub"));
            const zip = archive([
                ["sub/", null],
                ["sub/evil.txt", "EVIL"]
            ]);

            expect(() => zip.extractEntryTo("sub/", root, true, true)).to.throw(IN_THE_WAY);
            expect(fs.existsSync(pth.join(outside, "evil.txt"))).to.equal(false);
        });
    });

    describe("extractAllToAsync", () => {
        it("does not write a file through a symlinked directory", () => {
            linkDir(outside, pth.join(root, "sub"));
            const zip = archive([["sub/evil.txt", "EVIL"]]);

            return rejection(zip.extractAllToAsync(root, true)).then((err) => {
                expect(err).to.be.an("error");
                expect(err.message).to.match(IN_THE_WAY);
                expect(fs.existsSync(pth.join(outside, "evil.txt"))).to.equal(false);
            });
        });

        it("does not overwrite the target of a symlinked file", function () {
            const victim = pth.join(outside, "victim.txt");
            fs.writeFileSync(victim, "SAFE");
            linkFile(this, victim, pth.join(root, "a.txt"));
            const zip = archive([["a.txt", "EVIL"]]);

            return rejection(zip.extractAllToAsync(root, true)).then((err) => {
                expect(err).to.be.an("error");
                expect(err.message).to.match(IN_THE_WAY);
                expect(fs.readFileSync(victim, "utf8")).to.equal("SAFE");
            });
        });

        it("does not create a directory through a symlinked directory", () => {
            linkDir(outside, pth.join(root, "sub"));
            const zip = archive([["sub/newdir/", null]]);

            return rejection(zip.extractAllToAsync(root, true)).then((err) => {
                expect(err).to.be.an("error");
                expect(err.message).to.match(/Unable to create folder/);
                expect(fs.existsSync(pth.join(outside, "newdir"))).to.equal(false);
            });
        });
    });

    describe("legitimate extraction", () => {
        const entries = [
            ["dir/", null],
            ["dir/ok.txt", "OK"],
            ["top.txt", "TOP"]
        ];

        it("extracts into a root that is itself a symlink", () => {
            const real = pth.join(base, "real");
            fs.mkdirSync(real);
            const linkedRoot = pth.join(base, "linkedRoot");
            linkDir(real, linkedRoot);

            archive(entries).extractAllTo(linkedRoot, true);
            archive(entries).extractEntryTo("dir/ok.txt", linkedRoot, false, true, false, "renamed.txt");

            expect(fs.readFileSync(pth.join(real, "dir", "ok.txt"), "utf8")).to.equal("OK");
            expect(fs.readFileSync(pth.join(real, "top.txt"), "utf8")).to.equal("TOP");
            expect(fs.readFileSync(pth.join(real, "renamed.txt"), "utf8")).to.equal("OK");
        });

        it("extracts asynchronously into a root that is itself a symlink", () => {
            const real = pth.join(base, "real");
            fs.mkdirSync(real);
            const linkedRoot = pth.join(base, "linkedRoot");
            linkDir(real, linkedRoot);

            return archive(entries)
                .extractAllToAsync(linkedRoot, true)
                .then(() => {
                    expect(fs.readFileSync(pth.join(real, "dir", "ok.txt"), "utf8")).to.equal("OK");
                    expect(fs.readFileSync(pth.join(real, "top.txt"), "utf8")).to.equal("TOP");
                });
        });

        it("ignores symlinks inside the root that the archive does not write through", () => {
            linkDir(outside, pth.join(root, "unrelated"));

            archive(entries).extractAllTo(root, true);

            expect(fs.readFileSync(pth.join(root, "dir", "ok.txt"), "utf8")).to.equal("OK");
            expect(fs.readFileSync(pth.join(root, "top.txt"), "utf8")).to.equal("TOP");
            expect(fs.readdirSync(outside)).to.deep.equal([]);
        });
    });
});
