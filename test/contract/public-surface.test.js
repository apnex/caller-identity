// public-surface - the package exposes exactly what export-map.json names (zorg's target, EM14; E12).
//
// Every path in package.json's exports is named in the map; each module path is imported by its public name
// and its runtime exports compared with the map; every capability row of CONTRACT.md is served by some export
// or deferred with a ruling. The source imports no module particular to one runtime (D31, principle 6), reads
// time only through the clock port, whose default alone touches performance.now() and setTimeout, and takes
// AGP only as types, from the host's own AGP, a peer reached through a file: link.
import assert from "node:assert/strict";
import fs from "node:fs";
import { builtinModules } from "node:module";
import path from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const pkg = JSON.parse(fs.readFileSync(path.join(root, "package.json"), "utf8"));
const map = JSON.parse(fs.readFileSync(path.join(root, "export-map.json"), "utf8"));
const publicName = (p) => p === "." ? pkg.name : `${pkg.name}/${p.slice(2)}`;

test("the export map names the package and exactly its exported paths", () => {
	assert.equal(map.package, pkg.name);
	assert.deepEqual(Object.keys(map.paths).sort(), Object.keys(pkg.exports).sort());
});

for (const [p, entry] of Object.entries(map.paths)) {
	test(`${publicName(p)} exposes what the map names`, async () => {
		assert.ok(entry.exports, `${p} names no exports`);
		const mod = await import(publicName(p));
		assert.deepEqual(Object.keys(mod).sort(), Object.keys(entry.exports).sort());
		for (const [name, use] of Object.entries(entry.exports)) {
			assert.equal(use.part, "caller-identity", `${name} realises the caller-identity part`);
			assert.ok(Array.isArray(use.serves) && use.serves.length > 0, `${name} serves at least one row`);
		}
	});
}

const contractRows = () => {
	const lines = fs.readFileSync(path.join(root, "CONTRACT.md"), "utf8").split("\n");
	const start = lines.findIndex((l) => /^\|\s*Capability\s*\|\s*Relation\s*\|/.test(l));
	const rows = [];
	for (let i = start + 2; start >= 0 && lines[i]?.startsWith("|"); i++) rows.push(lines[i].split("|")[1].trim().replaceAll("`", ""));
	return rows;
};

test("every contract row is served by an export or deferred with a ruling, never both, and every row served is a contract row", () => {
	const rows = contractRows();
	const served = new Set(Object.values(map.paths).flatMap((e) => Object.values(e.exports)).flatMap((x) => x.serves));
	for (const row of rows) assert.ok(served.has(row) || map.deferred[row], `${row} is neither served nor deferred`);
	for (const row of served) assert.ok(rows.includes(row), `${row} is not a row of CONTRACT.md`);
	for (const [row, ruling] of Object.entries(map.deferred)) {
		assert.match(ruling, /^D\d+$/, `${row} is deferred without a ruling`);
		assert.ok(!served.has(row), `${row} is both served and deferred`);
		assert.ok(rows.includes(row), `${row} is not a row of CONTRACT.md`);
	}
});

test("D10-E1: session-principal, request-evidence and verified-principal are all served, and verified-principal is no longer deferred", async () => {
	const served = new Set(Object.values(map.paths).flatMap((e) => Object.values(e.exports)).flatMap((x) => x.serves));
	assert.ok(served.has("session-principal"));
	assert.ok(served.has("request-evidence"));
	assert.ok(served.has("verified-principal"));
	assert.deepEqual(map.deferred, {});
	assert.equal(fs.existsSync(path.join(root, "test", "contract", "verified-principal.test.js")), true);
});

const sources = (dir) => fs.readdirSync(dir, { withFileTypes: true }).flatMap((d) => d.isDirectory() ? sources(path.join(dir, d.name)) : [path.join(dir, d.name)]);
const specifiers = (text) => [...text.matchAll(/(?:\bfrom\s*|\bimport\s*\(\s*|\bimport\s+|\brequire\s*\(\s*)["']([^"']+)["']/g)].map((m) => m[1]);
// Source with its comments removed, so prose about a process or a clock is not mistaken for code.
const code = (text) => text.replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|[^:"'\\])\/\/.*$/gm, "$1");
const builtins = new Set(builtinModules.flatMap((m) => [m, `node:${m}`]));
const srcFiles = () => sources(path.join(root, "src")).filter((f) => f.endsWith(".ts"));

test("no source file imports a module particular to one runtime, or uses a global particular to Node", () => {
	for (const file of srcFiles()) {
		const name = path.relative(root, file);
		const text = fs.readFileSync(file, "utf8");
		const runtime = specifiers(text).filter((s) => s.startsWith("node:") || builtins.has(s));
		assert.deepEqual(runtime, [], `${name} imports ${runtime.join(", ")}`);
		assert.doesNotMatch(code(text), /\b(process|Buffer|__dirname|__filename)\b|\brequire\s*\(/, `${name} uses a global particular to Node`);
	}
});

test("time comes only from the clock port: no source reads the wall clock, and only the default clock reads performance.now() or sets a timer", () => {
	for (const file of srcFiles()) {
		const name = path.relative(root, file);
		const text = code(fs.readFileSync(file, "utf8"));
		assert.doesNotMatch(text, /Date\.now\s*\(|new Date\s*\(|Temporal\.Now/, `${name} reads the wall clock`);
		if (name === path.join("src", "clock.ts")) continue;
		assert.doesNotMatch(text, /performance\.now|setTimeout|setInterval/, `${name} reads time or sets a timer outside the clock port`);
	}
});

test("AGP is taken only as types: every source import of @agp is type-only, and the built package imports no @agp module at run time", () => {
	for (const file of srcFiles()) {
		const text = code(fs.readFileSync(file, "utf8"));
		for (const m of text.matchAll(/\bimport\s+(type\s+)?[^;]*?from\s*["'](@agp\/[^"']+)["']/g)) {
			assert.ok(m[1], `${path.relative(root, file)} imports ${m[2]} at run time`);
		}
	}
	for (const file of sources(path.join(root, "dist")).filter((f) => f.endsWith(".js"))) {
		assert.doesNotMatch(fs.readFileSync(file, "utf8"), /["']@agp\//, `${path.relative(root, file)} imports AGP at run time`);
	}
});

const validDepSpec = (name, spec) => spec === `file:../${name}` || new RegExp(`^https://github\\.com/apnex/${name}/releases/download/v0\\.\\d+\\.\\d+/apnex-${name}-0\\.\\d+\\.\\d+\\.tgz$`).test(spec);

test("AGP is a peer, the host's own, and every AGP package the tests use is a file: link to ../agp/packages", () => {
	assert.deepEqual(Object.keys(pkg.dependencies ?? {}), ["@apnex/shape-check"], "caller-identity depends only on shape-check at run time");
	assert.ok(validDepSpec("shape-check", pkg.dependencies["@apnex/shape-check"]));
	assert.deepEqual(Object.keys(pkg.peerDependencies ?? {}), ["@agp/core"]);
	assert.ok(["file:../agp/packages/core", "*", ">=0.1.0", "^0.1.0"].includes(pkg.peerDependencies["@agp/core"]));
	const agp = Object.entries(pkg.devDependencies).filter(([name]) => name.startsWith("@agp/"));
	assert.ok(agp.length > 0);
	for (const [name, spec] of agp) assert.equal(spec, `file:../agp/packages/${name.slice(5)}`, `${name} is linked from AGP's checkout`);
});
