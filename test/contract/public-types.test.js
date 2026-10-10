// public-types - caller-identity's published types compose with AGP's as zorg's CI5 needs: a TypeScript host
// gives the admission port to createNode, the node's operations reader to the sweeps, and a handler's delivery
// context to the evidence, without a cast.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import path from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");

test("a host composing caller-identity with AGP's node type-checks against the public entry point", () => {
	const tsc = path.join(root, "node_modules", ".bin", "tsc");
	const fixture = path.join(root, "test", "types", "zorg-hub-composition.mts");
	const run = () => execFileSync(tsc, ["--noEmit", "--strict", "--exactOptionalPropertyTypes", "--module", "NodeNext", "--moduleResolution", "NodeNext", "--target", "ES2022", "--types", "node", "--skipLibCheck", fixture], { cwd: root, stdio: "inherit" });
	assert.doesNotThrow(run, "the host does not compile");
});
