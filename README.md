# caller-identity

Establish the principal each request comes from, from the evidence its caller presented and the host's rules.

**Status: built, and certified at zorg's Delta 1, stage 4b (`bb240c6`), and Delta 2, stage 3 (`7d09303`).**\
Its vision is ratified (zorg's `D43`), and its contract's design is certified at zorg's Delta 1, amendment 2.\
Its contract tests run a host over AGP's production in-process carrier, with an injected clock port driving the sweeps, for `session-principal` and `request-evidence`; `verified-principal` is left out of Delta 1 (zorg's `D37`).

- `VISION.md` - why it exists, and what it will never be.
- `CONTRACT.md` - what a consumer can depend on, one capability per row.
- `docs/DECISIONS.md` - the rulings about this component.

It belongs to a component set first composed by zorg (`apnex/zorg`), and is released only by its own CI, as a tarball attached to a GitHub release with its SHA-512 beside it, which a consumer names in its `package.json`: `https://github.com/apnex/caller-identity/releases/download/v0.1.0/apnex-caller-identity-0.1.0.tgz` for `0.1.0`.

It depends on `@apnex/shape-check` through a `file:` link, and takes AGP's types as a peer of the host that embeds it, through a `file:` link to an AGP checkout beside it at `baa2c1a`, each installed and built first, since neither commits its `dist/`.\
The tests link AGP's `@agp/node` and `@agp/transport-loopback` the same way, and Node resolves AGP's own packages from that checkout's workspace.

To run the tests from clean checkouts:
```sh
(cd ../agp && git checkout baa2c1a && npm install && npm run build)
(cd ../shape-check && npm install && npm run build)
npm install
npm test
```
