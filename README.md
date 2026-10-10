# caller-identity

Establish the principal each request comes from, from the evidence its caller presented and the host's rules.

**Status: built at zorg's Delta 1, stage 4b, and awaiting its verification.**\
Its vision is ratified (zorg's `D43`), and its contract's design is certified at zorg's Delta 1, amendment 2.\
Its contract tests run a host over AGP's production in-process carrier, with an injected clock port driving the sweeps, for `session-principal` and `request-evidence`; `verified-principal` is left out of Delta 1 (zorg's `D37`).

- `VISION.md` - why it exists, and what it will never be.
- `CONTRACT.md` - what a consumer can depend on, one capability per row.
- `docs/DECISIONS.md` - the rulings about this component.

It belongs to a component set first composed by zorg (`apnex/zorg`), and is private until its first working code.

It takes AGP's types as a peer of the host that embeds it, through a `file:` link to an AGP checkout beside it at `1723c9d`, which must be installed and built first, since AGP's `dist/` is not committed.\
The tests link AGP's `@agp/node` and `@agp/transport-loopback` the same way, and Node resolves AGP's own packages from that checkout's workspace.

To run the tests from clean checkouts:
```sh
(cd ../agp && git checkout 1723c9d && npm install && npm run build)
npm install
npm test
```
