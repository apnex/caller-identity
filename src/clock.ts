/**
 * The clock port a host gives caller-identity (CONTRACT.md, CI2): time in milliseconds that a change to the
 * wall clock does not move, and a way to run the next sweep after a delay measured on that same clock.
 */

/** A scheduled callback that has not run yet, which can be cancelled. */
export interface Cancellable {
	cancel(): void;
}

/**
 * The host's clock: `now` is monotonic milliseconds, by default `performance.now()`; `schedule` runs a
 * callback once, no sooner than it can, after a delay in those milliseconds, by default with `setTimeout`.
 * The component reads no other clock: every time it records and every sweep it runs comes from this port.
 */
export interface ClockPort {
	now(): number;
	schedule(delayMs: number, callback: () => void): Cancellable;
}

/** The default clock: `performance.now()` and `setTimeout`, both standard in every runtime the set targets. */
export const defaultClock: ClockPort = Object.freeze({
	now(): number {
		return performance.now();
	},
	schedule(delayMs: number, callback: () => void): Cancellable {
		const handle = setTimeout(callback, delayMs);
		return Object.freeze({
			cancel(): void {
				clearTimeout(handle);
			},
		});
	},
});
