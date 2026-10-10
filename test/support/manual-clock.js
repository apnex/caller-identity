// manual-clock - the clock port a test injects into caller-identity (CI2): monotonic milliseconds that move
// only when the test moves them, and callbacks that run only when the test lets them.
//
// advanceTo(t) runs every callback due at or before t, each at its own due time, in due order, like AGP's
// ManualClock. setTime(t) moves the time without running anything, so a test can make a sweep late, and
// runDue() then runs what is due at the current time.

export class ManualClock {
	#now;
	#next = 1;
	#tasks = [];

	constructor(start = 1_000_000) {
		this.#now = start;
	}

	now() {
		return this.#now;
	}

	schedule(delayMs, callback) {
		if (!Number.isFinite(delayMs) || delayMs < 0) throw new RangeError(`invalid delay ${delayMs}`);
		const task = { id: this.#next++, due: this.#now + delayMs, callback, cancelled: false };
		this.#tasks.push(task);
		return Object.freeze({ cancel: () => { task.cancelled = true; } });
	}

	/** Moves the time forward to `t`, running each callback due on the way at its due time. */
	advanceTo(t) {
		if (t < this.#now) throw new RangeError("the clock never moves backwards");
		for (;;) {
			const task = this.#nextDue(t);
			if (task === undefined) break;
			// A late callback runs at the current time; the clock never moves backwards.
			this.#now = Math.max(this.#now, task.due);
			task.cancelled = true;
			task.callback();
		}
		this.#now = t;
	}

	advanceBy(ms) {
		this.advanceTo(this.#now + ms);
	}

	/** Moves the time forward to `t` and runs nothing: whatever falls due meanwhile is late. */
	setTime(t) {
		if (t < this.#now) throw new RangeError("the clock never moves backwards");
		this.#now = t;
	}

	/** Runs every callback due at the current time, late ones included. */
	runDue() {
		this.advanceTo(this.#now);
	}

	/** The due times of the callbacks still scheduled, earliest first. */
	pending() {
		return this.#tasks.filter((t) => !t.cancelled).map((t) => t.due).sort((a, b) => a - b);
	}

	#nextDue(limit) {
		let selected;
		for (const task of this.#tasks) {
			if (task.cancelled || task.due > limit) continue;
			if (selected === undefined || task.due < selected.due || (task.due === selected.due && task.id < selected.id)) selected = task;
		}
		this.#tasks = this.#tasks.filter((t) => !t.cancelled || t === selected);
		return selected;
	}
}
