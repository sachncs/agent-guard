/** Coordinates replaceable client requests and prevents stale UI updates. */
export class LatestRequest {
  private sequence = 0;
  private controller: AbortController | null = null;

  begin() {
    this.controller?.abort();
    const controller = new AbortController();
    this.controller = controller;
    const sequence = ++this.sequence;
    return {
      signal: controller.signal,
      isCurrent: () => sequence === this.sequence,
      finish: () => {
        if (sequence === this.sequence) this.controller = null;
      },
    };
  }

  get active(): boolean {
    return this.controller !== null;
  }

  abort(): void {
    this.sequence += 1;
    this.controller?.abort();
    this.controller = null;
  }
}
