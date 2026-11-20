// TEST HELPER ONLY: React Flow measures the DOM, jsdom does not (React
// Flow's testing guide). Call from beforeAll() in tests that render the graph.
import { vi } from "vitest";

export function mockReactFlowDom() {
  class RO {
    cb: ResizeObserverCallback;
    constructor(cb: ResizeObserverCallback) {
      this.cb = cb;
    }
    observe(t: Element) {
      this.cb([{ target: t } as ResizeObserverEntry], this as unknown as ResizeObserver);
    }
    unobserve() {}
    disconnect() {}
  }
  vi.stubGlobal("ResizeObserver", RO);
  class DOMMatrixRO {
    m22: number;
    constructor(t?: string) {
      const scale = t?.match(/scale\(([1-9.])\)/)?.[1];
      this.m22 = scale !== undefined ? +scale : 1;
    }
  }
  vi.stubGlobal("DOMMatrixReadOnly", DOMMatrixRO);
  Object.defineProperties(HTMLElement.prototype, {
    offsetHeight: { configurable: true, get() { return parseFloat(this.style.height) || 800; } },
    offsetWidth: { configurable: true, get() { return parseFloat(this.style.width) || 1200; } },
  });
  (SVGElement.prototype as unknown as { getBBox: () => DOMRect }).getBBox = () => ({ x: 0, y: 0, width: 0, height: 0 }) as DOMRect;
  if (!globalThis.CSS?.escape) vi.stubGlobal("CSS", { escape: (s: string) => s.replace(/"/g, '\\"') });
}
