import "@testing-library/jest-dom/vitest";

// jsdom implements neither Element.scrollTo nor window.scrollTo — components that autoscroll (e.g.
// RunLive's live log) call them on mount, so stub them to no-ops for the test environment.
if (!Element.prototype.scrollTo) {
  Element.prototype.scrollTo = () => {};
}
