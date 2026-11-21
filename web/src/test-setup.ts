import '@testing-library/jest-dom/vitest'

// jsdom has no layout engine. Default to a desktop viewport.
Object.defineProperty(window, 'matchMedia', {
  configurable: true,
  writable: true,
  value: (media: string) => Object.assign(new EventTarget(), { media, matches: true }),
})
