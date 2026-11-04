// jsdom has no matchMedia; GSAP's reduced-motion handling needs it. Tests run as "no preference".
window.matchMedia ??= ((query: string) => ({
  matches: false, media: query, onchange: null,
  addListener() {}, removeListener() {}, addEventListener() {}, removeEventListener() {}, dispatchEvent: () => false,
})) as typeof window.matchMedia;
