/** SVG filters for the brushwork, defined once. `ink-brush` frays the Alerts panel's edge like a loaded brush;
 *  `ink-grain` is the paper-and-ink texture of the band. Pure SVG: no images, nothing for the CSP to fetch. */
export default function InkDefs() {
  return (
    <svg aria-hidden width="0" height="0" style={{ position: "absolute" }}>
      <filter id="ink-brush" x="-2%" y="-2%" width="104%" height="104%">
        {/* low frequency along the stroke, enough displacement to read as a loaded brush at a glance */}
        <feTurbulence type="fractalNoise" baseFrequency="0.012 0.06" numOctaves="3" seed="11" />
        <feDisplacementMap in="SourceGraphic" scale="4" />
      </filter>
      <filter id="ink-grain">
        <feTurbulence type="fractalNoise" baseFrequency="0.85" numOctaves="3" seed="4" />
        <feColorMatrix values="0 0 0 0 1  0 0 0 0 1  0 0 0 0 1  0 0 0 0.09 0" />
      </filter>
    </svg>
  );
}
