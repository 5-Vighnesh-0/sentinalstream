/** SVG filters for the brushwork, defined once. `ink-rough` frays an edge like a loaded brush (panels, buttons);
 *  `ink-grain` is the paper-and-ink texture of the band. Pure SVG: no images, nothing for the CSP to fetch. */
export default function InkDefs() {
  return (
    <svg aria-hidden width="0" height="0" style={{ position: "absolute" }}>
      <filter id="ink-rough" x="-3%" y="-20%" width="106%" height="140%">
        <feTurbulence type="fractalNoise" baseFrequency="0.035 0.09" numOctaves="2" seed="7" />
        <feDisplacementMap in="SourceGraphic" scale="1.4" />
      </filter>
      <filter id="ink-grain">
        <feTurbulence type="fractalNoise" baseFrequency="0.85" numOctaves="3" seed="4" />
        <feColorMatrix values="0 0 0 0 1  0 0 0 0 1  0 0 0 0 1  0 0 0 0.09 0" />
      </filter>
    </svg>
  );
}
