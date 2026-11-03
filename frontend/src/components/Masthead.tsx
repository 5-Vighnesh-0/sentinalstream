import gsap from "gsap";
import { ShieldAlert } from "lucide-react";
import { useLayoutEffect, useRef, type ReactNode } from "react";

type Props = { highInEffect: number; nav: ReactNode; status: ReactNode };

/** The bulletin's headline band: ink at rest, flooded signal red while a High is in effect.
 *  The flood is the one authored motion on the page: a wipe in from the left, like a warning being raised.
 *  With reduced motion it cross-fades instead, so the state change still shows. */
export default function Masthead({ highInEffect, nav, status }: Props) {
  const flood = useRef<HTMLDivElement>(null);
  const raised = highInEffect > 0;

  useLayoutEffect(() => {
    const el = flood.current;
    if (!el) return;
    const mm = gsap.matchMedia();
    mm.add({ full: "(prefers-reduced-motion: no-preference)", reduced: "(prefers-reduced-motion: reduce)" }, (ctx) => {
      if (ctx.conditions?.full) {
        if (raised) {
          // always from the left edge, even right after an exit to the right
          gsap.fromTo(el, { clipPath: "inset(0% 100% 0% 0%)", opacity: 1 }, { clipPath: "inset(0% 0% 0% 0%)", duration: 0.6, ease: "expo.out" });
        } else {
          gsap.to(el, { clipPath: "inset(0% 0% 0% 100%)", duration: 0.35, ease: "power2.in" }); // exits faster than it arrives
        }
      } else {
        gsap.to(el, { clipPath: "inset(0% 0% 0% 0%)", opacity: raised ? 1 : 0, duration: 0.2 });
      }
    });
    return () => mm.revert();
  }, [raised]);

  return (
    <header className="relative overflow-hidden bg-ink text-white">
      <div
        ref={flood}
        aria-hidden
        className="absolute inset-0 bg-sev-high"
        style={{ clipPath: "inset(0% 100% 0% 0%)" }}
      />
      <div className="relative mx-auto flex max-w-[1440px] flex-wrap items-center gap-x-6 gap-y-3 px-4 py-3 sm:px-6">
        <h1 className="text-[22px] font-bold tracking-tight">SentinelStream</h1>
        {raised && (
          <p className="flex items-center gap-2 text-sm font-semibold tracking-wide">
            <ShieldAlert aria-hidden size={18} />
            HIGH IN EFFECT
            <span className="rounded bg-white px-1.5 font-mono text-sev-high-ink">{highInEffect}</span>
          </p>
        )}
        {nav}
        <div className="ml-auto">{status}</div>
      </div>
    </header>
  );
}
