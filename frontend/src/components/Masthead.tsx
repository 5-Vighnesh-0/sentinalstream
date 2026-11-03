import type { ReactNode } from "react";

type Props = { nav: ReactNode; status: ReactNode };

/** The clean white strip above the ink band: wordmark, view tabs, connection status. */
export default function Masthead({ nav, status }: Props) {
  return (
    <header className="border-b border-hairline bg-surface">
      <div className="mx-auto flex max-w-[1440px] flex-wrap items-center gap-x-8 gap-y-3 px-4 py-3 sm:px-6">
        <h1 className="font-display text-lg font-extrabold tracking-[0.06em] uppercase">SentinelStream</h1>
        {nav}
        <div className="ml-auto">{status}</div>
      </div>
    </header>
  );
}
