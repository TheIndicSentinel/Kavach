import { useEffect, useRef, type ReactNode, type RefObject } from "react";

type DialogProps = {
  /** The id of the title; the dialog is labelled by it. */
  titleId: string;
  title: ReactNode;
  /** The id of the text that says what confirming does; the dialog is described by it. */
  descriptionId: string;
  children: ReactNode;
  /** Escape calls this, unless `busy`. */
  onCancel: () => void;
  /** While a request is in flight Escape does nothing: the request cannot be taken back. */
  busy?: boolean;
  /** Focus goes here when the dialog closes and the element that opened it is gone. */
  fallbackFocus?: RefObject<HTMLElement | null>;
};

const FOCUSABLE =
  'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

/**
 * A modal confirmation (role=alertdialog, aria-modal). Focus moves to the
 * first control inside when it opens, Tab and Shift+Tab stay inside, Escape
 * cancels, and focus returns to the element that opened it when it closes.
 * Render it only while it is open.
 */
export function Dialog({
  titleId,
  title,
  descriptionId,
  children,
  onCancel,
  busy = false,
  fallbackFocus,
}: DialogProps) {
  const panel = useRef<HTMLDivElement>(null);
  // Read in the key handler, so the listener is added once.
  const latest = useRef({ onCancel, busy });
  useEffect(() => {
    latest.current = { onCancel, busy };
  });

  useEffect(() => {
    const opener = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    const fallback = fallbackFocus?.current ?? null;
    const focusable = () =>
      Array.from(panel.current?.querySelectorAll<HTMLElement>(FOCUSABLE) ?? []);
    (focusable()[0] ?? panel.current)?.focus();

    function onKeyDown(event: KeyboardEvent) {
      if (event.key === "Escape") {
        event.preventDefault();
        if (!latest.current.busy) latest.current.onCancel();
        return;
      }
      if (event.key !== "Tab") return;
      const items = focusable();
      if (items.length === 0) {
        event.preventDefault();
        return;
      }
      const first = items[0];
      const last = items[items.length - 1];
      const inside = panel.current?.contains(document.activeElement) ?? false;
      if (event.shiftKey && (document.activeElement === first || !inside)) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && (document.activeElement === last || !inside)) {
        event.preventDefault();
        first.focus();
      }
    }
    document.addEventListener("keydown", onKeyDown);
    return () => {
      document.removeEventListener("keydown", onKeyDown);
      // The opener may be gone: a stop can remove the button that started it.
      if (opener?.isConnected) opener.focus();
      else fallback?.focus();
    };
  }, [fallbackFocus]);

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-kavach-900/40 p-4">
      <div
        ref={panel}
        role="alertdialog"
        aria-modal="true"
        aria-labelledby={titleId}
        aria-describedby={descriptionId}
        tabIndex={-1}
        className="max-h-full w-full max-w-lg overflow-y-auto rounded-xl border border-border bg-surface-raised p-5 shadow-(--shadow-card)"
      >
        <h2 id={titleId} className="mb-2 text-base font-semibold text-ink">
          {title}
        </h2>
        {children}
      </div>
    </div>
  );
}
