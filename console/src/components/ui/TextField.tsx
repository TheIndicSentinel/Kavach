import type { Ref } from "react";
import { cn } from "../../lib/cn";

type TextFieldProps = {
  id: string;
  label: string;
  value: string;
  onChange: (value: string) => void;
  /** Shown under the field and tied to it with aria-describedby. */
  hint?: string;
  /** Why the value was refused; marks the field invalid. */
  error?: string | null;
  placeholder?: string;
  maxLength?: number;
  ref?: Ref<HTMLInputElement>;
  className?: string;
};

/** A labelled text input whose hint and error are announced with it. */
export function TextField({
  id,
  label,
  value,
  onChange,
  hint,
  error,
  placeholder,
  maxLength,
  ref,
  className,
}: TextFieldProps) {
  const hintId = hint ? `${id}-hint` : undefined;
  const errorId = error ? `${id}-error` : undefined;
  const describedBy = [hintId, errorId].filter(Boolean).join(" ") || undefined;
  return (
    <div className={className}>
      <label htmlFor={id} className="mb-1.5 block text-sm font-medium text-ink">
        {label}
      </label>
      <input
        id={id}
        ref={ref}
        value={value}
        onChange={(event) => onChange(event.target.value)}
        placeholder={placeholder}
        maxLength={maxLength}
        autoComplete="off"
        spellCheck={false}
        aria-invalid={error ? true : undefined}
        aria-describedby={describedBy}
        className={cn(
          "w-full rounded-lg border bg-white px-3 py-2 font-mono text-sm text-ink placeholder:text-stone-400 focus:border-saffron-500 focus:ring-2 focus:ring-saffron-500/20",
          error ? "border-decision-block" : "border-border",
        )}
      />
      {hint && (
        <p id={hintId} className="mt-1 text-xs text-muted">
          {hint}
        </p>
      )}
      {error && (
        <p id={errorId} className="mt-1 text-xs font-medium text-decision-block">
          {error}
        </p>
      )}
    </div>
  );
}
