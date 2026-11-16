import { useId, useState, type ReactNode } from "react";
import { Button } from "../ui/Button";
import { copyCommand, type VerifyCommand } from "../../lib/evidence";

/** One command in a selectable code block, with a Copy button and its own status region. */
function CommandBlock({ item }: { item: VerifyCommand }) {
  const codeId = useId();
  const [status, setStatus] = useState("");

  async function copy() {
    // Only ever from this click: the console never writes to the clipboard on its own.
    setStatus("");
    setStatus(await copyCommand(item.command));
  }

  return (
    <li className="space-y-1.5">
      <p className="text-sm font-medium text-ink">{item.label}</p>
      <div className="flex flex-col gap-2 sm:flex-row sm:items-start">
        <pre className="flex-1 overflow-x-auto rounded-lg bg-stone-50 p-3 text-xs text-ink">
          <code id={codeId} className="select-all font-mono whitespace-pre-wrap break-all">
            {item.command}
          </code>
        </pre>
        <Button
          variant="ghost"
          size="sm"
          onClick={copy}
          aria-label={`Copy: ${item.label}`}
          aria-describedby={codeId}
        >
          Copy
        </Button>
      </div>
      <p className="text-xs text-muted">{item.note}</p>
      <p role="status" aria-live="polite" className="text-xs font-medium text-kavach-700">
        {status}
      </p>
    </li>
  );
}

type VerifyCommandsProps = {
  commands: VerifyCommand[];
  /** What these commands can establish, in the verifiers' words. */
  children?: ReactNode;
};

/** The commands that check a record offline. The console runs none of them. */
export function VerifyCommands({ commands, children }: VerifyCommandsProps) {
  const headingId = useId();
  return (
    <section aria-labelledby={headingId} className="space-y-3">
      <h3 id={headingId} className="text-sm font-semibold text-ink">
        Verify it yourself
      </h3>
      <p className="text-sm text-ink">
        The console does not verify signatures or hashes: it shows what the API returned. Run one of
        these where you keep your trusted keys and exports. Replace the example paths with yours.
      </p>
      {children}
      <ul className="space-y-4">
        {commands.map((item) => (
          <CommandBlock key={item.command} item={item} />
        ))}
      </ul>
    </section>
  );
}
