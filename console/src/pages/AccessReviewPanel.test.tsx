import { describe, expect, it } from "vitest";
import { render, text } from "../test/markup";
import { AccessReviewPanel } from "./AccessReviewPanel";

describe("AccessReviewPanel", () => {
  it("waits for an explicit request before loading the audited review", () => {
    const html = render(<AccessReviewPanel />);
    expect(text(html)).toContain("Load access review");
    expect(text(html)).toContain("Each review load and CSV export is recorded");
    expect(text(html)).not.toContain("Loading and auditing the access review");
    expect(text(html)).not.toContain("Download CSV");
  });
});
