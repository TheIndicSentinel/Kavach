// The UI-2 stop dialog driven by the keyboard alone: focus moves in, stays in,
// Escape cancels, and focus goes back. Also the role-aware change-request
// buttons, which depend on who the console knows it is.
import type { Locator, Page } from "@playwright/test";
import { expect, test } from "./api";

const AGENT = "/agents/agent:collections-bot";

/** Presses Tab until `target` has focus; fails if it never does. */
async function tabTo(page: Page, target: Locator, limit = 60) {
  for (let i = 0; i < limit; i++) {
    if (await target.evaluate((el) => el === document.activeElement)) return;
    await page.keyboard.press("Tab");
  }
  await expect(target).toBeFocused();
}

async function focusInside(dialog: Locator): Promise<boolean> {
  return dialog.evaluate((el) => el.contains(document.activeElement));
}

test.describe("stop dialog from the keyboard", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto(AGENT);
    await expect(page.getByRole("status").filter({ hasText: "is active" })).toBeVisible();
  });

  test("focus moves in, stays in, Escape cancels and focus returns", async ({ page, api }) => {
    const opener = page.getByRole("button", { name: "Quarantine", exact: true });
    await tabTo(page, opener);
    await page.keyboard.press("Enter");

    const dialog = page.getByRole("alertdialog");
    await expect(dialog).toBeVisible();
    await expect(dialog).toHaveAttribute("aria-modal", "true");
    await expect(dialog).toHaveAccessibleName(/Quarantine agent:collections-bot/);
    await expect(page.getByLabel("Reason code (required)")).toBeFocused();

    // reason, note, cancel, confirm: Tab and Shift+Tab both wrap inside.
    for (let i = 0; i < 6; i++) {
      await page.keyboard.press("Tab");
      expect(await focusInside(dialog)).toBe(true);
    }
    for (let i = 0; i < 6; i++) {
      await page.keyboard.press("Shift+Tab");
      expect(await focusInside(dialog)).toBe(true);
    }

    await page.keyboard.press("Escape");
    await expect(dialog).toHaveCount(0);
    await expect(opener).toBeFocused();
    expect(api.calls.map((c) => c.key)).not.toContain(
      "POST /v1/agents/agent:collections-bot/quarantine",
    );
  });

  test("confirming with no reason code puts focus on the reason code", async ({ page }) => {
    await tabTo(page, page.getByRole("button", { name: "Quarantine", exact: true }));
    await page.keyboard.press("Enter");
    await tabTo(page, page.getByRole("button", { name: "Quarantine agent" }));
    await page.keyboard.press("Enter");

    const reason = page.getByLabel("Reason code (required)");
    await expect(reason).toBeFocused();
    await expect(reason).toHaveAttribute("aria-invalid", "true");
    await expect(page.getByRole("alertdialog")).toBeVisible();
  });

  test("a confirmed stop reports its result and focus lands on the agent", async ({ page, api }) => {
    await tabTo(page, page.getByRole("button", { name: "Quarantine", exact: true }));
    await page.keyboard.press("Enter");

    // Type-ahead picks "Rogue behaviour"; Enter in the note submits the form.
    await page.keyboard.type("Rogue");
    await expect(page.getByLabel("Reason code (required)")).toHaveValue("rogue_behaviour");
    await page.keyboard.press("Tab");
    await page.keyboard.type("seen in e2e");
    await page.keyboard.press("Enter");

    await expect(page.getByRole("alertdialog")).toHaveCount(0);
    await expect(page.getByRole("status").filter({ hasText: "Evidence record" })).toBeVisible();
    // The Quarantine button is gone with the state it applied to.
    await expect(page.getByRole("heading", { name: "agent:collections-bot" })).toBeFocused();

    const stop = api.calls.find((c) => c.key === "POST /v1/agents/agent:collections-bot/quarantine");
    expect(stop?.body).toEqual({ reason_code: "rogue_behaviour", note: "seen in e2e" });
  });
});

test.describe("change requests and the signed-in principal", () => {
  async function asPrincipal(page: Page, principal: string) {
    await page.addInitScript((id) => sessionStorage.setItem("kavach.principal", id), principal);
  }

  test("the proposer gets no approve or reject button", async ({ page }) => {
    await asPrincipal(page, "operator-1"); // the fixture's proposer
    await page.goto("/changes");
    await expect(page.getByText("Reinstate agent")).toBeVisible();
    await expect(page.getByRole("button", { name: "Approve and apply" })).toHaveCount(0);
    await expect(page.getByRole("button", { name: "Reject" })).toHaveCount(0);
    await expect(page.getByRole("button", { name: "Cancel (proposer)" })).toBeVisible();
    await expect(page.getByText("a different principal approves or rejects it")).toBeVisible();
  });

  test("another principal gets approve and reject, not cancel", async ({ page }) => {
    await asPrincipal(page, "admin-2");
    await page.goto("/changes");
    await expect(page.getByRole("button", { name: "Approve and apply" })).toBeVisible();
    await expect(page.getByRole("button", { name: "Reject" })).toBeVisible();
    await expect(page.getByRole("button", { name: "Cancel (proposer)" })).toHaveCount(0);
  });

  test("with a token, every button stays and the API decides", async ({ page }) => {
    await page.addInitScript(() => {
      sessionStorage.setItem("kavach.principal", "operator-1");
      sessionStorage.setItem("kavach.accessToken", "not-a-real-token");
    });
    await page.goto("/changes");
    await expect(page.getByRole("button", { name: "Approve and apply" })).toBeVisible();
    await expect(page.getByRole("button", { name: "Reject" })).toBeVisible();
    await expect(page.getByRole("button", { name: "Cancel (proposer)" })).toBeVisible();
  });
});
