// Keyboard-only helpers: Tab to a control, and sign in as a principal by the
// header the console sends in --insecure-dev.
import type { Locator, Page } from "@playwright/test";
import { expect } from "./page";

/** Presses Tab until `target` has focus; fails if it never does. */
export async function tabTo(page: Page, target: Locator, limit = 80) {
  for (let i = 0; i < limit; i++) {
    if (await target.evaluate((el) => el === document.activeElement)) return;
    await page.keyboard.press("Tab");
  }
  await expect(target).toBeFocused();
}

/** The principal header the console sends with no token (sessionStorage, as Settings saves it). */
export async function asPrincipal(page: Page, principal: string) {
  await page.addInitScript((id) => sessionStorage.setItem("kavach.principal", id), principal);
}
