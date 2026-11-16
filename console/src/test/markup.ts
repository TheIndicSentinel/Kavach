// Helpers for tests that render to static markup (react-dom/server): the
// console has no DOM test environment, so these read the HTML string.
import type { ReactElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { createElement } from "react";

/** Renders `element` inside a router, as the app does. */
export function render(element: ReactElement): string {
  return renderToStaticMarkup(createElement(MemoryRouter, null, element));
}

/** The visible text of some markup: tags dropped, entities decoded, spaces collapsed. */
export function text(html: string): string {
  return html
    .replace(/<[^>]+>/g, " ")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&#x27;/g, "'")
    .replace(/&amp;/g, "&")
    .replace(/\s+/g, " ")
    .trim();
}

/**
 * The text inside every element with `role="<role>"`, in document order.
 * Elements of the same tag nested inside are counted so the right closing
 * tag ends each one.
 */
export function byRole(html: string, role: string): string[] {
  const found: string[] = [];
  const opener = new RegExp(`<([a-z0-9]+)[^>]*\\brole="${role}"[^>]*>`, "g");
  for (let match = opener.exec(html); match; match = opener.exec(html)) {
    const tag = match[1];
    const tags = new RegExp(`<(/?)${tag}\\b[^>]*>`, "g");
    tags.lastIndex = match.index + match[0].length;
    let depth = 1;
    let end = html.length;
    for (let t = tags.exec(html); t; t = tags.exec(html)) {
      depth += t[1] ? -1 : 1;
      if (depth === 0) {
        end = t.index;
        break;
      }
    }
    found.push(text(html.slice(match.index + match[0].length, end)));
  }
  return found;
}

/** Renders `element` as the route `pattern` (e.g. "/agents/:agentId") at `path`. */
export function renderAt(path: string, pattern: string, element: ReactElement): string {
  return renderToStaticMarkup(
    createElement(
      MemoryRouter,
      { initialEntries: [path] },
      createElement(Routes, null, createElement(Route, { path: pattern, element })),
    ),
  );
}
