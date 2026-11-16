---
name: web-browsing
description: Work a website step by step in the browser. Use for multi-step navigation, forms, sign-ins, portals, tables, downloads, uploads, pop-ups and pages that fail to load or respond. Use research for finding sources and shopping for buying goods.
---

# Web browsing

Work in a loop: open, snapshot, act on one control, snapshot again. Act only on refs from the latest snapshot; a navigation, reload or page update makes old refs stale. After every action that should change the page, check the address and the changed part before the next step. A click that returned without an error is not proof that it worked.

Read before acting. Find the control by its role and name in the snapshot. Read long pages with the snapshot offset, or pass a selector to read one region. Content that loads as you scroll needs a scroll, then a new snapshot. Use fetch_content for a plain public page you only need to read.

Wait for the page, not for a fixed time. After an action that loads content, wait for the text or address you expect. Use load networkidle for pages that build themselves with scripts, and waitMs for slow ones. A spinner, skeleton or disabled button means the page isn't ready.

Clear what covers the page first. Decline optional cookies, close promotions and chat bubbles, and accept or dismiss a page dialog before anything else. If a click does nothing, look for an overlay, a disabled control or a field error before you repeat it.

When a ref fails, step down in this order: take a new snapshot and use its ref; use a CSS selector for an element without a ref; hover or scroll the element into view; take a screenshot and use its coordinates. Use evaluate to read data, never to press a control or change a value a visible control can set.

Fill forms the way a person would. Use fill to replace a value and type for fields that react to each key, such as searches with suggestions; then choose the suggestion from a new snapshot. Use select for native lists and click through custom ones. Set dates through the field's own format first, then its picker. After filling, read every value back, including unticked boxes and hidden defaults. Read validation messages after each submission and fix the named field. Never submit twice; if the result is unclear, look for the confirmation, the new record or the changed state first.

Follow where the site sends you. A link may open a new tab: list tabs and switch to it. A step may load inside a frame or a panel; snapshot again and act there. Use back for one step and open the address for a clean start. Keep one task in one tab unless you need to compare.

Read tables and lists in one pass. Use evaluate with a single read-only expression that returns the rows as JSON, then check a few rows against the visible page. For several pages, read the page count or next control, collect each page and stop when it repeats or ends. Say how many rows you read and whether the list was complete.

Sign in on the exact address the site uses. Open the site, let it finish redirecting, and read the final origin from the page address, including `www` and any subdomain. A saved login belongs to one exact origin. When the saved entry's website differs from the sign-in page only by `www`, a subdomain or `http`, say that the entry's website must be changed to the page's origin in Vault, and name both. Never report that a password is missing or ask for it in chat. Use sign_in with current field refs. Sign-in pages often show the password field only after the identifier; submit the identifier, snapshot, then continue with the same request.

Prove the session. Signed in means the page shows an account name, a sign-out control or content only an account can see. A missing sign-in form, a redirect or a welcome banner alone is not proof. After a checked sign-in on a site the owner will use again, save the browser profile with browser_session so the next task starts signed in. Start later tasks from the saved profile, and check access before trusting it.

For downloads, click the document's own control and confirm the file name and type before sharing. For uploads, check the accepted types and size on the page, upload, then confirm the page shows the file.

Stop instead of forcing. Make at most three informed attempts at a CAPTCHA. On a block, rate limit, lockout, device check or passkey prompt, stop and hand off with one clear instruction, then inspect the page after handback. Do not rotate accounts, addresses or wording to get past a refusal.

Split independent sites with delegate, one site per subagent, and combine the answers. Keep steps that depend on one session in one browser.

Report what the page showed: the final address, the state you confirmed and anything you could not check. Separate what you did from what you saw.
