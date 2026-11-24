/**
 * WP4 field-detection tests — port of upstream `tests/tests.html`.
 *
 * Upstream loads the whole content-script bundle into a Playwright page. This
 * port loads `dist/content/testing.js`, which exposes the same pure DOM
 * functions the production content script uses (`src/content/*`). Layout is
 * real Chromium layout, so visibility cases behave like the oracle.
 */

import { expect, test } from "@playwright/test";
import { fileURLToPath } from "node:url";

const TEST_API_PATH = fileURLToPath(
  new URL("../../dist/content/testing.js", import.meta.url),
);

const FIXTURE_HTML = `<!doctype html>
<html><head><meta charset="utf-8"><title>friendlypass content tests</title>
<style>.hiddenOne { visibility: hidden; }</style></head>
<body>
  <div id="basic1" style="display:none">
    <input placeholder="username" type="text" name="loginField">
    <input placeholder="password" type="password" name="passwordField">
  </div>

  <div id="basic2" style="display:none">
    <input placeholder="username" type="text" name="loginField">
  </div>

  <div id="basic3" style="display:none">
    <input placeholder="password" type="password" name="passwordField">
  </div>

  <div id="basic4" style="display:none">
    <input placeholder="username" type="text" name="loginField">
    <input placeholder="password" type="password" name="passwordField">
    <input type="text" id="auth">
  </div>

  <div id="div1" style="display:none">
    <button id="toggle1">View login form</button>
    <div id="loginForm1" style="display:none">
      <input placeholder="username" type="text" name="loginField">
      <input placeholder="password" type="password" name="passwordField">
    </div>
  </div>

  <div id="div2" style="display:none">
    <button id="toggle2">View login form</button>
    <div id="dialog" style="position: relative; z-index: auto;">
      <div id="outer" style="overflow: hidden; height: 0px;">
        <div id="inner" style="margin: -197px auto auto;">
          <form method="post" class="signin" action="#">
            <input placeholder="username" type="text" name="loginField">
            <input placeholder="password" type="password" name="passwordField">
          </form>
        </div>
      </div>
    </div>
  </div>

  <div id="hiddenFields1" style="display:none">
    <div style="position: absolute; margin-left: -500px;">
      <input placeholder="outsideLeft" type="password" name="outsideLeft">
    </div>
    <div style="position: absolute; top: -500px;">
      <input placeholder="outsideTop" type="password" name="outsideTop">
    </div>
  </div>

  <div id="hiddenFields2" style="display:none">
    <div>
      <input placeholder="zeroSize" type="password" name="zeroSize" style="width:0;height:0">
      <input placeholder="oneSize" type="password" name="oneSize" style="width:1px;height:1px">
      <input placeholder="visibilityHidden" type="password" name="visibilityHidden" style="visibility:hidden">
      <input placeholder="displayNone" type="password" name="displayNone" style="display:none">
      <input placeholder="hiddenOne" type="password" name="hiddenOne" class="hiddenOne">
      <input placeholder="normal" type="password" name="normal">
    </div>
  </div>

  <div id="passwordChange1" style="display:none">
    <input type="password" name="Old password" value="oldPassword">
    <input type="password" name="New password" value="newPassword">
    <input type="password" name="Repeat password" value="newPassword">
  </div>

  <div id="passwordChange2" style="display:none">
    <input type="password" name="New password" value="newPassword">
    <input type="password" name="Repeat password" value="newPassword">
    <input type="password" name="Old password" value="oldPassword">
  </div>

  <div id="passwordChange3" style="display:none">
    <form action="secondPage">
      <input type="password" name="Old password" value="oldPassword">
      <input type="password" name="New password" value="newPassword">
      <input type="password" name="Repeat password" value="newPassword">
      <input type="submit" value="Change password">
    </form>
  </div>

  <div id="passwordChange4" style="display:none">
    <form action="secondPage">
      <input type="password" name="New password" value="newPassword">
      <input type="password" name="Repeat password" value="newPassword">
      <input type="password" name="Old password" value="oldPassword">
      <input type="submit" value="Change password">
    </form>
  </div>

  <div id="passwordChange5" style="display:none">
    <form action="firstForm"><input type="password" name="Old password" value="oldPassword"></form>
    <form action="secondForm"><input type="password" name="New password" value="newPassword"></form>
    <form action="thirdForm"><input type="password" name="Repeat password" value="newPassword"></form>
  </div>

  <div id="searchCases"></div>
  <div id="shadowHost"></div>
  <script>
    document.getElementById('toggle1').addEventListener('click', () => {
      const form = document.getElementById('loginForm1');
      form.style.display = form.style.display === 'none' ? 'block' : 'none';
    });
    document.getElementById('toggle2').addEventListener('click', () => {
      const dialog = document.getElementById('dialog');
      const outer = document.getElementById('outer');
      const inner = document.getElementById('inner');
      if (dialog.style.zIndex === 'auto') {
        dialog.style.zIndex = '9999';
        inner.style.margin = '0px';
        outer.style.height = 'auto';
      }
    });
  </script>
</body></html>`;

interface ContentTestApi {
  getInputs(root: ParentNode, options?: { ignoreVisibility?: boolean }): HTMLInputElement[];
  collectInputs(root: ParentNode): HTMLInputElement[];
  buildCombinations(inputs: HTMLInputElement[]): unknown[];
  getNewPassword(inputs: HTMLInputElement[]): string;
  isSearchField(input: HTMLInputElement): boolean;
  isTOTPField(input: HTMLInputElement): boolean;
  isVisible(input: HTMLElement): boolean;
}

declare global {
  interface Window {
    __friendlypassContentTest: ContentTestApi;
  }
}

test.beforeEach(async ({ page }) => {
  await page.setContent(FIXTURE_HTML, { waitUntil: "load" });
  await page.addScriptTag({ path: TEST_API_PATH });
  await page.waitForFunction(() => Boolean(window.__friendlypassContentTest));
});

test("input field matching", async ({ page }) => {
  const cases: Array<[string, number, string?]> = [
    ["basic1", 2],
    ["basic2", 1],
    ["basic3", 1],
    ["basic4", 3],
    ["div1", 2, "#toggle1"],
    ["div2", 2, "#toggle2"],
    ["hiddenFields1", 0],
  ];

  for (const [divId, expected, action] of cases) {
    const result = await page.evaluate(
      ({ divId: id, action: selector }) => {
        const container = document.getElementById(id) as HTMLElement;
        container.style.display = "block";
        if (selector) {
          (container.querySelector(selector) as HTMLElement | null)?.click();
        }
        const api = window.__friendlypassContentTest;
        const inputs = api.getInputs(container);
        const combinations = api.buildCombinations(inputs);
        container.style.display = "none";
        return { count: inputs.length, combinations: combinations.length };
      },
      { divId, action },
    );

    expect(result.count, `getInputs() for ${divId}`).toBe(expected);
  }
});

test("hidden fields are excluded except the visible one", async ({ page }) => {
  const result = await page.evaluate(() => {
    const container = document.getElementById("hiddenFields2") as HTMLElement;
    container.style.display = "block";
    const api = window.__friendlypassContentTest;
    const inputs = api.getInputs(container);
    container.style.display = "none";
    return inputs.map((input) => input.name);
  });
  expect(result).toEqual(["normal"]);
});

test("search fields", async ({ page }) => {
  const cases: Array<[string, Record<string, string>, boolean]> = [
    ["", { id: "otp_field", name: "otp", type: "text", maxlength: "8" }, false],
    ["", { placeholder: "search", type: "text", id: "username" }, true],
    ["", { "aria-label": "search", type: "text", id: "username" }, true],
    ["", { type: "search", name: "q" }, true],
  ];

  for (const [className, properties, expected] of cases) {
    const actual = await page.evaluate(
      ({ className: classes, properties: props }) => {
        const input = document.createElement("input");
        if (classes) {
          input.className = classes;
        }
        for (const [name, value] of Object.entries(props)) {
          if (name === "maxlength") {
            input.setAttribute("maxlength", value);
          } else {
            input.setAttribute(name, value);
          }
        }
        document.body.append(input);
        const result = window.__friendlypassContentTest.isSearchField(input);
        input.remove();
        return result;
      },
      { className, properties },
    );
    expect(actual, `search field ${JSON.stringify(properties)}`).toBe(expected);
  }

  const underSearchForm = await page.evaluate(() => {
    const form = document.createElement("form");
    form.setAttribute("action", "search");
    const input = document.createElement("input");
    input.setAttribute("type", "text");
    form.append(input);
    document.body.append(form);
    const result = window.__friendlypassContentTest.isSearchField(input);
    form.remove();
    return result;
  });
  expect(underSearchForm, "generic input under search form").toBe(true);
});

test("a search-only page has no login combinations", async ({ page }) => {
  const combinations = await page.evaluate(() => {
    const container = document.getElementById("searchCases") as HTMLElement;
    container.innerHTML =
      '<form action="/search"><input type="search" name="q" placeholder="Search">' +
      '<input type="text" name="alsoSearch" placeholder="search"></form>' +
      '<div role="search"><input type="text" name="roleSearch"></div>';
    const api = window.__friendlypassContentTest;
    const inputs = api.getInputs(container);
    const combos = api.buildCombinations(inputs);
    container.innerHTML = "";
    return combos.length;
  });
  expect(combinations).toBe(0);
});

test("TOTP field detection", async ({ page }) => {
  const cases: Array<[string, Record<string, string | number>, boolean]> = [
    ["", { id: "otp_field", name: "otp", type: "text", maxLength: "8" }, true],
    ["", { id: "2fa", type: "text", maxLength: "6" }, true],
    ["", { id: "2fa", type: "text", maxLength: "4" }, false],
    ["", { id: "2fa", type: "text", maxLength: "12" }, false],
    ["", { id: "promocode", type: "text" }, false],
    ["", { id: "Promotional Code", type: "text" }, false],
    ["", { id: "postcode", type: "text" }, false],
    ["", { id: "postalcode", type: "text" }, false],
    ["", { id: "encode", type: "text" }, false],
    ["", { id: "encodedText", type: "text" }, false],
    ["", { id: "decoder", type: "text" }, false],
    ["", { id: "code", type: "text" }, true],
    ["", { id: "2fa", type: "text", maxLength: "12", autocomplete: "one-time-code" }, true],
    ["", { id: "username", type: "text" }, false],
    ["", { type: "password" }, false],
    [
      "TwoFA-input ng-empty ng-invalid",
      {
        autocapitalize: "off",
        autocorrect: "off",
        id: "twoFactorCode",
        type: "text",
        placeholder: "Two-factor passcode",
        name: "twoFactorCode",
      },
      true,
    ],
    [
      "",
      {
        minlength: "6",
        maxLength: "10",
        name: "challenge",
        placeholder: "Authentication code",
        type: "tel",
      },
      true,
    ],
    [
      "whsOnd zHQkBf",
      {
        autocomplete: "off",
        id: "idvPin",
        tabindex: "0",
        name: "idvPin",
        pattern: "[0-9 ]*",
        type: "tel",
        spellcheck: "false",
      },
      true,
    ],
    [
      "form-control",
      {
        autocomplete: "off",
        id: "idTxtBx_SAOTCC_OTC",
        maxLength: "8",
        tabindex: "0",
        name: "otc",
        placeholder: "Code",
        type: "tel",
      },
      true,
    ],
  ];

  for (const [className, properties, expected] of cases) {
    const actual = await page.evaluate(
      ({ className: classes, properties: props }) => {
        const input = document.createElement("input");
        if (classes) {
          input.className = classes;
        }
        for (const [name, value] of Object.entries(props)) {
          const attribute = name === "maxLength" ? "maxlength" : name;
          input.setAttribute(attribute, String(value));
        }
        document.body.append(input);
        const result = window.__friendlypassContentTest.isTOTPField(input);
        input.remove();
        return result;
      },
      { className, properties },
    );
    expect(actual, `TOTP field ${JSON.stringify(properties)}`).toBe(expected);
  }
});

test("password change forms pick the new password", async ({ page }) => {
  const cases: Array<[string, string]> = [
    ["passwordChange1", "newPassword"],
    ["passwordChange2", "newPassword"],
    ["passwordChange3", "newPassword"],
    ["passwordChange4", "newPassword"],
    ["passwordChange5", "newPassword"],
  ];

  for (const [divId, expected] of cases) {
    const actual = await page.evaluate((id) => {
      const container = document.getElementById(id) as HTMLElement;
      container.style.display = "block";
      const api = window.__friendlypassContentTest;
      const inputs = api.getInputs(container, { ignoreVisibility: true });
      const value = api.getNewPassword(inputs);
      container.style.display = "none";
      return value;
    }, divId);
    expect(actual, `new password for ${divId}`).toBe(expected);
  }
});

test("inputs inside an open shadow root are detected", async ({ page }) => {
  const result = await page.evaluate(() => {
    const host = document.getElementById("shadowHost") as HTMLElement;
    const root = host.attachShadow({ mode: "open" });
    root.innerHTML =
      '<form action="/shadow"><input name="username" type="text" autocomplete="username">' +
      '<input name="password" type="password"><input name="totp" type="text" maxlength="6"></form>';
    const api = window.__friendlypassContentTest;
    const inputs = api.getInputs(document);
    const combinations = api.buildCombinations(inputs);
    root.innerHTML = "";
    return {
      inputs: inputs.length,
      combinations: combinations.length,
    };
  });
  expect(result.inputs).toBe(3);
  expect(result.combinations).toBeGreaterThanOrEqual(2);
});
