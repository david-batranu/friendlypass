/**
 * Local HTTP pages for the Firefox suite (WP9).
 *
 * Everything is served from 127.0.0.1 on an ephemeral port, so database entries
 * match the real page URLs and no external network is used.
 */

import http from "node:http";

const LOGIN_PAGE = `<!doctype html><html><head><meta charset="utf-8"><title>Sign in</title></head>
<body>
<h1>Sign in</h1>
<form id="login-form" action="/login-done" method="post">
  <label>Username <input id="username" name="username" type="text" autocomplete="username"></label>
  <label>Password <input id="password" name="password" type="password" autocomplete="current-password"></label>
  <button id="submit" type="submit">Log in</button>
</form>
</body></html>`;

const SAVE_PAGE = `<!doctype html><html><head><meta charset="utf-8"><title>Create account</title></head>
<body>
<h1>Create account</h1>
<form id="signup-form" action="/save-done" method="post">
  <input id="username" name="username" type="text" autocomplete="username">
  <input id="password" name="password" type="password" autocomplete="new-password">
  <button id="submit" type="submit">Create account</button>
</form>
</body></html>`;

function plainPage(title) {
  return `<!doctype html><html><head><meta charset="utf-8"><title>${title}</title></head>
<body><h1>${title}</h1></body></html>`;
}

const PAGES = {
  "/login": LOGIN_PAGE,
  "/login-done": plainPage("Signed in"),
  "/save": SAVE_PAGE,
  "/save-done": plainPage("Account created"),
};

/**
 * @returns {Promise<{ baseUrl: string, close(): Promise<void> }>}
 */
export async function startPages() {
  const server = http.createServer((request, response) => {
    const url = new URL(request.url ?? "/", "http://127.0.0.1");
    if (request.method === "POST") {
      request.resume();
      const destination =
        url.pathname === "/login" || url.pathname === "/login-done"
          ? "/login-done"
          : "/save-done";
      response.writeHead(302, { location: destination });
      response.end();
      return;
    }
    const html = PAGES[url.pathname];
    if (!html) {
      response.writeHead(404, { "content-type": "text/plain" });
      response.end("not found");
      return;
    }
    response.writeHead(200, {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store",
    });
    response.end(html);
  });

  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      server.removeListener("error", reject);
      resolve();
    });
  });

  const address = server.address();
  return {
    baseUrl: `http://127.0.0.1:${address.port}`,
    close: async () => {
      await new Promise((resolve) => server.close(() => resolve()));
      server.closeAllConnections?.();
    },
  };
}
