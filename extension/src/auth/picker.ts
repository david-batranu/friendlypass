/**
 * friendlypass HTTP-auth login picker (WP5).
 *
 * Opened by the service worker as a small popup window while a Basic/Digest
 * challenge is held. The window only ever receives labels (login, title,
 * group) and the entry UUID; passwords stay in the service worker and are
 * never rendered or persisted here.
 *
 * Messages:
 *   → { channel, action: "list", token }
 *   ← { ok: true, value: { origin, realm, entries: [{uuid,login,name,group}] } }
 *   → { channel, action: "choose", token, uuid }
 *   → { channel, action: "cancel", token }
 */

const CHANNEL = "friendlypass-http-auth";

interface PickerEntry {
  uuid: string;
  login: string;
  name: string;
  group: string;
}

interface PickerList {
  origin: string;
  realm: string | null;
  entries: PickerEntry[];
}

interface PickerReply {
  ok?: boolean;
  value?: PickerList | null;
  error?: string;
}

function tokenFromLocation(): string {
  try {
    return new URLSearchParams(window.location.search).get("token") ?? "";
  } catch {
    return "";
  }
}

function send(message: Record<string, unknown>): Promise<PickerReply> {
  return new Promise((resolve) => {
    try {
      chrome.runtime.sendMessage(
        { channel: CHANNEL, ...message },
        (response: unknown) => {
          const lastError = chrome.runtime.lastError;
          if (lastError) {
            resolve({ ok: false, error: lastError.message });
            return;
          }
          resolve(
            typeof response === "object" && response !== null
              ? (response as PickerReply)
              : { ok: false, error: "No response from friendlypass" },
          );
        },
      );
    } catch (cause) {
      resolve({ ok: false, error: String(cause) });
    }
  });
}

function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  className?: string,
  text?: string,
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function renderList(list: PickerList, token: string): void {
  const context = document.getElementById("context");
  if (context) {
    const realm = list.realm ? ` · realm “${list.realm}”` : "";
    context.textContent = `${list.origin}${realm}`;
  }

  const container = document.getElementById("entries");
  if (!container) return;
  container.textContent = "";

  if (list.entries.length === 0) {
    container.append(el("p", "status", "No matching logins."));
    return;
  }

  for (const entry of list.entries) {
    const button = el("button", "entry");
    button.type = "button";
    button.append(el("span", "login", entry.login || "(no username)"));
    const meta = [entry.name, entry.group].filter((value) => value.length > 0);
    if (meta.length > 0) {
      button.append(el("span", "meta", meta.join(" · ")));
    }
    button.addEventListener("click", () => {
      button.disabled = true;
      void send({ action: "choose", token, uuid: entry.uuid }).finally(() => {
        window.close();
      });
    });
    container.append(button);
  }

  const first = container.querySelector<HTMLButtonElement>("button.entry");
  first?.focus();
}

async function main(): Promise<void> {
  const token = tokenFromLocation();
  const container = document.getElementById("entries");
  const cancel = document.getElementById("cancel");

  const closeWithCancel = (): void => {
    void send({ action: "cancel", token }).finally(() => {
      window.close();
    });
  };

  cancel?.addEventListener("click", closeWithCancel);
  window.addEventListener("keydown", (event) => {
    if (event.key === "Escape") {
      event.preventDefault();
      closeWithCancel();
    }
  });

  if (!token) {
    if (container) {
      container.textContent = "";
      container.append(el("p", "status", "This picker was opened incorrectly."));
    }
    return;
  }

  const reply = await send({ action: "list", token });
  if (!reply.ok || !reply.value) {
    if (container) {
      container.textContent = "";
      container.append(
        el("p", "status", reply.error ?? "This login request expired."),
      );
    }
    return;
  }
  renderList(reply.value, token);
}

void main().catch((cause: unknown) => {
  const container = document.getElementById("entries");
  if (container) {
    container.textContent = "";
    container.append(el("p", "status", `Could not load logins: ${String(cause)}`));
  }
});
