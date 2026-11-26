/**
 * `disableBrowserPasswordManager`: the extension takes over the browser's
 * `privacy.services.passwordSavingEnabled` and hands it back when the option is
 * turned off.
 */

import { describe, expect, it } from "vitest";

import {
  applyBrowserPasswordManager,
  type PasswordSavingSetting,
} from "../../src/background/browser-passwords";

function fakeSetting(level: string): PasswordSavingSetting & { calls: string[]; value: boolean } {
  const fake = {
    calls: [] as string[],
    value: true,
    level,
    get(_details: Record<string, never>, callback: (details: { value: unknown; levelOfControl?: string }) => void) {
      fake.calls.push("get");
      callback({ value: fake.value, levelOfControl: fake.level });
    },
    set(details: { value: boolean }, callback?: () => void) {
      fake.calls.push(`set:${details.value}`);
      fake.value = details.value;
      fake.level = "controlled_by_this_extension";
      callback?.();
    },
    clear(_details: Record<string, never>, callback?: () => void) {
      fake.calls.push("clear");
      fake.value = true;
      fake.level = "controllable_by_this_extension";
      callback?.();
    },
  };
  return fake;
}

describe("applyBrowserPasswordManager", () => {
  it("turns the browser's password saving off when enabled", async () => {
    const setting = fakeSetting("controllable_by_this_extension");
    expect(await applyBrowserPasswordManager(true, setting)).toBe("disabled");
    expect(setting.value).toBe(false);
    expect(setting.calls).toContain("set:false");
  });

  it("hands the setting back when the option is turned off", async () => {
    const setting = fakeSetting("controllable_by_this_extension");
    await applyBrowserPasswordManager(true, setting);
    expect(await applyBrowserPasswordManager(false, setting)).toBe("released");
    expect(setting.value).toBe(true);
    expect(setting.calls).toContain("clear");
  });

  it("does not clear a setting it never controlled", async () => {
    const setting = fakeSetting("controllable_by_this_extension");
    expect(await applyBrowserPasswordManager(false, setting)).toBe("released");
    expect(setting.calls).not.toContain("clear");
  });

  it("leaves a setting owned by policy or another extension alone", async () => {
    for (const level of ["not_controllable", "controlled_by_other_extensions"]) {
      const setting = fakeSetting(level);
      expect(await applyBrowserPasswordManager(true, setting)).toBe("controlled_by_other");
      expect(setting.calls).toEqual(["get"]);
    }
  });

  it("reports a browser without the privacy API", async () => {
    expect(await applyBrowserPasswordManager(true, null)).toBe("unavailable");
  });

  it("never throws when the browser call fails", async () => {
    const setting = fakeSetting("controllable_by_this_extension");
    setting.set = () => {
      throw new Error("boom");
    };
    expect(await applyBrowserPasswordManager(true, setting)).toBe("error");
  });
});
