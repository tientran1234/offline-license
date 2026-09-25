import { mkdtemp, readdir, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { beforeEach, describe, expect, it } from "vitest";
import {
  issue,
  LicenseFileError,
  LICENSE_FILE_VERSION,
  readLicenseFile,
  verify,
  writeLicenseFile,
} from "../src/index.js";
import { at, claims, keys, NOW } from "./helpers.js";

const token = () => issue(keys.privateKey, claims());

let dir: string;
let path: string;

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "offline-license-file-"));
  path = join(dir, "license.json");
});

/** Put raw text where readLicenseFile will look, bypassing the writer. */
const given = (text: string) => writeFile(path, text, "utf8");

describe("a license file", () => {
  it("round-trips a token, its issuer and its notes", async () => {
    const t = token();
    await writeLicenseFile(path, { token: t, issuer: "Acme Ltd", notes: "renewal 2027" });

    expect(await readLicenseFile(path)).toEqual({
      version: LICENSE_FILE_VERSION,
      token: t,
      issuer: "Acme Ltd",
      notes: "renewal 2027",
    });
  });

  it("hands back a token that still verifies", async () => {
    await writeLicenseFile(path, { token: token() });
    const file = await readLicenseFile(path);
    expect(verify(keys.publicKey, file.token, { now: at(NOW) }).ok).toBe(true);
  });

  it("stamps the version itself and writes the optional fields only when given", async () => {
    await writeLicenseFile(path, { token: "lic1.aaa.bbb" });
    const written: unknown = JSON.parse(await readFile(path, "utf8"));
    expect(written).toEqual({ version: LICENSE_FILE_VERSION, token: "lic1.aaa.bbb" });
  });

  it("is indented JSON with the version first, so a review diffs line by line", async () => {
    await writeLicenseFile(path, { token: "lic1.aaa.bbb", issuer: "Acme Ltd" });
    expect(await readFile(path, "utf8")).toBe(
      `{\n  "version": 1,\n  "token": "lic1.aaa.bbb",\n  "issuer": "Acme Ltd"\n}\n`,
    );
  });

  it("creates the directory it is given", async () => {
    const nested = join(dir, "etc", "acme", "license.json");
    await writeLicenseFile(nested, { token: "lic1.aaa.bbb" });
    expect((await readLicenseFile(nested)).token).toBe("lic1.aaa.bbb");
  });

  it("replaces an existing file whole, leaving no temp file behind", async () => {
    await writeLicenseFile(path, { token: "lic1.aaa.bbb", notes: "a long note that the next write drops" });
    await writeLicenseFile(path, { token: "lic1.ccc.ddd" });

    // A rename cannot leave a tail of the old file, and must not leave the temp
    // one either: either would be a second "license" sitting next to the real one.
    expect(await readLicenseFile(path)).toEqual({ version: LICENSE_FILE_VERSION, token: "lic1.ccc.ddd" });
    expect(await readdir(dir)).toEqual(["license.json"]);
  });
});

describe("reading a file that is not one", () => {
  it("refuses a version this release does not know", async () => {
    await given(JSON.stringify({ version: 2, token: "lic1.aaa.bbb" }));
    await expect(readLicenseFile(path)).rejects.toThrow(LicenseFileError);
    await expect(readLicenseFile(path)).rejects.toThrow(/version 2/);
  });

  it("refuses a missing version, and a version that only looks like one", async () => {
    await given(JSON.stringify({ token: "lic1.aaa.bbb" }));
    await expect(readLicenseFile(path)).rejects.toThrow(LicenseFileError);

    await given(JSON.stringify({ version: "1", token: "lic1.aaa.bbb" }));
    await expect(readLicenseFile(path)).rejects.toThrow(LicenseFileError);
  });

  it("refuses a field it does not know, rather than dropping it on the next write", async () => {
    await given(JSON.stringify({ version: 1, token: "lic1.aaa.bbb", note: "mistyped" }));
    await expect(readLicenseFile(path)).rejects.toThrow(/unknown field: note/);
  });

  it("refuses an envelope with no usable token", async () => {
    for (const bad of [{}, { token: "" }, { token: 42 }, { token: ["lic1.aaa.bbb"] }]) {
      await given(JSON.stringify({ version: 1, ...bad }));
      await expect(readLicenseFile(path)).rejects.toThrow(/token must be a non-empty string/);
    }
  });

  it("refuses an empty issuer or notes, which say less than leaving them out", async () => {
    await given(JSON.stringify({ version: 1, token: "lic1.aaa.bbb", issuer: "" }));
    await expect(readLicenseFile(path)).rejects.toThrow(/issuer/);

    await given(JSON.stringify({ version: 1, token: "lic1.aaa.bbb", notes: 7 }));
    await expect(readLicenseFile(path)).rejects.toThrow(/notes/);
  });

  it("refuses text that is not JSON, and JSON that is not an object", async () => {
    await given("lic1.aaa.bbb\n"); // the bare token, as an older tool wrote it
    await expect(readLicenseFile(path)).rejects.toThrow(/not JSON/);

    await given(JSON.stringify(["lic1.aaa.bbb"]));
    await expect(readLicenseFile(path)).rejects.toThrow(/expected a JSON object/);
  });

  it("reports a missing file as ENOENT, not as a broken envelope", async () => {
    // "No license installed" is a state the product handles; "the license file
    // is corrupt" is one it reports. Collapsing them would hide the second.
    await expect(readLicenseFile(join(dir, "absent.json"))).rejects.toMatchObject({ code: "ENOENT" });
  });
});

describe("the envelope as a trust boundary", () => {
  it("is not one: issuer and notes are outside the signature", async () => {
    // Anyone with the file can rewrite them, so nothing may depend on them —
    // the test pins that the reader reports them as written, untouched, and
    // that the verdict comes from the token alone.
    await writeLicenseFile(path, { token: token(), issuer: "Acme Ltd" });
    const text = await readFile(path, "utf8");
    await given(text.replace("Acme Ltd", "Someone Else"));

    const file = await readLicenseFile(path);
    expect(file.issuer).toBe("Someone Else");
    expect(verify(keys.publicKey, file.token, { now: at(NOW) }).ok).toBe(true);
  });

  it("reads a token it cannot vouch for, and leaves the verdict to verify()", async () => {
    const [prefix, payload] = token().split(".") as [string, string, string];
    await writeLicenseFile(path, { token: `${prefix}.${payload}.${"A".repeat(86)}` });

    const file = await readLicenseFile(path);
    expect(verify(keys.publicKey, file.token, { now: at(NOW) })).toEqual({
      ok: false,
      reason: "invalid_signature",
    });
  });
});

describe("writing an envelope a reader would refuse", () => {
  it("fails at the call, not at the next read", async () => {
    // JavaScript callers get no help from the types, and a file that cannot be
    // read back is worse than no file: it looks like a license.
    await expect(writeLicenseFile(path, { token: "" } as never)).rejects.toThrow(LicenseFileError);
    await expect(writeLicenseFile(path, { token: token(), issuer: 7 } as never)).rejects.toThrow(LicenseFileError);
    expect(await readdir(dir)).toEqual([]);
  });
});
