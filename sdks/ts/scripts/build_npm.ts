import { build, emptyDir } from "jsr:@deno/dnt";

await emptyDir("./npm");

await build({
  test: false,
  entryPoints: [
    "./mod.ts",
    {
      name: "./attestation",
      path: "./attestation/mod.ts",
    },
  ],
  outDir: "./npm",
  shims: {
    // see JS docs for overview and more options
    deno: true,
    crypto: true,
  },
  package: {
    // package.json properties
    name: "@marlinorg/oyster-sdk",
    version: Deno.args[0],
    description: "Oyster SDK",
    license: "MIT",
    repository: {
      type: "git",
      url:
        "https://github.com/marlinprotocol/oyster-monorepo/tree/master/sdks/ts",
    },
    bugs: {
      url: "https://github.com/marlinprotocol/oyster-monorepo/issues",
    },
  },
  postBuild() {
    // steps to run after building and before running the tests
    // Deno.copyFileSync("LICENSE", "npm/LICENSE");
    // Deno.copyFileSync("README.md", "npm/README.md");
  },
});
