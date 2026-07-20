/** @type {import('jest').Config} */
export default {
  preset: "ts-jest/presets/default-esm",
  testEnvironment: "node",
  extensionsToTreatAsEsm: [".ts"],
  moduleNameMapper: {
    // Strip .js from relative imports (../src/foo.js → ../src/foo)
    "^(\\.{1,2}/.*)\\.js$": "$1",
    // Explicitly resolve @noble packages — Jest can't handle their exports map
    "^@noble/curves/ed25519\\.js$": "<rootDir>/../../node_modules/@noble/curves/ed25519.js",
    "^@noble/hashes/hkdf\\.js$": "<rootDir>/../../node_modules/@noble/hashes/hkdf.js",
    "^@noble/hashes/hmac\\.js$": "<rootDir>/../../node_modules/@noble/hashes/hmac.js",
    "^@noble/hashes/sha2\\.js$": "<rootDir>/../../node_modules/@noble/hashes/sha2.js",
  },
  transform: {
    "^.+\\.tsx?$": [
      "ts-jest",
      {
        useESM: true,
        tsconfig: "./tsconfig.json",
      },
    ],
  },
  testMatch: ["**/tests/**/*.test.ts"],
};
