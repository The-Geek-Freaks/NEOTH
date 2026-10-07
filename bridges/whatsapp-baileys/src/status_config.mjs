// Status transport remains disabled unless the sidecar operator opts in.
// This parser is isolated so the policy is source-testable without starting a
// bridge server or touching a linked WhatsApp account.
export function statusEditEnabledFromEnv(env = process.env) {
  return env?.NEOTH_WA_STATUS_EDIT_V1 === "1";
}
