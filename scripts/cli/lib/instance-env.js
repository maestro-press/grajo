/**
 * Side-effect module: the instance this command must agree with the gateway about.
 *
 * Imported FIRST by scripts/cli/mail-add.js — before servers/db.js, the instance registry, the mail
 * store, the keychain or anything else that resolves or caches a path — because it does what
 * servers/gateway/boot/run-instance-paths-gate.js does for the gateway: apply the checkout `.env`
 * (an already-set variable wins; CROW_APP_ENV_PATH is honoured, so a co-hosted instance can name its
 * own file) and then run `runInstancePathsGate` from servers/gateway/boot/instance-paths-gate.js.
 *
 * Reused, not copied, on purpose: a CLI that resolved its own paths would read and write a different
 * crow.db than the gateway on a host that runs more than one instance, and its "connected" account
 * would be invisible to Mail.
 *
 * Two things the gateway's boot does are deliberately NOT done here: the `[isolation]` report lines
 * (a one-shot command prints the single instance it writes to, in its own words) and the satellite
 * profile refusal (that is a gateway-host rule). The `.env` and the gate are what matter, and a
 * refused layout exits INSTANCE_PATHS_EXIT_CODE (78) exactly as the gateway does.
 */
import { runInstancePathsGate } from "../../../servers/gateway/boot/instance-paths-gate.js";

runInstancePathsGate();