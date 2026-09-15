import { createWorker } from "./http/router.js";
import { handlePublicRequest } from "./api/plan.js";
import { runScheduledMaintenance } from "./operations/maintenance.js";

const worker = createWorker({ business: handlePublicRequest });
export default {
  fetch: worker.fetch,
  async scheduled(controller, env) {
    await runScheduledMaintenance({
      db: env.DB,
      bucket: env.AUDIT_ARCHIVE,
      token: env.CLOUDFLARE_DNS_TOKEN,
      scheduledTime: controller.scheduledTime,
    });
  },
};
