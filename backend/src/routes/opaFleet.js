import { Router } from "express";
import * as opaTracker from "../services/opaTracker.js";
import * as opaBundle from "../services/opaBundle.js";
import { authorize } from "../middleware/authorize.js";

export function createOpaFleetRouter() {
  const router = Router();

  router.get("/", authorize("read", "platform_key"), async (req, res) => {
    let bundle;
    try {
      bundle = await opaBundle.getBundle();
    } catch (e) {
      return res.status(500).json({ error: `Failed to load bundle status: ${e.message}` });
    }

    const currentRevision = bundle?.revision || "";
    const replicas = opaTracker.getReplicas();

    // Enrich replicas with the policies they are running
    const enrichedReplicas = replicas.map((rep) => {
      let runningPolicies = null;
      if (rep.reportedRevision) {
        runningPolicies = opaTracker.getPoliciesForRevision(rep.reportedRevision);
        // Fallback to current if reported matches current but policies not yet in cache
        if (!runningPolicies && rep.reportedRevision === currentRevision) {
          runningPolicies = opaTracker.getPoliciesForRevision(currentRevision);
        }
      }
      return {
        ...rep,
        policies: runningPolicies,
      };
    });

    const currentPolicies = opaTracker.getPoliciesForRevision(currentRevision) || [];

    res.json({
      currentRevision,
      replicas: enrichedReplicas,
      currentPolicies,
    });
  });

  return router;
}
