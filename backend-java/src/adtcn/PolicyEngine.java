package adtcn;

import java.util.*;

/**
 * Policy-gated autonomous response engine — same compound-condition
 * design as the Python prototype: a single weak signal never triggers
 * isolation on its own.
 */
public class PolicyEngine {

    private final Storage storage;

    public PolicyEngine(Storage storage) {
        this.storage = storage;
    }

    public static class Response {
        public String entityId, responseLevel, reason, actionTaken;
        public int threatScore;
        public double timestamp;
    }

    public Response decideResponse(String entityId, CorrelationEngine.ScoreReport report) {
        int score = report.threatScore;
        Set<String> signals = new HashSet<>(report.signals);

        boolean honeytokenTriggered = signals.contains("decoy_file_accessed")
                || signals.contains("decoy_credential_used");
        boolean lateralMovement = signals.contains("lateral_movement");
        boolean scanning = signals.contains("internal_scanning");
        boolean ransomware = signals.contains("ransomware_activity");

        if (ransomware) {
            return act(entityId, score, "EMERGENCY",
                    "Ransomware behavior detected; preserve the decoy evidence and contain the endpoint",
                    "ISOLATE_ENDPOINT + ENCRYPT_REMAINING_PC_SERVER_DATABASE_ASSETS + PRESERVE_DECOY_EVIDENCE");
        }

        if (honeytokenTriggered && lateralMovement && score > 80) {
            return act(entityId, score, "EMERGENCY",
                    "Decoy credential/file triggered AND lateral movement observed AND score > 80",
                    "ISOLATE_ENDPOINT + LOCK_ACCOUNT + NOTIFY_SOC");
        }
        if (honeytokenTriggered && score >= 60) {
            return act(entityId, score, "ISOLATE",
                    "Honeytoken interaction with high-confidence corroborating signals",
                    "ISOLATE_ENDPOINT");
        }
        if (scanning && score >= 60) {
            return act(entityId, score, "RESTRICT",
                    "Internal scanning behavior with elevated score",
                    "RESTRICT_NETWORK_EGRESS");
        }
        if (score >= 30) {
            return act(entityId, score, "INCREASE_MONITORING",
                    "Score crossed suspicious threshold",
                    "INCREASE_TELEMETRY_SAMPLING");
        }
        return act(entityId, score, "OBSERVE", "No significant signals", "NONE");
    }

    private Response act(String entityId, int score, String level, String reason, String action) {
        double timestamp = System.currentTimeMillis() / 1000.0;
        if (!level.equals("OBSERVE")) {
            storage.insertIncident(entityId, score, level, reason, action, timestamp);
        }
        Response r = new Response();
        r.entityId = entityId;
        r.threatScore = score;
        r.responseLevel = level;
        r.reason = reason;
        r.actionTaken = action;
        r.timestamp = timestamp;
        return r;
    }
}
