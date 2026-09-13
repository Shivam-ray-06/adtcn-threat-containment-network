package adtcn;

import java.util.*;

/**
 * Correlation / risk-scoring engine — mirrors the Python prototype's
 * logic exactly (same weight table, same sliding window, same
 * "no single weak signal proves compromise" design principle).
 */
public class CorrelationEngine {

    public static final double WINDOW_SECONDS = 15 * 60; // 15 minutes

    private static final Map<String, Integer> WEIGHTS = new HashMap<>();
    private static final Map<String, AttackProfile> ATTACK_PROFILES = new HashMap<>();
    static {
        WEIGHTS.put("unusual_process", 10);
        WEIGHTS.put("internal_scanning", 20);
        WEIGHTS.put("suspicious_external_connection", 20);
        WEIGHTS.put("decoy_file_accessed", 30);
        WEIGHTS.put("decoy_credential_used", 40);
        WEIGHTS.put("privilege_escalation", 30);
        WEIGHTS.put("lateral_movement", 25);
        WEIGHTS.put("ransomware_activity", 45);
        WEIGHTS.put("phishing", 25);
        WEIGHTS.put("social_engineering", 25);
        WEIGHTS.put("ddos", 30);
        WEIGHTS.put("brute_force", 30);
        WEIGHTS.put("sql_injection", 30);
        WEIGHTS.put("man_in_the_middle", 30);

        ATTACK_PROFILES.put("unusual_process", new AttackProfile(
                "Suspicious execution", "Initial access / execution",
                "An attacker launches an encoded or unusual process to establish control.",
                "The AI flags rare process behavior and high-risk command-line patterns, then correlates it with later signals."));
        ATTACK_PROFILES.put("internal_scanning", new AttackProfile(
                "Internal discovery", "Discovery",
                "The compromised host probes many internal destinations to map reachable systems.",
                "The network sensor counts distinct destinations in a sliding window and raises a discovery signal when the threshold is crossed."));
        ATTACK_PROFILES.put("decoy_file_accessed", new AttackProfile(
                "Credential access", "Credential access",
                "The attacker opens a planted credential file while hunting for secrets.",
                "The endpoint agent detects access to a tracked honeyfile and links the event to its unique decoy identity."));
        ATTACK_PROFILES.put("decoy_credential_used", new AttackProfile(
                "Credential access", "Credential access",
                "The attacker attempts authentication with a credential that was planted as bait.",
                "A honeytoken match provides a high-confidence identity signal and corroborates the file-access event."));
        ATTACK_PROFILES.put("privilege_escalation", new AttackProfile(
                "Privilege escalation", "Privilege escalation",
                "The attacker attempts to move from a normal user context to administrator-level control.",
                "The AI correlates the escalation event with the host score and prior execution signals before increasing containment."));
        ATTACK_PROFILES.put("lateral_movement", new AttackProfile(
                "Lateral movement", "Lateral movement",
                "The attacker uses the compromised host or stolen credentials to reach another system.",
                "The graph path and authenticated destination are correlated with the originating entity to identify movement."));
        ATTACK_PROFILES.put("suspicious_external_connection", new AttackProfile(
                "Command and control", "Command and control",
                "The compromised host makes an unusual first contact with a sensitive destination.",
                "The network sensor detects first-time communication with a sensitive host and supplies destination context."));
        ATTACK_PROFILES.put("ransomware_activity", new AttackProfile(
                "Ransomware impact", "Impact",
                "The attacker begins rapid encryption or destructive file activity to disrupt operations.",
                "The AI identifies a burst of high-risk file changes and combines it with the host's prior attack chain."));
        ATTACK_PROFILES.put("phishing", new AttackProfile(
                "Phishing", "Initial access",
                "A deceptive message redirects a user to a malicious link or credential capture page.",
                "The AI correlates sender reputation, lookalike domains, link indicators, and the recipient's click telemetry."));
        ATTACK_PROFILES.put("social_engineering", new AttackProfile(
                "Social engineering", "Initial access",
                "An attacker manipulates a person or trusted workflow to bypass normal safeguards.",
                "The AI spots urgency, authority spoofing, unusual approval paths, and requests outside the user's baseline."));
        ATTACK_PROFILES.put("ddos", new AttackProfile(
                "DDoS", "Impact",
                "Distributed traffic overwhelms an edge, service, or application until availability degrades.",
                "The AI detects traffic bursts, source spread, elevated errors, and deviation from the service's normal profile."));
        ATTACK_PROFILES.put("brute_force", new AttackProfile(
                "Brute force", "Credential access",
                "Repeated authentication attempts guess or validate credentials against an account or service.",
                "The AI correlates failure velocity, password-spray patterns, source diversity, and impossible travel."));
        ATTACK_PROFILES.put("sql_injection", new AttackProfile(
                "SQL injection", "Initial access",
                "Untrusted input changes the meaning of a database query and reaches a data store.",
                "The AI identifies unsafe parameter patterns, query errors, abnormal data access, and endpoint context."));
        ATTACK_PROFILES.put("man_in_the_middle", new AttackProfile(
                "Man in the middle", "Credential access",
                "Traffic is intercepted or altered between two endpoints that expect to trust each other.",
                "The AI correlates certificate mismatches, rogue gateways, route changes, and unexpected session paths."));
    }

    private final Storage storage;

    public CorrelationEngine(Storage storage) {
        this.storage = storage;
    }

    public int scoreEventType(String eventType) {
        return WEIGHTS.getOrDefault(eventType, 5);
    }

    public static class AttackProfile {
        public final String attackType, tactic, working, detection;

        AttackProfile(String attackType, String tactic, String working, String detection) {
            this.attackType = attackType;
            this.tactic = tactic;
            this.working = working;
            this.detection = detection;
        }
    }

    public AttackProfile profileFor(String eventType) {
        return ATTACK_PROFILES.getOrDefault(eventType, new AttackProfile(
                "Unclassified activity", "Unknown", "An event was received without a mapped attack category.",
                "The AI records the signal and waits for corroborating behavior."));
    }

    public static class ScoreReport {
        public String entityId;
        public int threatScore;
        public List<String> signals;
        public int eventCount;
    }

    public ScoreReport computeEntityScore(String entityId) {
        double now = System.currentTimeMillis() / 1000.0;
        List<Storage.EventRecord> recent = storage.getRecentEvents(entityId, WINDOW_SECONDS, now);

        int total = 0;
        Set<String> signalTypes = new TreeSet<>();
        for (Storage.EventRecord e : recent) {
            total += e.weight;
            signalTypes.add(e.eventType);
        }
        total = Math.min(total, 100);

        ScoreReport report = new ScoreReport();
        report.entityId = entityId;
        report.threatScore = total;
        report.signals = new ArrayList<>(signalTypes);
        report.eventCount = recent.size();
        return report;
    }

    public static String classifyScore(int score) {
        if (score < 30)
            return "NORMAL";
        if (score < 60)
            return "SUSPICIOUS";
        if (score < 80)
            return "HIGH_RISK";
        return "CRITICAL";
    }
}
