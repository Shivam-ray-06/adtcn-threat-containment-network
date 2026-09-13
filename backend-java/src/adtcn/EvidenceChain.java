package adtcn;

import java.security.MessageDigest;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Tamper-evident evidence chain — each entry's hash covers its own
 * payload plus the previous entry's hash, so altering any past record
 * breaks every hash after it. Same primitive a blockchain uses,
 * without needing distributed consensus for a single-organization log.
 */
public class EvidenceChain {

    public static class Entry {
        public int eventId;
        public String payload;
        public String prevHash;
        public String hash;
        public double timestamp;
    }

    private final List<Entry> chain = new CopyOnWriteArrayList<>();

    private static String sha256(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(input.getBytes("UTF-8"));
            StringBuilder sb = new StringBuilder();
            for (byte b : hashBytes) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public synchronized String commitEvent(int eventId, Map<String, Object> payload) {
        String payloadStr = Json.stringify(new TreeMap<>(payload)); // sorted keys for determinism
        String prevHash = chain.isEmpty() ? "0".repeat(64) : chain.get(chain.size() - 1).hash;
        String newHash = sha256(payloadStr + prevHash);

        Entry entry = new Entry();
        entry.eventId = eventId;
        entry.payload = payloadStr;
        entry.prevHash = prevHash;
        entry.hash = newHash;
        entry.timestamp = System.currentTimeMillis() / 1000.0;
        chain.add(entry);
        return newHash;
    }

    /** Deliberately exposed for the tamper-detection test tool. */
    public synchronized void corruptEntryForTesting(int index, String newPayload) {
        if (index >= 0 && index < chain.size()) {
            chain.get(index).payload = newPayload;
        }
    }

    public synchronized Map<String, Object> verify() {
        String prevHash = "0".repeat(64);
        for (int i = 0; i < chain.size(); i++) {
            Entry entry = chain.get(i);
            String expected = sha256(entry.payload + prevHash);
            if (!expected.equals(entry.hash)) {
                return Json.obj(
                        "valid", false,
                        "broken_at_index", i,
                        "broken_event_id", entry.eventId,
                        "entries_checked", i,
                        "total_entries", chain.size()
                );
            }
            prevHash = entry.hash;
        }
        return Json.obj(
                "valid", true,
                "entries_checked", chain.size(),
                "total_entries", chain.size(),
                "latest_hash", prevHash
        );
    }

    public int size() { return chain.size(); }
}
