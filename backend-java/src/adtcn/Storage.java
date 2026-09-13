package adtcn;

import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Thread-safe in-memory storage. A real deployment would back this with
 * a database (see README for the swap-in point) — for the prototype,
 * in-memory keeps the backend dependency-free and fast, which matters
 * more for a live demo than durability across restarts.
 */
public class Storage {

    public static class EventRecord {
        public int id;
        public String entityId, eventType, source;
        public int weight;
        public Map<String, Object> metadata;
        public double timestamp;
    }

    public static class Incident {
        public int id;
        public String entityId, responseLevel, reason, actionTaken;
        public int threatScore;
        public double timestamp;
    }

    public static class Decoy {
        public String id, decoyType, location, zone;
        public double createdAt;
        public boolean triggered;
    }

    public static class GraphEdge {
        public String src, dst, label;
        public double timestamp;
    }

    private final AtomicInteger eventIdSeq = new AtomicInteger(0);
    private final AtomicInteger incidentIdSeq = new AtomicInteger(0);

    private final List<EventRecord> events = new CopyOnWriteArrayList<>();
    private final List<Incident> incidents = new CopyOnWriteArrayList<>();
    private final Map<String, Decoy> decoys = new ConcurrentHashMap<>();
    private final List<GraphEdge> graphEdges = new CopyOnWriteArrayList<>();

    public int insertEvent(String entityId, String eventType, String source, int weight,
            Map<String, Object> metadata, double timestamp) {
        EventRecord e = new EventRecord();
        e.id = eventIdSeq.incrementAndGet();
        e.entityId = entityId;
        e.eventType = eventType;
        e.source = source;
        e.weight = weight;
        e.metadata = metadata != null ? metadata : new LinkedHashMap<>();
        e.timestamp = timestamp;
        events.add(e);
        return e.id;
    }

    public int insertIncident(String entityId, int threatScore, String responseLevel,
            String reason, String actionTaken, double timestamp) {
        Incident inc = new Incident();
        inc.id = incidentIdSeq.incrementAndGet();
        inc.entityId = entityId;
        inc.threatScore = threatScore;
        inc.responseLevel = responseLevel;
        inc.reason = reason;
        inc.actionTaken = actionTaken;
        inc.timestamp = timestamp;
        incidents.add(inc);
        return inc.id;
    }

    public List<EventRecord> getRecentEvents(String entityId, double windowSeconds, double now) {
        List<EventRecord> result = new ArrayList<>();
        for (EventRecord e : events) {
            if (e.entityId.equals(entityId) && e.timestamp >= now - windowSeconds) {
                result.add(e);
            }
        }
        result.sort(Comparator.comparingDouble(e -> e.timestamp));
        return result;
    }

    public List<Incident> getAllIncidents() {
        List<Incident> copy = new ArrayList<>(incidents);
        copy.sort((a, b) -> Double.compare(b.timestamp, a.timestamp));
        return copy;
    }

    public List<EventRecord> getAllEvents() {
        List<EventRecord> copy = new ArrayList<>(events);
        copy.sort(Comparator.comparingDouble(e -> e.timestamp));
        return copy;
    }

    public Set<String> getDistinctEntityIds() {
        Set<String> ids = new LinkedHashSet<>();
        for (EventRecord e : events)
            ids.add(e.entityId);
        return ids;
    }

    public void registerDecoy(String id, String type, String location, String zone, double createdAt) {
        Decoy d = new Decoy();
        d.id = id;
        d.decoyType = type;
        d.location = location;
        d.zone = zone;
        d.createdAt = createdAt;
        d.triggered = decoys.containsKey(id) && decoys.get(id).triggered;
        decoys.put(id, d);
    }

    public void markDecoyTriggered(String id) {
        Decoy d = decoys.get(id);
        if (d != null)
            d.triggered = true;
    }

    public Decoy getDecoy(String id) {
        return decoys.get(id);
    }

    public List<Decoy> getAllDecoys() {
        return new ArrayList<>(decoys.values());
    }

    public void addGraphEdge(String src, String dst, String label, double timestamp) {
        GraphEdge edge = new GraphEdge();
        edge.src = src;
        edge.dst = dst;
        edge.label = label;
        edge.timestamp = timestamp;
        graphEdges.add(edge);
    }

    public List<GraphEdge> getGraph() {
        return new ArrayList<>(graphEdges);
    }
}
