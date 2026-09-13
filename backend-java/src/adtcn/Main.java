package adtcn;

import com.sun.net.httpserver.*;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;

/**
 * ADTCN backend — pure JDK implementation (no external dependencies:
 * this build environment can't reach Maven Central, so Spring/Jackson
 * etc. aren't an option — everything here is java.* and com.sun.net.*).
 *
 * REST API on :8000, WebSocket broadcast on :8001, dashboard static
 * files served from :8000/.
 *
 * Flow per incoming event, same as the Python prototype:
 * POST /events -> correlation engine (score) -> policy engine
 * (decide + simulate response) -> evidence chain (hash) ->
 * broadcast to dashboard over WebSocket.
 */
public class Main {

    static final int HTTP_PORT = 8000;
    static final int WS_PORT = 8001;

    static Storage storage = new Storage();
    static CorrelationEngine correlation = new CorrelationEngine(storage);
    static PolicyEngine policy = new PolicyEngine(storage);
    static EvidenceChain evidence = new EvidenceChain();
    static DecoyManager decoys;
    static WsServer wsServer = new WsServer(WS_PORT);

    public static void main(String[] args) throws Exception {
        Path decoyDir = Paths.get("..", "decoys");
        decoys = new DecoyManager(storage, decoyDir);
        seedBaselineDecoys();

        wsServer.start();

        HttpServer server = HttpServer.create(new InetSocketAddress(HTTP_PORT), 0);
        server.createContext("/events", Main::handleEvents);
        server.createContext("/state", Main::handleState);
        server.createContext("/graph", Main::handleGraph);
        server.createContext("/evidence/verify", Main::handleEvidenceVerify);
        server.createContext("/health", Main::handleHealth);
        server.createContext("/", Main::handleStatic); // dashboard static files + index

        server.setExecutor(java.util.concurrent.Executors.newCachedThreadPool());
        server.start();

        System.out.println("[main] ADTCN Java backend running:");
        System.out.println("[main]   REST API : http://localhost:" + HTTP_PORT);
        System.out.println("[main]   WebSocket: ws://localhost:" + WS_PORT);
    }

    static void seedBaselineDecoys() {
        if (storage.getAllDecoys().isEmpty()) {
            decoys.createDecoyFile("finance_admin_credentials.txt", "finance",
                    "admin_user: finance_admin\npassword: F1n@nce_2026!");
            decoys.createDecoyCredential("finance_admin", "finance");
        }
    }

    // ---------------- HTTP handlers ----------------

    static void handleEvents(HttpExchange ex) throws IOException {
        addCors(ex);
        if (ex.getRequestMethod().equals("OPTIONS")) {
            ex.sendResponseHeaders(204, -1);
            return;
        }
        if (!ex.getRequestMethod().equals("POST")) {
            sendJson(ex, 405, Json.obj("error", "POST only"));
            return;
        }

        String body = readBody(ex);
        Map<String, Object> req;
        try {
            req = Json.parseObject(body);
        } catch (Exception e) {
            sendJson(ex, 400, Json.obj("error", "invalid JSON: " + e.getMessage()));
            return;
        }

        String entityId = (String) req.get("entity_id");
        String eventType = (String) req.get("event_type");
        String source = (String) req.getOrDefault("source", "unknown");
        @SuppressWarnings("unchecked")
        Map<String, Object> metadata = (Map<String, Object>) req.getOrDefault("metadata", new LinkedHashMap<>());
        String graphSrc = (String) req.get("graph_src");
        String graphDst = (String) req.get("graph_dst");
        String graphLabel = (String) req.get("graph_label");

        double ts = System.currentTimeMillis() / 1000.0;
        int weight = correlation.scoreEventType(eventType);
        CorrelationEngine.AttackProfile attackProfile = correlation.profileFor(eventType);
        if (!metadata.containsKey("attacker_ip") && req.get("attacker_ip") instanceof String) {
            metadata.put("attacker_ip", req.get("attacker_ip"));
        }
        boolean observedIp = metadata.get("attacker_ip") instanceof String
                && !((String) metadata.get("attacker_ip")).isBlank();
        String attackerIp = observedIp ? (String) metadata.get("attacker_ip") : deriveAttackerIp(entityId);
        metadata.put("attacker_ip", attackerIp);
        metadata.put("attacker_ip_source", observedIp ? "observed" : "derived from entity");
        if (graphSrc != null)
            metadata.put("graph_src", graphSrc);
        if (graphDst != null)
            metadata.put("graph_dst", graphDst);
        if ("decoy_file_accessed".equals(eventType)) {
            metadata.put("decoy_file_taken", true);
            metadata.put("decoy_file_path", metadata.getOrDefault("path", "unknown decoy file"));
            metadata.put("malware_injected_at", ts);
            metadata.put("malware_target", entityId);
            metadata.put("malware_action", "payload attached when decoy was opened");
        }

        int eventId = storage.insertEvent(entityId, eventType, source, weight, metadata, ts);

        if (metadata.containsKey("decoy_id") && metadata.get("decoy_id") != null) {
            storage.markDecoyTriggered((String) metadata.get("decoy_id"));
        }

        if (graphSrc != null && graphDst != null) {
            storage.addGraphEdge(graphSrc, graphDst, graphLabel != null ? graphLabel : eventType, ts);

            for (String zoneKeyword : new String[] { "finance", "database" }) {
                if (graphDst.toLowerCase().contains(zoneKeyword)) {
                    Storage.Decoy newDecoy = decoys.deployAdaptiveDecoy(zoneKeyword);
                    wsServer.broadcast(Json.stringify(Json.obj(
                            "type", "decoy_deployed",
                            "payload", Json.obj("decoy_id", newDecoy.id, "zone", newDecoy.zone,
                                    "location", newDecoy.location))));
                }
            }
        }

        CorrelationEngine.ScoreReport scoreReport = correlation.computeEntityScore(entityId);
        PolicyEngine.Response response = policy.decideResponse(entityId, scoreReport);

        Map<String, Object> evidencePayload = Json.obj(
                "event_id", eventId, "entity_id", entityId, "event_type", eventType,
                "source", source, "weight", weight, "timestamp", ts);
        String evidenceHash = evidence.commitEvent(eventId, evidencePayload);

        wsServer.broadcast(Json.stringify(Json.obj(
                "type", "event",
                "payload", Json.obj(
                        "event_id", eventId, "entity_id", entityId, "event_type", eventType,
                        "source", source, "weight", weight, "timestamp", ts, "attacker_ip", attackerIp,
                        "attack_type", attackProfile.attackType, "tactic", attackProfile.tactic,
                        "graph_dst", graphDst,
                        "metadata", metadata))));
        wsServer.broadcast(Json.stringify(Json.obj(
                "type", "score_update",
                "payload", Json.obj(
                        "entity_id", scoreReport.entityId, "threat_score", scoreReport.threatScore,
                        "signals", scoreReport.signals, "event_count", scoreReport.eventCount))));
        wsServer.broadcast(Json.stringify(Json.obj(
                "type", "ai_detection",
                "payload", Json.obj(
                        "entity_id", entityId, "event_type", eventType,
                        "attack_type", attackProfile.attackType, "tactic", attackProfile.tactic,
                        "working", attackProfile.working, "detection", attackProfile.detection,
                        "confidence", weight >= 30 ? "high" : "medium", "timestamp", ts,
                        "attacker_ip", attackerIp))));
        if (!response.responseLevel.equals("OBSERVE")) {
            wsServer.broadcast(Json.stringify(Json.obj(
                    "type", "incident",
                    "payload", Json.obj(
                            "entity_id", response.entityId, "threat_score", response.threatScore,
                            "response_level", response.responseLevel, "reason", response.reason,
                            "action_taken", response.actionTaken, "timestamp", response.timestamp))));
        }

        Map<String, Object> result = Json.obj(
                "event_id", eventId,
                "score", Json.obj("entity_id", scoreReport.entityId, "threat_score", scoreReport.threatScore,
                        "signals", scoreReport.signals, "event_count", scoreReport.eventCount),
                "response", Json.obj("entity_id", response.entityId, "threat_score", response.threatScore,
                        "response_level", response.responseLevel, "reason", response.reason,
                        "action_taken", response.actionTaken),
                "evidence_hash", evidenceHash);
        sendJson(ex, 200, result);
    }

    static void handleState(HttpExchange ex) throws IOException {
        addCors(ex);
        List<Object> entityScores = new ArrayList<>();
        for (String entityId : storage.getDistinctEntityIds()) {
            CorrelationEngine.ScoreReport r = correlation.computeEntityScore(entityId);
            entityScores.add(Json.obj("entity_id", r.entityId, "threat_score", r.threatScore,
                    "signals", r.signals, "event_count", r.eventCount));
        }

        List<Object> incidentsJson = new ArrayList<>();
        for (Storage.Incident inc : storage.getAllIncidents()) {
            incidentsJson.add(Json.obj("id", inc.id, "entity_id", inc.entityId,
                    "threat_score", inc.threatScore, "response_level", inc.responseLevel,
                    "reason", inc.reason, "action_taken", inc.actionTaken, "timestamp", inc.timestamp));
        }

        List<Object> eventsJson = new ArrayList<>();
        for (Storage.EventRecord event : storage.getAllEvents()) {
            CorrelationEngine.AttackProfile profile = correlation.profileFor(event.eventType);
            String attackerIp = String
                    .valueOf(event.metadata.getOrDefault("attacker_ip", deriveAttackerIp(event.entityId)));
            eventsJson.add(Json.obj("event_id", event.id, "entity_id", event.entityId,
                    "event_type", event.eventType, "source", event.source, "weight", event.weight,
                    "timestamp", event.timestamp, "attacker_ip", attackerIp,
                    "attack_type", profile.attackType, "tactic", profile.tactic, "metadata", event.metadata));
        }

        List<Object> decoysJson = new ArrayList<>();
        for (Storage.Decoy d : storage.getAllDecoys()) {
            decoysJson.add(Json.obj("id", d.id, "decoy_type", d.decoyType, "location", d.location,
                    "zone", d.zone, "triggered", d.triggered));
        }

        sendJson(ex, 200, Json.obj("entities", entityScores, "incidents", incidentsJson,
                "events", eventsJson, "decoys", decoysJson));
    }

    static String deriveAttackerIp(String entityId) {
        if (entityId != null && entityId.matches("PC-\\d+")) {
            String suffix = entityId.substring(3);
            try {
                return "10.20.0." + Integer.parseInt(suffix);
            } catch (NumberFormatException ignored) {
                // Fall through to the reserved documentation address.
            }
        }
        return "192.0.2.10";
    }

    static void handleGraph(HttpExchange ex) throws IOException {
        addCors(ex);
        List<Object> edges = new ArrayList<>();
        for (Storage.GraphEdge e : storage.getGraph()) {
            edges.add(Json.obj("src", e.src, "dst", e.dst, "label", e.label, "timestamp", e.timestamp));
        }
        sendJson(ex, 200, Json.obj("edges", edges));
    }

    static void handleEvidenceVerify(HttpExchange ex) throws IOException {
        addCors(ex);
        sendJson(ex, 200, evidence.verify());
    }

    static void handleHealth(HttpExchange ex) throws IOException {
        addCors(ex);
        sendJson(ex, 200, Json.obj("status", "ok"));
    }

    static void handleStatic(HttpExchange ex) throws IOException {
        addCors(ex);
        String path = ex.getRequestURI().getPath();
        if (path.equals("/"))
            path = "/index.html";
        Path file = Paths.get("..", "dashboard").resolve(path.substring(1)).normalize();
        if (!file.startsWith(Paths.get("..", "dashboard").normalize()) || !Files.exists(file)) {
            ex.sendResponseHeaders(404, -1);
            return;
        }
        byte[] content = Files.readAllBytes(file);
        String contentType = path.endsWith(".html") ? "text/html"
                : path.endsWith(".js") ? "application/javascript"
                        : path.endsWith(".css") ? "text/css" : "application/octet-stream";
        ex.getResponseHeaders().set("Content-Type", contentType);
        ex.sendResponseHeaders(200, content.length);
        try (OutputStream os = ex.getResponseBody()) {
            os.write(content);
        }
    }

    // ---------------- helpers ----------------

    static String readBody(HttpExchange ex) throws IOException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        byte[] chunk = new byte[1024];
        int n;
        InputStream is = ex.getRequestBody();
        while ((n = is.read(chunk)) != -1)
            buf.write(chunk, 0, n);
        return buf.toString(StandardCharsets.UTF_8);
    }

    static void sendJson(HttpExchange ex, int status, Object payload) throws IOException {
        byte[] bytes = Json.stringify(payload).getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", "application/json");
        ex.sendResponseHeaders(status, bytes.length);
        try (OutputStream os = ex.getResponseBody()) {
            os.write(bytes);
        }
    }

    static void addCors(HttpExchange ex) {
        ex.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
        ex.getResponseHeaders().set("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
        ex.getResponseHeaders().set("Access-Control-Allow-Headers", "Content-Type");
    }
}
