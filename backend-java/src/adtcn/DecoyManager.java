package adtcn;

import java.io.*;
import java.nio.file.*;
import java.util.*;

/**
 * Decoy / honeytoken manager. Creates fake assets tagged with a unique
 * tracking ID, and supports "adaptive deception": deploying new decoys
 * near wherever the attacker's graph path currently points.
 */
public class DecoyManager {

    private final Storage storage;
    private final Path decoyDir;

    public DecoyManager(Storage storage, Path decoyDir) {
        this.storage = storage;
        this.decoyDir = decoyDir;
        try { Files.createDirectories(decoyDir); } catch (IOException ignored) {}
    }

    public Storage.Decoy createDecoyFile(String filename, String zone, String fakeContent) {
        String id = UUID.randomUUID().toString();
        Path path = decoyDir.resolve(filename);
        String content = fakeContent + "\n# tracking_id: " + id + "\n";
        try {
            Files.write(path, content.getBytes());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        double now = System.currentTimeMillis() / 1000.0;
        storage.registerDecoy(id, "file", path.toString(), zone, now);
        Storage.Decoy d = storage.getDecoy(id);
        return d;
    }

    public Storage.Decoy createDecoyCredential(String username, String zone) {
        String id = UUID.randomUUID().toString();
        double now = System.currentTimeMillis() / 1000.0;
        storage.registerDecoy(id, "credential", username, zone, now);
        return storage.getDecoy(id);
    }

    public Storage.Decoy deployAdaptiveDecoy(String zone) {
        long ts = System.currentTimeMillis() / 1000;
        if (zone.equals("finance")) {
            return createDecoyFile("Q3_Budget_Forecast_" + ts + ".xlsx", "finance",
                    "CONFIDENTIAL - Q3 Budget Forecast (decoy)");
        }
        if (zone.equals("database")) {
            return createDecoyCredential("db_admin_temp_" + ts, "database");
        }
        return createDecoyFile("backup_" + ts + ".zip", zone, "decoy archive");
    }

    public Storage.Decoy findByUsername(String username) {
        for (Storage.Decoy d : storage.getAllDecoys()) {
            if (d.decoyType.equals("credential") && d.location.equals(username)) return d;
        }
        return null;
    }
}
