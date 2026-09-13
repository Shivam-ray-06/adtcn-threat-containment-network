package adtcn;

import java.io.*;
import java.net.*;
import java.security.MessageDigest;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Minimal WebSocket server implementing just enough of RFC 6455 to
 * broadcast JSON messages to the dashboard: HTTP Upgrade handshake +
 * unmasked server->client text frames. No external libraries (Maven
 * Central isn't reachable in this build environment), and the
 * dashboard never needs to send meaningful data back, so incoming
 * frame parsing is intentionally minimal (just enough to detect
 * disconnects).
 */
public class WsServer {

    private static final String MAGIC = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

    private final int port;
    private final List<Socket> clients = new CopyOnWriteArrayList<>();
    private ServerSocket serverSocket;

    public WsServer(int port) { this.port = port; }

    public void start() {
        Thread t = new Thread(this::run, "ws-accept-loop");
        t.setDaemon(true);
        t.start();
    }

    private void run() {
        try {
            serverSocket = new ServerSocket(port);
            System.out.println("[ws] WebSocket server listening on port " + port);
            while (true) {
                Socket socket = serverSocket.accept();
                Thread handler = new Thread(() -> handleClient(socket), "ws-client");
                handler.setDaemon(true);
                handler.start();
            }
        } catch (IOException e) {
            System.err.println("[ws] server error: " + e.getMessage());
        }
    }

    private void handleClient(Socket socket) {
        try {
            InputStream in = socket.getInputStream();
            BufferedReader reader = new BufferedReader(new InputStreamReader(in));

            String line;
            String wsKey = null;
            while ((line = reader.readLine()) != null && !line.isEmpty()) {
                if (line.toLowerCase().startsWith("sec-websocket-key:")) {
                    wsKey = line.substring(line.indexOf(':') + 1).trim();
                }
            }
            if (wsKey == null) { socket.close(); return; }

            String acceptKey = computeAcceptKey(wsKey);
            OutputStream out = socket.getOutputStream();
            String response = "HTTP/1.1 101 Switching Protocols\r\n" +
                    "Upgrade: websocket\r\n" +
                    "Connection: Upgrade\r\n" +
                    "Sec-WebSocket-Accept: " + acceptKey + "\r\n\r\n";
            out.write(response.getBytes("UTF-8"));
            out.flush();

            clients.add(socket);
            System.out.println("[ws] client connected (" + clients.size() + " total)");

            // Block here just to detect disconnection; we never act on
            // incoming frame content since the dashboard has nothing to say.
            byte[] buf = new byte[1024];
            while (in.read(buf) != -1) {
                // discard — dashboard doesn't send meaningful data
            }
        } catch (IOException ignored) {
        } finally {
            clients.remove(socket);
            try { socket.close(); } catch (IOException ignored) {}
            System.out.println("[ws] client disconnected (" + clients.size() + " remaining)");
        }
    }

    private String computeAcceptKey(String clientKey) {
        try {
            MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
            byte[] hash = sha1.digest((clientKey + MAGIC).getBytes("UTF-8"));
            return Base64.getEncoder().encodeToString(hash);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public synchronized void broadcast(String jsonMessage) {
        byte[] frame = encodeTextFrame(jsonMessage);
        for (Socket client : clients) {
            try {
                client.getOutputStream().write(frame);
                client.getOutputStream().flush();
            } catch (IOException e) {
                clients.remove(client);
            }
        }
    }

    private byte[] encodeTextFrame(String message) {
        byte[] payload;
        try { payload = message.getBytes("UTF-8"); } catch (Exception e) { throw new RuntimeException(e); }
        int len = payload.length;
        ByteArrayOutputStreamCompat baos = new ByteArrayOutputStreamCompat();
        baos.write(0x81); // FIN + text opcode
        if (len < 126) {
            baos.write(len);
        } else if (len < 65536) {
            baos.write(126);
            baos.write((len >> 8) & 0xFF);
            baos.write(len & 0xFF);
        } else {
            baos.write(127);
            for (int i = 7; i >= 0; i--) baos.write((int) ((len >> (8 * i)) & 0xFF));
        }
        baos.writeBytes(payload);
        return baos.toByteArray();
    }

    // Tiny helper so we don't need java.io.ByteArrayOutputStream's checked-exception writeBytes variant confusion
    private static class ByteArrayOutputStreamCompat extends ByteArrayOutputStream {
        public void writeBytes(byte[] b) { write(b, 0, b.length); }
    }
}
