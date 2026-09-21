/* This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 */
package org.jak_linux.dns66.vpn;

import org.xbill.DNS.ARecord;
import org.xbill.DNS.DClass;
import org.xbill.DNS.Flags;
import org.xbill.DNS.Message;
import org.xbill.DNS.Section;

import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509ExtendedTrustManager;

/**
 * In-process TLS server speaking just enough DoT and DoH for the upstream
 * tests. It exists so {@link DotUpstream}/{@link DohUpstream} can be tested
 * against real TLS instead of mocked sockets - the interesting behavior
 * (framing, chunked decoding, keep-alive, stale-socket retry) lives on the
 * wire.
 *
 * Certificate handling: the server needs real key material, which we
 * generate once per JVM by invoking {@code keytool} (shipped with every
 * JDK, which gradle unit tests need anyway). The client side never checks
 * the chain - tests pass a trust-everything factory into the package-private
 * upstream constructors - so the certificate merely has to exist and be
 * parseable.
 */
final class FakeTlsDnsServer implements Closeable {
    private static final String KEYSTORE_PASSWORD = "dns66-test";
    private static final byte[] ANSWER_ADDRESS = {(byte) 192, 0, 2, 99};

    /** Cached so both upstream test classes share one keytool invocation. */
    private static volatile SSLContext cachedServerContext;
    private static volatile SSLSocketFactory cachedTrustAllFactory;

    private final SSLServerSocket serverSocket;
    private final ExecutorService connectionPool = Executors.newCachedThreadPool(runnable -> {
        Thread thread = new Thread(runnable, "FakeTlsDnsServer-conn");
        thread.setDaemon(true);
        return thread;
    });

    /** Completed TLS handshakes - the keep-alive and retry tests count these. */
    final AtomicInteger acceptedConnections = new AtomicInteger();
    /** Query payload bytes, in arrival order. */
    final List<byte[]> receivedQueries = Collections.synchronizedList(new ArrayList<>());
    // Last DoH request metadata, for asserting the request format.
    volatile String lastRequestLine;
    volatile String lastHostHeader;
    volatile String lastContentType;

    /**
     * Serve exactly one query per TLS connection, closing the connection
     * after the answer. This simulates a server with a short idle timeout:
     * the next resolve() finds a stale pooled socket on the client side.
     */
    volatile boolean oneQueryPerConnection = false;
    /** DoH only: answer with Transfer-Encoding: chunked (incl. extension + trailers). */
    volatile boolean chunked = false;
    /** DoH only: answer with HTTP 500. */
    volatile boolean http500 = false;

    /** Speak DoH (HTTP/1.1) on accepted connections; DoT (2-byte framing) otherwise. */
    private final boolean dohMode;

    FakeTlsDnsServer(boolean dohMode) throws IOException {
        this.dohMode = dohMode;
        // Bound immediately, so tests can connect as soon as the
        // constructor returns; connections queue in the listen backlog.
        SSLServerSocket bound;
        try {
            bound = (SSLServerSocket) serverContext().getServerSocketFactory()
                    .createServerSocket(0, 50, InetAddress.getByName("127.0.0.1"));
        } catch (Exception e) {
            throw new IOException("Cannot start fake TLS DNS server", e);
        }
        serverSocket = bound;
        Thread acceptor = new Thread(this::acceptLoop, "FakeTlsDnsServer-accept");
        acceptor.setDaemon(true);
        acceptor.start();
    }

    int port() {
        return serverSocket.getLocalPort();
    }

    private void acceptLoop() {
        while (!serverSocket.isClosed()) {
            try {
                Socket client = serverSocket.accept();
                connectionPool.execute(() -> serve((SSLSocket) client));
            } catch (IOException e) {
                return; // serverSocket was closed
            }
        }
    }

    private void serve(SSLSocket socket) {
        try (Socket closeable = socket) {
            socket.startHandshake();
            acceptedConnections.incrementAndGet();
            if (dohMode)
                serveDoh(socket);
            else
                serveDot(socket);
        } catch (IOException e) {
            // Client went away mid-conversation; nothing to salvage.
        }
    }

    private void serveDot(SSLSocket socket) throws IOException {
        DataInputStream in = new DataInputStream(socket.getInputStream());
        DataOutputStream out = new DataOutputStream(socket.getOutputStream());
        while (true) {
            int length;
            try {
                length = in.readUnsignedShort();
            } catch (EOFException e) {
                return; // client closed a keep-alive connection
            }
            byte[] query = new byte[length];
            in.readFully(query);
            receivedQueries.add(query);
            byte[] response = dnsResponseFor(query);
            out.writeShort(response.length);
            out.write(response);
            out.flush();
            if (oneQueryPerConnection) {
                socket.close();
                return;
            }
        }
    }

    private void serveDoh(SSLSocket socket) throws IOException {
        while (true) {
            byte[] query = readDohRequest(socket);
            if (query == null)
                return; // EOF between requests: connection closed
            receivedQueries.add(query);
            OutputStream out = socket.getOutputStream();
            if (http500) {
                // A real 500-ing server may or may not close; closing keeps
                // the test simple, and the client must fail on the status
                // line before it ever looks at the body.
                out.write("HTTP/1.1 500 nope\r\nContent-Length: 0\r\n\r\n"
                        .getBytes(StandardCharsets.US_ASCII));
                out.flush();
                socket.close();
                return;
            }
            byte[] response = dnsResponseFor(query);
            if (chunked)
                writeChunked(out, response);
            else {
                out.write(("HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\n"
                        + "Content-Length: " + response.length + "\r\n\r\n")
                        .getBytes(StandardCharsets.US_ASCII));
                out.write(response);
                out.flush();
            }
            if (oneQueryPerConnection) {
                socket.close();
                return;
            }
        }
    }

    /**
     * Reads one HTTP/1.1 request (headers + Content-Length body). Returns
     * null on EOF before the request line.
     */
    private byte[] readDohRequest(SSLSocket socket) throws IOException {
        InputStream in = socket.getInputStream();
        String requestLine = readLine(in);
        if (requestLine == null || requestLine.isEmpty())
            return null;
        int contentLength = -1;
        String line;
        while ((line = readLine(in)) != null && !line.isEmpty()) {
            int colon = line.indexOf(':');
            if (colon < 0)
                continue;
            String name = line.substring(0, colon).trim().toLowerCase(Locale.ROOT);
            String value = line.substring(colon + 1).trim();
            if (name.equals("content-length"))
                contentLength = Integer.parseInt(value);
            else if (name.equals("host"))
                lastHostHeader = value;
            else if (name.equals("content-type"))
                lastContentType = value;
        }
        if (line == null || contentLength < 0)
            throw new IOException("Incomplete DoH request");
        byte[] body = new byte[contentLength];
        int off = 0;
        while (off < contentLength) {
            int read = in.read(body, off, contentLength - off);
            if (read < 0)
                throw new EOFException("EOF in request body");
            off += read;
        }
        lastRequestLine = requestLine;
        return body;
    }

    private void writeChunked(OutputStream out, byte[] response) throws IOException {
        // Two chunks, the first with a chunk extension, plus a trailer
        // section - exactly the frills the client claims to survive.
        int split = response.length / 2;
        byte[] first = Arrays.copyOfRange(response, 0, split);
        byte[] second = Arrays.copyOfRange(response, split, response.length);
        out.write(("HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\n"
                + "Transfer-Encoding: chunked\r\n\r\n").getBytes(StandardCharsets.US_ASCII));
        out.write((Integer.toHexString(first.length) + ";ext=1\r\n").getBytes(StandardCharsets.US_ASCII));
        out.write(first);
        out.write("\r\n".getBytes(StandardCharsets.US_ASCII));
        out.write((Integer.toHexString(second.length) + "\r\n").getBytes(StandardCharsets.US_ASCII));
        out.write(second);
        out.write("\r\n".getBytes(StandardCharsets.US_ASCII));
        out.write("0\r\nX-Dns66-Test: trailer\r\n\r\n".getBytes(StandardCharsets.US_ASCII));
        out.flush();
    }

    private static String readLine(InputStream in) throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        int c;
        while ((c = in.read()) != -1) {
            if (c == '\n')
                break;
            buffer.write(c);
        }
        if (c == -1 && buffer.size() == 0)
            return null;
        byte[] bytes = buffer.toByteArray();
        int end = bytes.length;
        if (end > 0 && bytes[end - 1] == '\r')
            end--;
        return new String(bytes, 0, end, StandardCharsets.US_ASCII);
    }

    /** Builds a well-formed response with QR set and one A record answer. */
    static byte[] dnsResponseFor(byte[] queryWire) throws IOException {
        Message request = new Message(queryWire);
        Message response = new Message(request.getHeader().getID());
        response.getHeader().setFlag(Flags.QR);
        response.addRecord(request.getQuestion(), Section.QUESTION);
        response.addRecord(new ARecord(request.getQuestion().getName(), DClass.IN, 300,
                Inet4Address.getByAddress(ANSWER_ADDRESS)), Section.ANSWER);
        return response.toWire();
    }

    @Override
    public void close() {
        try {
            serverSocket.close();
        } catch (IOException e) {
            // Closing anyway
        }
        // Handlers blocked on read() get their sockets closed by the
        // upstream's shutdown() in tearDown; interrupt the rest.
        connectionPool.shutdownNow();
    }

    /** Server-side context presenting the throwaway self-signed certificate. */
    static SSLContext serverContext() throws Exception {
        if (cachedServerContext != null)
            return cachedServerContext;
        synchronized (FakeTlsDnsServer.class) {
            if (cachedServerContext == null)
                cachedServerContext = generateServerContext();
            return cachedServerContext;
        }
    }

    private static SSLContext generateServerContext() throws Exception {
        // keytool refuses to write into an existing (empty) file, so hand
        // it a path that does not exist yet, in a fresh temp directory.
        Path keystoreDir = Files.createTempDirectory("dns66-test");
        Path keystorePath = keystoreDir.resolve("keystore.p12");
        String keytool = System.getProperty("java.home") + "/bin/keytool";
        Process process = new ProcessBuilder(keytool, "-genkeypair",
                "-alias", "dns66-test",
                "-keyalg", "RSA", "-keysize", "2048", "-sigalg", "SHA256withRSA",
                "-dname", "CN=dns66-test",
                "-ext", "SAN=dns:localhost,ip:127.0.0.1",
                "-validity", "2",
                "-keystore", keystorePath.toString(),
                "-storetype", "PKCS12",
                "-storepass", KEYSTORE_PASSWORD,
                "-keypass", KEYSTORE_PASSWORD,
                "-noprompt")
                .redirectErrorStream(true)
                .start();
        // Drain before waiting: a full pipe would deadlock keytool.
        byte[] output = process.getInputStream().readAllBytes();
        if (process.waitFor() != 0)
            throw new IllegalStateException("keytool failed: " + new String(output, StandardCharsets.UTF_8));
        try {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            try (InputStream in = Files.newInputStream(keystorePath)) {
                keyStore.load(in, KEYSTORE_PASSWORD.toCharArray());
            }
            KeyManagerFactory keyManagerFactory =
                    KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            keyManagerFactory.init(keyStore, KEYSTORE_PASSWORD.toCharArray());
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(keyManagerFactory.getKeyManagers(), null, new SecureRandom());
            return context;
        } finally {
            Files.deleteIfExists(keystorePath);
            Files.deleteIfExists(keystoreDir);
        }
    }

    /**
     * Client-side factory accepting any server certificate. An
     * {@link X509ExtendedTrustManager} with empty checks, so no hostname or
     * chain validation happens regardless of endpoint identification
     * settings.
     */
    static SSLSocketFactory trustAllClientFactory() throws Exception {
        if (cachedTrustAllFactory != null)
            return cachedTrustAllFactory;
        synchronized (FakeTlsDnsServer.class) {
            if (cachedTrustAllFactory == null) {
                TrustManager[] trustAll = new TrustManager[]{new X509ExtendedTrustManager() {
                    @Override
                    public void checkClientTrusted(X509Certificate[] chain, String authType) {
                    }

                    @Override
                    public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket) {
                    }

                    @Override
                    public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine) {
                    }

                    @Override
                    public void checkServerTrusted(X509Certificate[] chain, String authType) {
                    }

                    @Override
                    public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket) {
                    }

                    @Override
                    public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine) {
                    }

                    @Override
                    public X509Certificate[] getAcceptedIssuers() {
                        return new X509Certificate[0];
                    }
                }};
                SSLContext context = SSLContext.getInstance("TLS");
                context.init(null, trustAll, new SecureRandom());
                cachedTrustAllFactory = context.getSocketFactory();
            }
            return cachedTrustAllFactory;
        }
    }
}
