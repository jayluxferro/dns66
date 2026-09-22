/* This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 */
package org.jak_linux.dns66.vpn;

import android.annotation.SuppressLint;
import android.net.VpnService;
import android.os.Build;
import android.util.Log;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.Deque;
import java.util.concurrent.ConcurrentLinkedDeque;

import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

/**
 * Base class for encrypted DNS upstreams (DoT and DoH). Keeps a small pool
 * of idle TLS connections so queries do not pay a handshake each time, and
 * retries once on a fresh socket when a pooled (keep-alive) connection has
 * gone stale - retrying is safe because DNS requests are idempotent.
 *
 * Connections are protected from our own VPN via {@link VpnService#protect},
 * so they use the underlying network directly.
 */
public abstract class SecureUpstream {
    private static final String TAG = "SecureUpstream";

    /**
     * Three seconds: resolvers fail over to their next configured server
     * quickly, so we must lose the connect race before they give up on us
     * (observed on device with the default resolver timeout).
     */
    private static final int CONNECT_TIMEOUT_MS = 3000;
    private static final int READ_TIMEOUT_MS = 5000;
    private static final int MAX_IDLE_SOCKETS = 3;
    /**
     * Pooled connections older than this are discarded instead of reused:
     * public resolvers (e.g. Quad9) close idle TLS connections after a short
     * time, and writing to the half-closed socket only surfaces at the read,
     * which costs a full read timeout per query.
     */
    private static final long IDLE_TIMEOUT_MS = 5000;

    private final SSLSocketFactory sslSocketFactory;
    private final Deque<IdleSocket> idleSockets = new ConcurrentLinkedDeque<>();

    protected final VpnService vpnService;
    protected final DnsUpstream upstream;

    protected SecureUpstream(VpnService vpnService, DnsUpstream upstream) {
        this(vpnService, upstream, (SSLSocketFactory) SSLSocketFactory.getDefault());
    }

    protected SecureUpstream(VpnService vpnService, DnsUpstream upstream, SSLSocketFactory sslSocketFactory) {
        this.vpnService = vpnService;
        this.upstream = upstream;
        this.sslSocketFactory = sslSocketFactory;
    }

    /**
     * Resolves one DNS query on a pooled connection.
     *
     * @param query The raw DNS message bytes from the client
     * @return The raw DNS response message bytes
     * @throws IOException If the upstream could not be reached or answered garbage
     */
    public byte[] resolve(byte[] query) throws IOException {
        // The first attempt may use a stale pooled socket; if that fails,
        // retry once with a fresh connection.
        for (int attempt = 0; attempt < 2; attempt++) {
            SSLSocket socket = pollUsableIdleSocket();
            boolean fresh = false;
            if (socket == null) {
                socket = createSocket();
                fresh = true;
            }
            try {
                byte[] response = exchange(socket, query);
                if (idleSockets.size() < MAX_IDLE_SOCKETS)
                    idleSockets.offer(new IdleSocket(socket));
                else
                    closeQuietly(socket);
                return response;
            } catch (RuntimeException e) {
                // A runtime error is a bug, not connection staleness: release
                // the socket and let it propagate - no retry.
                closeQuietly(socket);
                throw e;
            } catch (IOException e) {
                closeQuietly(socket);
                if (fresh)
                    throw e;
                Log.d(TAG, "Pooled connection to " + upstream + " failed, retrying with a fresh one", e);
            }
        }
        throw new IOException("Could not resolve via " + upstream);
    }

    /**
     * Takes the most recently used idle connection, discarding expired
     * (and closed) ones on the way.
     */
    private SSLSocket pollUsableIdleSocket() {
        long now = System.currentTimeMillis();
        IdleSocket idle;
        while ((idle = idleSockets.pollLast()) != null) {
            if (!idle.socket.isClosed() && now - idle.lastUsed < IDLE_TIMEOUT_MS)
                return idle.socket;
            closeQuietly(idle.socket);
        }
        return null;
    }

    /**
     * Performs a single query/response exchange on the given connection.
     * Implementations must not close the socket.
     */
    protected abstract byte[] exchange(SSLSocket socket, byte[] query) throws IOException;

    /** Releases all pooled connections. */
    public void shutdown() {
        IdleSocket idle;
        while ((idle = idleSockets.poll()) != null)
            closeQuietly(idle.socket);
    }

    /** A pooled connection with the time it was last used. */
    private static class IdleSocket {
        final SSLSocket socket;
        final long lastUsed;

        IdleSocket(SSLSocket socket) {
            this.socket = socket;
            this.lastUsed = System.currentTimeMillis();
        }
    }

    @SuppressLint("NewApi")
    private SSLSocket createSocket() throws IOException {
        Socket socket = new Socket();
        // Keep our own upstream traffic out of the VPN
        if (!vpnService.protect(socket))
            Log.w(TAG, "protect() failed for " + upstream);
        socket.connect(new InetSocketAddress(upstream.host, upstream.port), CONNECT_TIMEOUT_MS);
        SSLSocket sslSocket = (SSLSocket) sslSocketFactory.createSocket(socket, upstream.host, upstream.port, true);
        sslSocket.setSoTimeout(READ_TIMEOUT_MS);
        // Verify that the certificate the server presents matches the host we
        // dialed. Without this, SSLSockets only validate the chain - any
        // CA-signed certificate would be accepted for every upstream,
        // including the shipped IP-literal defaults. The handshake below
        // enforces the check and fails with an SSLException (an IOException)
        // on mismatch, which resolve() propagates instead of retrying.
        // Requires API 24; on API 23 the check stays off. (SDK_INT == 0 is
        // the JVM unit-test runtime, where the method exists; lint cannot
        // model that clause, hence the targeted suppression.)
        if (Build.VERSION.SDK_INT == 0 || Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            SSLParameters sslParameters = sslSocket.getSSLParameters();
            sslParameters.setEndpointIdentificationAlgorithm("HTTPS");
            sslSocket.setSSLParameters(sslParameters);
        }
        sslSocket.startHandshake();
        return sslSocket;
    }

    static void closeQuietly(Socket socket) {
        if (socket == null)
            return;
        try {
            socket.close();
        } catch (IOException e) {
            // Ignore, we are closing anyway
        }
    }
}
