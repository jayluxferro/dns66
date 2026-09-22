/* This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 */
package org.jak_linux.dns66.vpn;

import android.net.VpnService;
import android.util.Log;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.xbill.DNS.ARecord;
import org.xbill.DNS.DClass;
import org.xbill.DNS.Flags;
import org.xbill.DNS.Message;
import org.xbill.DNS.Name;
import org.xbill.DNS.Section;

import java.io.IOException;
import java.net.Socket;

import javax.net.ssl.SSLException;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Tests {@link DotUpstream} against a real in-process TLS server: RFC 7858
 * length-prefixed framing, connection keep-alive, and the stale-socket
 * retry in {@link SecureUpstream#resolve}.
 */
public class DotUpstreamTest {

    private MockedStatic<Log> logMock;
    private VpnService vpnService;
    private FakeTlsDnsServer server;
    private DotUpstream upstream;

    @Before
    public void setUp() throws Exception {
        // SecureUpstream logs on the stale-socket retry path; android.util.Log
        // is not mockable without this.
        logMock = Mockito.mockStatic(Log.class);
        vpnService = Mockito.mock(VpnService.class);
        when(vpnService.protect(any(Socket.class))).thenReturn(true);

        server = new FakeTlsDnsServer(false);
        DnsUpstream descriptor = DnsUpstream.parse("tls://127.0.0.1:" + server.port());
        upstream = new DotUpstream(vpnService, descriptor, FakeTlsDnsServer.trustAllClientFactory());
    }

    @After
    public void tearDown() {
        upstream.shutdown();
        server.close();
        logMock.close();
    }

    private static byte[] queryWire() throws Exception {
        return Message.newQuery(new ARecord(new Name("dot.example.com."),
                DClass.IN, 3600, java.net.Inet4Address.getByAddress(new byte[]{0, 0, 0, 0}))).toWire();
    }

    @Test
    public void resolveRoundTripsLengthPrefixedMessage() throws Exception {
        byte[] query = queryWire();

        byte[] response = upstream.resolve(query);

        Message responseMessage = new Message(response);
        assertEquals(new Message(query).getHeader().getID(), responseMessage.getHeader().getID());
        assertTrue(responseMessage.getHeader().getFlag(Flags.QR));
        assertEquals(1, responseMessage.getSectionArray(Section.ANSWER).length);

        // The server parsed exactly the query bytes out of the 2-byte
        // framing (a framing bug would have desynchronized readFully).
        assertEquals(1, server.acceptedConnections.get());
        assertArrayEquals(query, server.receivedQueries.get(0));

        // Upstream traffic must be protected from our own VPN.
        verify(vpnService).protect(any(Socket.class));
    }

    @Test
    public void keepAliveReusesOneConnection() throws Exception {
        upstream.resolve(queryWire());
        upstream.resolve(queryWire());

        assertEquals(2, server.receivedQueries.size());
        assertEquals(1, server.acceptedConnections.get());
    }

    @Test
    public void stalePooledSocketIsRetriedOnFreshConnection() throws Exception {
        // Server drops the connection after each answer, so the second
        // resolve() finds a pooled socket the server has already closed.
        server.oneQueryPerConnection = true;

        assertNotNull(upstream.resolve(queryWire()));
        assertNotNull(upstream.resolve(queryWire()));

        assertEquals(2, server.acceptedConnections.get());
    }

    @Test
    public void freshSocketFailurePropagates() throws Exception {
        server.oneQueryPerConnection = true;
        upstream.resolve(queryWire());
        // Take the whole server down: the pooled socket is dead AND no new
        // connection can be made, so the retry-once logic must give up and
        // let the fresh-socket failure propagate.
        server.close();

        assertThrows(IOException.class, () -> upstream.resolve(queryWire()));
    }

    @Test
    public void hostnameMismatchFailsTheHandshakeWithoutRetry() throws Exception {
        // The impostor presents a valid-format certificate, but not one
        // valid for 127.0.0.1 (the host the upstream dials), so hostname
        // verification must reject it: an encrypted connection to the wrong
        // identity is worth nothing. Trusting the chain is not enough.
        try (FakeTlsDnsServer impostor = new FakeTlsDnsServer(false, "dns:impostor.example.com")) {
            DnsUpstream descriptor = DnsUpstream.parse("tls://127.0.0.1:" + impostor.port());
            DotUpstream mismatched = new DotUpstream(vpnService, descriptor, FakeTlsDnsServer.trustAllClientFactory());
            try {
                // An SSLException (rather than, say, a connect failure)
                // proves the certificate was rejected by the check, and the
                // fresh-socket failure must propagate: a mismatch is never
                // stale-connection material to retry into a success.
                IOException e = assertThrows(IOException.class, () -> mismatched.resolve(queryWire()));
                assertTrue("Expected a TLS verification failure, got: " + e, e instanceof SSLException);
                // The query must never have reached the impostor.
                assertEquals(0, impostor.receivedQueries.size());
            } finally {
                mismatched.shutdown();
            }
        }
    }

    @Test
    public void upstreamDescriptorPointsAtServer() throws Exception {
        // Sanity check that the descriptor parsing lines up with what the
        // pool actually connects to.
        assertEquals("tls://127.0.0.1:" + server.port(), upstream.upstream.toString());
    }
}
