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

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Tests {@link DohUpstream} against a real in-process TLS server: RFC 8484
 * request format, Content-Length and chunked response decoding, HTTP error
 * status handling, keep-alive, and the stale-socket retry in
 * {@link SecureUpstream#resolve}.
 */
public class DohUpstreamTest {

    private MockedStatic<Log> logMock;
    private VpnService vpnService;
    private FakeTlsDnsServer server;
    private DohUpstream upstream;

    @Before
    public void setUp() throws Exception {
        // SecureUpstream logs on the stale-socket retry path; android.util.Log
        // is not mockable without this.
        logMock = Mockito.mockStatic(Log.class);
        vpnService = Mockito.mock(VpnService.class);
        when(vpnService.protect(any(Socket.class))).thenReturn(true);

        server = new FakeTlsDnsServer(true);
        DnsUpstream descriptor = DnsUpstream.parse("https://127.0.0.1:" + server.port() + "/dns-query");
        upstream = new DohUpstream(vpnService, descriptor, FakeTlsDnsServer.trustAllClientFactory());
    }

    @After
    public void tearDown() {
        upstream.shutdown();
        server.close();
        logMock.close();
    }

    private static byte[] queryWire() throws Exception {
        return Message.newQuery(new ARecord(new Name("doh.example.com."),
                DClass.IN, 3600, java.net.Inet4Address.getByAddress(new byte[]{0, 0, 0, 0}))).toWire();
    }

    private static void assertValidDnsResponse(byte[] query, byte[] response) throws Exception {
        Message responseMessage = new Message(response);
        assertEquals(new Message(query).getHeader().getID(), responseMessage.getHeader().getID());
        assertTrue(responseMessage.getHeader().getFlag(Flags.QR));
        assertEquals(1, responseMessage.getSectionArray(Section.ANSWER).length);
    }

    @Test
    public void resolvePostsDnsMessageAndDecodesContentLengthResponse() throws Exception {
        byte[] query = queryWire();

        byte[] response = upstream.resolve(query);

        assertValidDnsResponse(query, response);

        // RFC 8484 request shape: POST to the configured path with the
        // DNS message as application/dns-message body.
        assertEquals("POST /dns-query HTTP/1.1", server.lastRequestLine);
        assertEquals("application/dns-message", server.lastContentType);
        // Non-default port must appear in the Host header.
        assertEquals("127.0.0.1:" + server.port(), server.lastHostHeader);
        assertArrayEquals(query, server.receivedQueries.get(0));

        verify(vpnService).protect(any(Socket.class));
        assertEquals(1, server.acceptedConnections.get());
    }

    @Test
    public void decodesChunkedResponseWithExtensionsAndTrailers() throws Exception {
        server.chunked = true;
        byte[] query = queryWire();

        byte[] response = upstream.resolve(query);

        assertValidDnsResponse(query, response);
        assertArrayEquals(query, server.receivedQueries.get(0));
    }

    @Test
    public void non200ResponseThrows() throws Exception {
        server.http500 = true;

        assertThrows(IOException.class, () -> upstream.resolve(queryWire()));

        // The request did reach the server before it failed us.
        assertEquals(1, server.receivedQueries.size());
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
}
