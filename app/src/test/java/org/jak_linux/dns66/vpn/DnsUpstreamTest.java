/* This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 */
package org.jak_linux.dns66.vpn;

import org.junit.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.URISyntaxException;
import java.net.UnknownHostException;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertThrows;

/**
 * Tests for the upstream location parser: one test per accepted syntax
 * form, plus the error cases. The parsed descriptor drives the protocol
 * dispatch in {@link DnsPacketProxy}, so the port defaults matter.
 */
public class DnsUpstreamTest {

    @Test
    public void plainIpv4DefaultsToPort53() throws Exception {
        DnsUpstream upstream = DnsUpstream.parse("192.0.2.1");

        assertEquals(DnsUpstream.Protocol.PLAIN, upstream.protocol);
        assertEquals("192.0.2.1", upstream.host);
        assertEquals(53, upstream.port);
        assertNull(upstream.dohPath);
        // Plain upstreams must carry the resolved address for the UDP relay
        assertEquals(InetAddress.getByName("192.0.2.1"), upstream.address);
        assertSame(Inet4Address.class, upstream.address.getClass());
    }

    @Test
    public void plainIpv4WithExplicitPort() throws Exception {
        DnsUpstream upstream = DnsUpstream.parse("192.0.2.1:5353");

        assertEquals(DnsUpstream.Protocol.PLAIN, upstream.protocol);
        assertEquals("192.0.2.1", upstream.host);
        assertEquals(5353, upstream.port);
        assertEquals(InetAddress.getByName("192.0.2.1"), upstream.address);
    }

    @Test
    public void plainBareIpv6HasMultipleColonsSoNoPortSplit() throws Exception {
        DnsUpstream upstream = DnsUpstream.parse("2001:db8::1");

        assertEquals(DnsUpstream.Protocol.PLAIN, upstream.protocol);
        assertEquals("2001:db8::1", upstream.host);
        assertEquals(53, upstream.port);
        assertEquals(InetAddress.getByName("2001:db8::1"), upstream.address);
        assertSame(Inet6Address.class, upstream.address.getClass());
    }

    @Test
    public void plainBracketedIpv6WithPort() throws Exception {
        DnsUpstream upstream = DnsUpstream.parse("[2001:db8::1]:5353");

        assertEquals(DnsUpstream.Protocol.PLAIN, upstream.protocol);
        assertEquals("2001:db8::1", upstream.host);
        assertEquals(5353, upstream.port);
        assertEquals(InetAddress.getByName("2001:db8::1"), upstream.address);
    }

    @Test
    public void plainBracketedIpv6WithoutPort() throws Exception {
        DnsUpstream upstream = DnsUpstream.parse("[2001:db8::1]");

        assertEquals(DnsUpstream.Protocol.PLAIN, upstream.protocol);
        assertEquals("2001:db8::1", upstream.host);
        assertEquals(53, upstream.port);
    }

    @Test
    public void plainHostnamesResolveHere() throws Exception {
        // The UDP relay needs the address at configure time, so plain
        // locations are resolved eagerly; a literal needs no DNS lookup.
        DnsUpstream upstream = DnsUpstream.parse("192.0.2.7");

        assertEquals(InetAddress.getByName("192.0.2.7"), upstream.address);
    }

    @Test
    public void dotDefaultsToPort853() throws Exception {
        DnsUpstream upstream = DnsUpstream.parse("tls://dot.example.com");

        assertEquals(DnsUpstream.Protocol.DOT, upstream.protocol);
        assertEquals("dot.example.com", upstream.host);
        assertEquals(853, upstream.port);
        assertNull(upstream.dohPath);
        // Encrypted upstreams are not resolved at parse time - the TLS
        // connection does that.
        assertNull(upstream.address);
    }

    @Test
    public void dotWithExplicitPort() throws Exception {
        DnsUpstream upstream = DnsUpstream.parse("tls://192.0.2.1:8853");

        assertEquals(DnsUpstream.Protocol.DOT, upstream.protocol);
        assertEquals("192.0.2.1", upstream.host);
        assertEquals(8853, upstream.port);
    }

    @Test
    public void dohDefaultsToPort443AndKeepsPath() throws Exception {
        DnsUpstream upstream = DnsUpstream.parse("https://doh.example.com/dns-query");

        assertEquals(DnsUpstream.Protocol.DOH, upstream.protocol);
        assertEquals("doh.example.com", upstream.host);
        assertEquals(443, upstream.port);
        assertEquals("/dns-query", upstream.dohPath);
        assertNull(upstream.address);
    }

    @Test
    public void dohWithExplicitPortAndPath() throws Exception {
        DnsUpstream upstream = DnsUpstream.parse("https://doh.example.com:8443/dns-query");

        assertEquals(DnsUpstream.Protocol.DOH, upstream.protocol);
        assertEquals("doh.example.com", upstream.host);
        assertEquals(8443, upstream.port);
        assertEquals("/dns-query", upstream.dohPath);
    }

    @Test
    public void dohWithIpLiteralHost() throws Exception {
        // The default resolvers use IP URLs (certs carry IP SANs)
        DnsUpstream upstream = DnsUpstream.parse("https://1.1.1.1/dns-query");

        assertEquals(DnsUpstream.Protocol.DOH, upstream.protocol);
        assertEquals("1.1.1.1", upstream.host);
        assertEquals(443, upstream.port);
        assertEquals("/dns-query", upstream.dohPath);
    }

    @Test
    public void dohWithoutPathIsRejected() {
        assertThrows(URISyntaxException.class, () -> DnsUpstream.parse("https://doh.example.com"));
    }

    @Test
    public void dohWithRootPathIsAccepted() throws Exception {
        // Only a completely missing path is rejected; "/" is a (if
        // unusual) path and pins current parser behavior.
        DnsUpstream upstream = DnsUpstream.parse("https://doh.example.com/");

        assertEquals("/", upstream.dohPath);
        assertEquals(443, upstream.port);
    }

    @Test
    public void emptyLocationIsRejected() {
        assertThrows(UnknownHostException.class, () -> DnsUpstream.parse(""));
    }

    @Test
    public void nullLocationIsRejected() {
        assertThrows(UnknownHostException.class, () -> DnsUpstream.parse(null));
    }

    @Test
    public void invalidPlainLocationIsRejected() {
        // Plain locations are resolved here, so a bad host must surface as
        // UnknownHostException. We cannot use a garbage name directly: the
        // result would depend on whatever DNS/search-domain the build
        // machine has (wildcard resolvers "resolve" anything), so the
        // resolution is mocked to fail deterministically.
        try (MockedStatic<InetAddress> inetAddressMock = Mockito.mockStatic(InetAddress.class)) {
            inetAddressMock.when(() -> InetAddress.getByName("bad.example.invalid"))
                    .thenThrow(new UnknownHostException("bad.example.invalid"));

            assertThrows(UnknownHostException.class, () -> DnsUpstream.parse("bad.example.invalid"));
        }
    }

    @Test
    public void unbracketedMissingCloseBracketIsRejected() {
        // Documents current behavior: the bracket parser throws
        // IllegalArgumentException, which configure() catches per item.
        assertThrows(IllegalArgumentException.class, () -> DnsUpstream.parse("[2001:db8::1"));
    }

    @Test
    public void toStringRoundTripsForAllProtocols() throws Exception {
        assertEquals("192.0.2.1:53", DnsUpstream.parse("192.0.2.1").toString());
        assertEquals("192.0.2.1:5353", DnsUpstream.parse("192.0.2.1:5353").toString());

        // DoT/DoH round-trip: re-parsing the rendering must yield the same
        // fields, as these strings are what AdVpnThread logs.
        DnsUpstream dot = DnsUpstream.parse("tls://dot.example.com");
        assertEquals("tls://dot.example.com:853", dot.toString());
        DnsUpstream dotReparsed = DnsUpstream.parse(dot.toString());
        assertEquals(DnsUpstream.Protocol.DOT, dotReparsed.protocol);
        assertEquals(dot.host, dotReparsed.host);
        assertEquals(dot.port, dotReparsed.port);

        DnsUpstream doh = DnsUpstream.parse("https://doh.example.com:8443/dns-query");
        assertEquals("https://doh.example.com:8443/dns-query", doh.toString());
        DnsUpstream dohReparsed = DnsUpstream.parse(doh.toString());
        assertEquals(DnsUpstream.Protocol.DOH, dohReparsed.protocol);
        assertEquals(doh.host, dohReparsed.host);
        assertEquals(doh.port, dohReparsed.port);
        assertEquals(doh.dohPath, dohReparsed.dohPath);
    }

    @Test
    public void plainFactorySkipsParsing() throws Exception {
        // AdVpnThread wraps system DNS servers with this factory
        InetAddress address = InetAddress.getByName("192.0.2.9");
        DnsUpstream upstream = DnsUpstream.plain("192.0.2.9", 53, address);

        assertEquals(DnsUpstream.Protocol.PLAIN, upstream.protocol);
        assertEquals("192.0.2.9", upstream.host);
        assertEquals(53, upstream.port);
        assertSame(address, upstream.address);
        assertEquals("192.0.2.9:53", upstream.toString());
    }
}
