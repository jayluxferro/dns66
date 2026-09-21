/* This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 */
package org.jak_linux.dns66.vpn;

import java.net.InetAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.UnknownHostException;

/**
 * Description of one upstream DNS server, parsed from a configuration
 * location string. The location syntax determines the protocol:
 *
 * <ul>
 *     <li>{@code 1.2.3.4} or {@code 1.2.3.4:53} or IPv6 - plain UDP DNS</li>
 *     <li>{@code tls://1.2.3.4[:853]} - DNS over TLS</li>
 *     <li>{@code https://host[:443]/path} - DNS over HTTPS</li>
 * </ul>
 */
public class DnsUpstream {
    private static final int DEFAULT_PLAIN_PORT = 53;
    private static final int DEFAULT_DOT_PORT = 853;
    private static final int DEFAULT_DOH_PORT = 443;

    public enum Protocol {
        PLAIN,
        DOT,
        DOH,
    }

    public final Protocol protocol;
    /**
     * Host name or IP address of the upstream, as written in the
     * configuration. Only resolved to an {@link InetAddress} for
     * {@link Protocol#PLAIN}, which needs it for the UDP relay.
     */
    public final String host;
    public final int port;
    /** Request path for DNS over HTTPS, including the leading slash. */
    public final String dohPath;
    /** Resolved address for plain upstreams; null for DOT/DOH. */
    public final InetAddress address;

    private DnsUpstream(Protocol protocol, String host, int port, String dohPath, InetAddress address) {
        this.protocol = protocol;
        this.host = host;
        this.port = port;
        this.dohPath = dohPath;
        this.address = address;
    }

    public static DnsUpstream plain(String host, int port, InetAddress address) {
        return new DnsUpstream(Protocol.PLAIN, host, port, null, address);
    }

    /**
     * Parses a DNS server location. See the class documentation for the
     * accepted syntax.
     *
     * @param location The location string from the configuration
     * @return The upstream description
     * @throws UnknownHostException If a plain or DoT host is not a valid
     *                              address (plain hosts are resolved here,
     *                              as the UDP relay needs the address)
     * @throws URISyntaxException   If a DoH URL is invalid
     */
    public static DnsUpstream parse(String location) throws UnknownHostException, URISyntaxException {
        if (location == null || location.isEmpty())
            throw new UnknownHostException("Empty DNS server location");

        if (location.startsWith("https://")) {
            URI uri = new URI(location);
            String host = uri.getHost();
            if (host == null || uri.getPath() == null || uri.getPath().isEmpty())
                throw new URISyntaxException(location, "DoH location needs a host and a path");
            int port = uri.getPort() == -1 ? DEFAULT_DOH_PORT : uri.getPort();
            return new DnsUpstream(Protocol.DOH, host, port, uri.getPath(), null);
        }

        String remainder = location;
        if (location.startsWith("tls://")) {
            remainder = location.substring("tls://".length());
            HostAndPort hp = parseHostAndPort(remainder, DEFAULT_DOT_PORT);
            return new DnsUpstream(Protocol.DOT, hp.host, hp.port, null, null);
        }

        HostAndPort hp = parseHostAndPort(remainder, DEFAULT_PLAIN_PORT);
        InetAddress address = InetAddress.getByName(hp.host);
        return new DnsUpstream(Protocol.PLAIN, hp.host, hp.port, null, address);
    }

    private static HostAndPort parseHostAndPort(String s, int defaultPort) {
        // [2001:db8::1]:53 style
        if (s.startsWith("[")) {
            int close = s.indexOf(']');
            if (close < 0)
                throw new IllegalArgumentException("Missing ] in address: " + s);
            String host = s.substring(1, close);
            int port = defaultPort;
            if (s.length() > close + 1 && s.charAt(close + 1) == ':')
                port = Integer.parseInt(s.substring(close + 2));
            return new HostAndPort(host, port);
        }
        int colon = s.lastIndexOf(':');
        if (colon > -1 && s.indexOf(':') == colon) {
            // Exactly one colon: host:port
            return new HostAndPort(s.substring(0, colon), Integer.parseInt(s.substring(colon + 1)));
        }
        return new HostAndPort(s, defaultPort);
    }

    private static class HostAndPort {
        final String host;
        final int port;

        HostAndPort(String host, int port) {
            this.host = host;
            this.port = port;
        }
    }

    @Override
    public String toString() {
        switch (protocol) {
            case DOH:
                return "https://" + host + ":" + port + dohPath;
            case DOT:
                return "tls://" + host + ":" + port;
            case PLAIN:
            default:
                return host + ":" + port;
        }
    }
}
