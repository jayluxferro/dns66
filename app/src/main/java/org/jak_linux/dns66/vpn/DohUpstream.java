/* This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 */
package org.jak_linux.dns66.vpn;

import android.net.VpnService;

import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

/**
 * DNS over HTTPS upstream (RFC 8484): DNS messages posted as
 * {@code application/dns-message} over HTTP/1.1 with keep-alive, running
 * on our own protected TLS connection (HttpURLConnection sockets cannot be
 * protected from the VPN, and managing the connection ourselves lets us
 * pool and reuse it).
 */
public class DohUpstream extends SecureUpstream {
    /**
     * Sanity caps against a hostile or broken server: DNS messages are
     * bounded by 64 KiB (the 2-byte DNS/TCP length prefix), so anything
     * beyond these limits is a protocol violation, not a valid answer -
     * and parsing it would let a peer make us allocate absurd buffers.
     */
    private static final int MAX_HEADER_LINE_BYTES = 16384;
    private static final int MAX_MESSAGE_BYTES = 128 * 1024;

    public DohUpstream(VpnService vpnService, DnsUpstream upstream) {
        super(vpnService, upstream);
    }

    DohUpstream(VpnService vpnService, DnsUpstream upstream, SSLSocketFactory sslSocketFactory) {
        super(vpnService, upstream, sslSocketFactory);
    }

    @Override
    protected byte[] exchange(SSLSocket socket, byte[] query) throws IOException {
        OutputStream out = socket.getOutputStream();
        byte[] head = ("POST " + upstream.dohPath + " HTTP/1.1\r\n"
                + "Host: " + hostHeader(upstream.host, upstream.port) + "\r\n"
                + "Content-Type: application/dns-message\r\n"
                + "Accept: application/dns-message\r\n"
                + "Connection: keep-alive\r\n"
                + "Content-Length: " + query.length + "\r\n"
                + "\r\n").getBytes(StandardCharsets.US_ASCII);
        out.write(head);
        out.write(query);
        out.flush();

        InputStream in = socket.getInputStream();
        String statusLine = readLine(in);
        // Skip 1xx interim responses (including their headers); the real
        // answer follows them.
        while (isInformational(statusLine)) {
            String interim;
            while ((interim = readLine(in)) != null && !interim.isEmpty()) {
                // Ignore interim headers
            }
            statusLine = readLine(in);
        }
        if (!isOk(statusLine))
            throw new IOException("Unexpected HTTP response: " + statusLine);

        int contentLength = -1;
        boolean chunked = false;
        String line;
        while ((line = readLine(in)) != null && !line.isEmpty()) {
            int colon = line.indexOf(':');
            if (colon < 0)
                continue;
            String name = line.substring(0, colon).trim().toLowerCase();
            String value = line.substring(colon + 1).trim();
            if (name.equals("content-length")) {
                try {
                    contentLength = Integer.parseInt(value);
                } catch (NumberFormatException e) {
                    throw new IOException("Invalid Content-Length: " + value);
                }
                if (contentLength < 0 || contentLength > MAX_MESSAGE_BYTES)
                    throw new IOException("Unreasonable Content-Length: " + contentLength);
            } else if (name.equals("transfer-encoding") && value.toLowerCase().contains("chunked"))
                chunked = true;
            else if (name.equals("content-encoding") && !value.equalsIgnoreCase("identity"))
                // We never request compression; decompressing would mean
                // parsing yet another attacker-controlled format.
                throw new IOException("Unexpected Content-Encoding: " + value);
        }

        if (chunked)
            return readChunkedBody(in);
        if (contentLength < 0)
            throw new IOException("Response has neither Content-Length nor chunked encoding");
        byte[] body = new byte[contentLength];
        readFully(in, body);
        return body;
    }

    /** The Host header value for a request to host:port (RFC 7230 section 5.4). */
    static String hostHeader(String host, int port) {
        // IPv6 literals must be bracketed, else they are indistinguishable
        // from host:port (RFC 3986 section 3.2.2).
        String literal = host.contains(":") ? "[" + host + "]" : host;
        return port == 443 ? literal : literal + ":" + port;
    }

    /** An interim (1xx) response whose headers must be skipped before the real status line. */
    private static boolean isInformational(String statusLine) {
        if (statusLine == null)
            return false;
        return statusLine.startsWith("HTTP/1.1 1") || statusLine.startsWith("HTTP/1.0 1");
    }

    /** Only 200 is a valid DoH answer (RFC 8484 section 4.1). */
    private static boolean isOk(String statusLine) {
        if (statusLine == null || !statusLine.startsWith("HTTP/1."))
            return false;
        String[] parts = statusLine.split(" ");
        if (parts.length < 2)
            return false;
        try {
            return Integer.parseInt(parts[1]) == 200;
        } catch (NumberFormatException e) {
            return false;
        }
    }

    private static String readLine(InputStream in) throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        int c;
        while ((c = in.read()) != -1) {
            if (c == '\n')
                break;
            buffer.write(c);
            if (buffer.size() > MAX_HEADER_LINE_BYTES)
                throw new IOException("Header line too long");
        }
        if (c == -1 && buffer.size() == 0)
            return null;
        byte[] bytes = buffer.toByteArray();
        int end = bytes.length;
        if (end > 0 && bytes[end - 1] == '\r')
            end--;
        return new String(bytes, 0, end, StandardCharsets.US_ASCII);
    }

    private static byte[] readChunkedBody(InputStream in) throws IOException {
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        while (true) {
            String sizeLine = readLine(in);
            if (sizeLine == null)
                throw new EOFException("EOF in chunked body");
            int semicolon = sizeLine.indexOf(';');
            String sizeField = (semicolon < 0 ? sizeLine : sizeLine.substring(0, semicolon)).trim();
            int size;
            try {
                size = Integer.parseInt(sizeField, 16);
            } catch (NumberFormatException e) {
                throw new IOException("Invalid chunk size: " + sizeLine);
            }
            if (size < 0 || size > MAX_MESSAGE_BYTES - body.size())
                throw new IOException("Unreasonable chunk size: " + sizeLine);
            if (size == 0)
                break;
            byte[] chunk = new byte[size];
            readFully(in, chunk);
            body.write(chunk, 0, size);
            // Trailing CRLF after each chunk
            readLine(in);
        }
        // Consume trailer headers until the final empty line
        String line;
        while ((line = readLine(in)) != null && !line.isEmpty()) {
            // Ignore trailers
        }
        return body.toByteArray();
    }

    private static void readFully(InputStream in, byte[] buffer) throws IOException {
        int off = 0;
        while (off < buffer.length) {
            int read = in.read(buffer, off, buffer.length - off);
            if (read < 0)
                throw new EOFException();
            off += read;
        }
    }
}
