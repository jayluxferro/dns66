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

    public DohUpstream(VpnService vpnService, DnsUpstream upstream) {
        super(vpnService, upstream);
    }

    DohUpstream(VpnService vpnService, DnsUpstream upstream, SSLSocketFactory sslSocketFactory) {
        super(vpnService, upstream, sslSocketFactory);
    }

    @Override
    protected byte[] exchange(SSLSocket socket, byte[] query) throws IOException {
        OutputStream out = socket.getOutputStream();
        String hostHeader = upstream.port == 443 ? upstream.host : upstream.host + ":" + upstream.port;
        byte[] head = ("POST " + upstream.dohPath + " HTTP/1.1\r\n"
                + "Host: " + hostHeader + "\r\n"
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
        if (statusLine == null || !statusLine.startsWith("HTTP/1.1 200") && !statusLine.startsWith("HTTP/1.0 200"))
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
            if (name.equals("content-length"))
                contentLength = Integer.parseInt(value);
            else if (name.equals("transfer-encoding") && value.toLowerCase().contains("chunked"))
                chunked = true;
        }

        if (chunked)
            return readChunkedBody(in);
        if (contentLength < 0)
            throw new IOException("Response has neither Content-Length nor chunked encoding");
        byte[] body = new byte[contentLength];
        readFully(in, body);
        return body;
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

    private static byte[] readChunkedBody(InputStream in) throws IOException {
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        while (true) {
            String sizeLine = readLine(in);
            if (sizeLine == null)
                throw new EOFException("EOF in chunked body");
            int semicolon = sizeLine.indexOf(';');
            int size = Integer.parseInt(semicolon < 0 ? sizeLine : sizeLine.substring(0, semicolon), 16);
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
