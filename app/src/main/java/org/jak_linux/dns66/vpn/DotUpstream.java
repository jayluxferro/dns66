/* This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 */
package org.jak_linux.dns66.vpn;

import android.net.VpnService;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

/**
 * DNS over TLS upstream (RFC 7858): DNS messages exchanged over a TLS
 * connection with a 2-byte big-endian length prefix.
 */
public class DotUpstream extends SecureUpstream {

    public DotUpstream(VpnService vpnService, DnsUpstream upstream) {
        super(vpnService, upstream);
    }

    DotUpstream(VpnService vpnService, DnsUpstream upstream, SSLSocketFactory sslSocketFactory) {
        super(vpnService, upstream, sslSocketFactory);
    }

    @Override
    protected byte[] exchange(SSLSocket socket, byte[] query) throws IOException {
        DataOutputStream out = new DataOutputStream(socket.getOutputStream());
        out.writeShort(query.length);
        out.write(query);
        out.flush();

        DataInputStream in = new DataInputStream(socket.getInputStream());
        int length = in.readUnsignedShort();
        byte[] response = new byte[length];
        in.readFully(response);
        return response;
    }
}
