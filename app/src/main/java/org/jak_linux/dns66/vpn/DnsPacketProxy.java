/* Copyright (C) 2016-2019 Software Freedom Conservancy (author: Julian Andres Klode) <jak@jak-linux.org>
 *
 * Derived from AdBuster:
 * Copyright (C) 2016 Daniel Brodie <dbrodie@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * Contributions shall also be provided under any later versions of the
 * GPL.
 */
package org.jak_linux.dns66.vpn;

import android.content.Context;
import android.net.VpnService;
import android.util.Log;

import org.jak_linux.dns66.db.RuleDatabase;
import org.pcap4j.packet.IpPacket;
import org.pcap4j.packet.IpSelector;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV6Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.UdpPacket;
import org.pcap4j.packet.UnknownPacket;
import org.xbill.DNS.DClass;
import org.xbill.DNS.Flags;
import org.xbill.DNS.Message;
import org.xbill.DNS.Name;
import org.xbill.DNS.Rcode;
import org.xbill.DNS.SOARecord;
import org.xbill.DNS.Section;
import org.xbill.DNS.TextParseException;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.Executors;

/**
 * Creates and parses packets, and sends packets to a remote socket or the device using
 * {@link AdVpnThread}.
 */
public class DnsPacketProxy {

    private static final String TAG = "DnsPacketProxy";
    // Choose a value that is smaller than the time needed to unblock a host.
    private static final int NEGATIVE_CACHE_TTL_SECONDS = 5;
    private static final SOARecord NEGATIVE_CACHE_SOA_RECORD;

    static {
        try {
            // Let's use a guaranteed invalid hostname here, clients are not supposed to use
            // our fake values, the whole thing just exists for negative caching.
            Name name = new Name("dns66.dns66.invalid.");
            NEGATIVE_CACHE_SOA_RECORD = new SOARecord(name, DClass.IN, NEGATIVE_CACHE_TTL_SECONDS,
                    name, name, 0, 0, 0, 0, NEGATIVE_CACHE_TTL_SECONDS);
        } catch (TextParseException e) {
            throw new RuntimeException(e);
        }
    }

    final RuleDatabase ruleDatabase;
    private final EventLoop eventLoop;
    private VpnService vpnService;
    ArrayList<DnsUpstream> upstreamDnsServers = new ArrayList<>();
    /**
     * Encrypted upstreams (DoT/DoH), created lazily per configured server.
     * Keyed by identity, as servers are unique instances of {@link DnsUpstream}.
     */
    private final Map<DnsUpstream, SecureUpstream> secureUpstreams = new IdentityHashMap<>();
    /**
     * Recreated on every {@link #initialize}: the VPN thread restarts (e.g. on
     * network changes) by exiting run() - which shuts this down - and
     * re-initializing, so a fixed pool would be dead after the first restart.
     */
    private ExecutorService resolveExecutor = newResolveExecutor();

    public DnsPacketProxy(EventLoop eventLoop, RuleDatabase database) {
        this.eventLoop = eventLoop;
        this.ruleDatabase = database;
    }

    public DnsPacketProxy(EventLoop eventLoop) {
        this.eventLoop = eventLoop;
        this.ruleDatabase = RuleDatabase.getInstance();
    }

    /**
     * Initializes the rules database and the list of upstream servers.
     *
     * @param vpnService         The VPN service we are running in (used to keep
     *                           encrypted upstream traffic out of the VPN)
     * @param upstreamDnsServers The upstream DNS servers to use; or an empty list if no
     *                           rewriting of ip addresses takes place
     * @throws InterruptedException If the database initialization was interrupted
     */
    void initialize(VpnService vpnService, ArrayList<DnsUpstream> upstreamDnsServers) throws InterruptedException {
        ruleDatabase.initialize(vpnService);
        this.vpnService = vpnService;
        this.upstreamDnsServers = upstreamDnsServers;
        resolveExecutor.shutdown();
        resolveExecutor = newResolveExecutor();
    }

    private static ExecutorService newResolveExecutor() {
        return Executors.newFixedThreadPool(3, runnable -> {
            Thread thread = new Thread(runnable, "Dns66SecureResolve");
            thread.setDaemon(true);
            return thread;
        });
    }

    /**
     * Returns the connection pool for an encrypted upstream, creating it on
     * first use. Creation has to be lazy: the upstream list is populated by
     * {@link AdVpnThread#configure()} after this proxy is initialized, so
     * pools cannot be pre-built in {@link #initialize}.
     */
    SecureUpstream secureUpstreamFor(DnsUpstream upstream) {
        synchronized (secureUpstreams) {
            SecureUpstream secureUpstream = secureUpstreams.get(upstream);
            if (secureUpstream == null) {
                switch (upstream.protocol) {
                    case DOT:
                        secureUpstream = new DotUpstream(vpnService, upstream);
                        break;
                    case DOH:
                        secureUpstream = new DohUpstream(vpnService, upstream);
                        break;
                    default:
                        return null;
                }
                secureUpstreams.put(upstream, secureUpstream);
            }
            return secureUpstream;
        }
    }

    /** Releases the encrypted upstream connection pools and the resolver threads. */
    void shutdown() {
        resolveExecutor.shutdown();
        // secureUpstreamFor() runs on resolver threads and may still be
        // putting entries in, so copy out under the lock: iterating the map
        // directly would race with those puts (ConcurrentModificationException).
        List<SecureUpstream> upstreams;
        synchronized (secureUpstreams) {
            upstreams = new ArrayList<>(secureUpstreams.values());
            secureUpstreams.clear();
        }
        for (SecureUpstream secureUpstream : upstreams)
            secureUpstream.shutdown();
    }

    /**
     * Handles a responsePayload from an upstream DNS server
     *
     * @param requestPacket   The original request packet
     * @param responsePayload The payload of the response
     */
    void handleDnsResponse(IpPacket requestPacket, byte[] responsePayload) {
        UdpPacket udpOutPacket = (UdpPacket) requestPacket.getPayload();
        UdpPacket.Builder payLoadBuilder = new UdpPacket.Builder(udpOutPacket)
                .srcPort(udpOutPacket.getHeader().getDstPort())
                .dstPort(udpOutPacket.getHeader().getSrcPort())
                .srcAddr(requestPacket.getHeader().getDstAddr())
                .dstAddr(requestPacket.getHeader().getSrcAddr())
                .correctChecksumAtBuild(true)
                .correctLengthAtBuild(true)
                .payloadBuilder(
                        new UnknownPacket.Builder()
                                .rawData(responsePayload)
                );


        IpPacket ipOutPacket;
        if (requestPacket instanceof IpV4Packet) {
            ipOutPacket = new IpV4Packet.Builder((IpV4Packet) requestPacket)
                    .srcAddr((Inet4Address) requestPacket.getHeader().getDstAddr())
                    .dstAddr((Inet4Address) requestPacket.getHeader().getSrcAddr())
                    .correctChecksumAtBuild(true)
                    .correctLengthAtBuild(true)
                    .payloadBuilder(payLoadBuilder)
                    .build();

        } else {
            ipOutPacket = new IpV6Packet.Builder((IpV6Packet) requestPacket)
                    .srcAddr((Inet6Address) requestPacket.getHeader().getDstAddr())
                    .dstAddr((Inet6Address) requestPacket.getHeader().getSrcAddr())
                    .correctLengthAtBuild(true)
                    .payloadBuilder(payLoadBuilder)
                    .build();
        }

        eventLoop.queueDeviceWrite(ipOutPacket);
    }

    /**
     * Handles a DNS request, by either blocking it or forwarding it to the remote location.
     *
     * @param packetData The packet data to read
     * @throws AdVpnThread.VpnNetworkException If some network error occurred
     */
    void handleDnsRequest(byte[] packetData) throws AdVpnThread.VpnNetworkException {

        IpPacket parsedPacket = null;
        try {
            parsedPacket = (IpPacket) IpSelector.newPacket(packetData, 0, packetData.length);
        } catch (Exception e) {
            Log.d(TAG, "handleDnsRequest: Discarding invalid IP packet", e);
            return;
        }

        UdpPacket parsedUdp;
        Packet udpPayload;

        try {
            parsedUdp = (UdpPacket) parsedPacket.getPayload();
            udpPayload = parsedUdp.getPayload();
        } catch (Exception e) {
            try {
                Log.d(TAG, "handleDnsRequest: Discarding unknown packet type " + parsedPacket.getHeader(), e);
            } catch (Exception e1) {
                Log.d(TAG, "handleDnsRequest: Discarding unknown packet type, could not log packet info", e1);
            }
            return;
        }

        DnsUpstream upstream = translateDestination(parsedPacket);
        if (upstream == null)
            return;

        if (udpPayload == null) {
            try {
                Log.i(TAG, "handleDnsRequest: Sending UDP packet without payload: " + parsedUdp);
            } catch (Exception e1) {
                Log.i(TAG, "handleDnsRequest: Sending UDP packet without payload");
            }

            // Let's be nice to Firefox. Firefox uses an empty UDP packet to
            // the gateway to reduce the RTT. For further details, please see
            // https://bugzilla.mozilla.org/show_bug.cgi?id=888268
            // (Only meaningful for plain upstreams we can relay to.)
            if (upstream.address != null) {
                try {
                    DatagramPacket outPacket = new DatagramPacket(new byte[0], 0, 0 /* length */, upstream.address, parsedUdp.getHeader().getDstPort().valueAsInt());
                    eventLoop.forwardPacket(outPacket, null);
                } catch (Exception e) {
                    Log.i(TAG, "handleDnsRequest: Could not send empty UDP packet", e);
                }
            }
            return;
        }

        byte[] dnsRawData = udpPayload.getRawData();
        Message dnsMsg;
        try {
            dnsMsg = new Message(dnsRawData);
        } catch (IOException e) {
            Log.d(TAG, "handleDnsRequest: Discarding non-DNS or invalid packet", e);
            return;
        }
        if (dnsMsg.getQuestion() == null) {
            Log.d(TAG, "handleDnsRequest: Discarding DNS packet with no query " + dnsMsg);
            return;
        }
        String dnsQueryName = dnsMsg.getQuestion().getName().toString(true);
        if (!ruleDatabase.isBlocked(dnsQueryName.toLowerCase(Locale.ENGLISH))) {
            Log.i(TAG, "handleDnsRequest: DNS Name " + dnsQueryName + " Allowed, sending to " + upstream);
            if (upstream.protocol == DnsUpstream.Protocol.PLAIN) {
                InetAddress destAddr = upstream.address != null ? upstream.address : parsedPacket.getHeader().getDstAddr();
                DatagramPacket outPacket = new DatagramPacket(dnsRawData, 0, dnsRawData.length, destAddr, parsedUdp.getHeader().getDstPort().valueAsInt());
                eventLoop.forwardPacket(outPacket, parsedPacket);
            } else {
                resolveSecure(upstream, parsedPacket, dnsRawData, dnsMsg);
            }
        } else {
            Log.i(TAG, "handleDnsRequest: DNS Name " + dnsQueryName + " Blocked!");
            dnsMsg.getHeader().setFlag(Flags.QR);
            dnsMsg.getHeader().setRcode(Rcode.NOERROR);
            dnsMsg.addRecord(NEGATIVE_CACHE_SOA_RECORD, Section.AUTHORITY);
            handleDnsResponse(parsedPacket, dnsMsg.toWire());
        }
    }

    /**
     * Resolves a query via an encrypted upstream (DoT/DoH) on a worker
     * thread, and turns the answer into a client response. Failures produce
     * a SERVFAIL reply so the client can immediately try the next server.
     */
    private void resolveSecure(DnsUpstream upstream, final IpPacket requestPacket, final byte[] dnsRawData, final Message dnsMsg) {
        final SecureUpstream secureUpstream = secureUpstreamFor(upstream);
        if (secureUpstream == null) {
            Log.e(TAG, "resolveSecure: No connection pool for " + upstream);
            sendServFail(requestPacket, dnsMsg);
            return;
        }
        try {
            resolveExecutor.execute(() -> {
                try {
                    byte[] response = secureUpstream.resolve(dnsRawData);
                    handleDnsResponse(requestPacket, response);
                } catch (IOException | RuntimeException e) {
                    Log.i(TAG, "resolveSecure: Upstream " + upstream + " failed", e);
                    sendServFail(requestPacket, dnsMsg);
                }
            });
        } catch (RejectedExecutionException e) {
            // Pool already shut down (e.g. mid-restart); fail this query
            // gracefully instead of killing the VPN thread.
            Log.w(TAG, "resolveSecure: Resolver threads not available", e);
            sendServFail(requestPacket, dnsMsg);
        }
    }

    private void sendServFail(IpPacket requestPacket, Message dnsMsg) {
        dnsMsg.getHeader().setFlag(Flags.QR);
        dnsMsg.getHeader().setRcode(Rcode.SERVFAIL);
        handleDnsResponse(requestPacket, dnsMsg.toWire());
    }

    /**
     * Determines the upstream a packet is destined for. With address
     * translation in use, this maps the fake alias address back to the
     * configured upstream; otherwise the packet's destination is wrapped
     * into a passthrough plain upstream.
     *
     * @param parsedPacket Packet to get destination address for.
     * @return The upstream description or null on failure.
     */
    private DnsUpstream translateDestination(IpPacket parsedPacket) {
        if (upstreamDnsServers.size() > 0) {
            byte[] addr = parsedPacket.getHeader().getDstAddr().getAddress();
            int index = addr[addr.length - 1] - 2;

            DnsUpstream upstream;
            try {
                upstream = upstreamDnsServers.get(index);
            } catch (Exception e) {
                Log.e(TAG, "handleDnsRequest: Cannot handle packets to " + parsedPacket.getHeader().getDstAddr().getHostAddress() + " - not a valid address for this network", e);
                return null;
            }
            Log.d(TAG, String.format("handleDnsRequest: Incoming packet to %s AKA %d AKA %s", parsedPacket.getHeader().getDstAddr().getHostAddress(), index, upstream));
            return upstream;
        }
        Log.d(TAG, String.format("handleDnsRequest: Incoming packet to %s - is upstream", parsedPacket.getHeader().getDstAddr().getHostAddress()));
        return DnsUpstream.plain(parsedPacket.getHeader().getDstAddr().getHostAddress(), -1, parsedPacket.getHeader().getDstAddr());
    }

    /**
     * Interface abstracting away {@link AdVpnThread}.
     */
    interface EventLoop {
        /**
         * Called to send a packet to a remote location
         *
         * @param packet        The packet to send
         * @param requestPacket If specified, the event loop must wait for a response, and then
         *                      call {@link #handleDnsResponse(IpPacket, byte[])} for the data
         *                      of the response, with this packet as the first argument.
         */
        void forwardPacket(DatagramPacket packet, IpPacket requestPacket) throws AdVpnThread.VpnNetworkException;

        /**
         * Write an IP packet to the local TUN device
         *
         * @param packet The packet to write (a response to a DNS request)
         */
        void queueDeviceWrite(IpPacket packet);
    }
}
