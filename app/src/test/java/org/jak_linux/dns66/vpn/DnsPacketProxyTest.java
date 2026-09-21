package org.jak_linux.dns66.vpn;

import android.net.VpnService;
import android.util.Log;

import org.jak_linux.dns66.Configuration;
import org.jak_linux.dns66.db.RuleDatabase;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.pcap4j.packet.IpPacket;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV4Rfc791Tos;
import org.pcap4j.packet.IpV6Packet;
import org.pcap4j.packet.IpV6SimpleFlowLabel;
import org.pcap4j.packet.IpV6SimpleTrafficClass;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;
import org.pcap4j.packet.UnknownPacket;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.packet.namednumber.IpVersion;
import org.pcap4j.packet.namednumber.TcpPort;
import org.pcap4j.packet.namednumber.UdpPort;
import org.xbill.DNS.ARecord;
import org.xbill.DNS.DClass;
import org.xbill.DNS.Flags;
import org.xbill.DNS.Message;
import org.xbill.DNS.Name;
import org.xbill.DNS.Rcode;
import org.xbill.DNS.Record;
import org.xbill.DNS.SOARecord;
import org.xbill.DNS.Section;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.xbill.DNS.Rcode.NOERROR;
import static org.xbill.DNS.Rcode.NXDOMAIN;

/**
 * Various tests for the core DNS packet proxying code.
 */
// TODO: 19/03/17 Check for correct point of error
public class DnsPacketProxyTest {
    private MockedStatic<Log> logMock;
    private MockEventLoop mockEventLoop;
    private DnsPacketProxy dnsPacketProxy;
    private RuleDatabase ruleDatabase;

    @Before
    public void setUp() throws NoSuchFieldException, IllegalAccessException {
        mockEventLoop = new MockEventLoop();
        ruleDatabase = Mockito.mock(RuleDatabase.class);
        dnsPacketProxy = new DnsPacketProxy(mockEventLoop, ruleDatabase);

        Configuration.Item item = new Configuration.Item();
        item.location = "blocked.example.com";
        item.state = Configuration.Item.STATE_DENY;

        Mockito.when(ruleDatabase.isBlocked("blocked.example.com")).thenReturn(true);

        logMock = Mockito.mockStatic(Log.class);
    }

    @After
    public void tearDown() {
        logMock.close();
    }

    public void tinySetUp() {
        mockEventLoop.lastOutgoing = null;
        mockEventLoop.lastResponse = null;
        dnsPacketProxy.upstreamDnsServers.clear();
    }

    @Test
    public void testInitialize() throws Exception {
        ArrayList<DnsUpstream> dnsServers = new ArrayList<>();
        dnsPacketProxy = new DnsPacketProxy(mockEventLoop, Mockito.mock(RuleDatabase.class));
        dnsPacketProxy.initialize(Mockito.mock(VpnService.class), dnsServers);
        assertSame(dnsServers, dnsPacketProxy.upstreamDnsServers);
    }

    @Test
    public void testHandleDnsRequestNotIpPacket() throws Exception {
        dnsPacketProxy.handleDnsRequest(new byte[]{'f', 'o', 'o'});
        assertNull(mockEventLoop.lastOutgoing);
        assertNull(mockEventLoop.lastResponse);
    }

    @Test
    public void testHandleDnsRequestNotUdpPacket() throws Exception {
        TcpPacket.Builder payLoadBuilder = new TcpPacket.Builder()
                .srcPort(TcpPort.HTTP)
                .dstPort(TcpPort.HTTP)
                .srcAddr(InetAddress.getByAddress(new byte[]{8, 8, 4, 4}))
                .dstAddr(InetAddress.getByAddress(new byte[]{8, 8, 8, 8}))
                .correctChecksumAtBuild(true)
                .correctLengthAtBuild(true)
                .payloadBuilder(
                        new UnknownPacket.Builder()
                                .rawData(new byte[0])
                );

        IpPacket ipOutPacket = new IpV4Packet.Builder()
                .version(IpVersion.IPV4)
                .tos(IpV4Rfc791Tos.newInstance((byte) 0))
                .protocol(IpNumber.UDP)
                .srcAddr((Inet4Address) Inet4Address.getByAddress(new byte[]{8, 8, 4, 4}))
                .dstAddr((Inet4Address) Inet4Address.getByAddress(new byte[]{8, 8, 8, 8}))
                .correctChecksumAtBuild(true)
                .correctLengthAtBuild(true)
                .payloadBuilder(payLoadBuilder)
                .build();

        dnsPacketProxy.handleDnsRequest(ipOutPacket.getRawData());
        assertNull(mockEventLoop.lastOutgoing);
        assertNull(mockEventLoop.lastResponse);
    }

    @Test
    public void testHandleDnsRequestNotDnsPacket() throws Exception {
        UdpPacket.Builder payLoadBuilder = new UdpPacket.Builder()
                .srcPort(UdpPort.HTTP)
                .dstPort(UdpPort.HTTP)
                .srcAddr(InetAddress.getByAddress(new byte[]{8, 8, 4, 4}))
                .dstAddr(InetAddress.getByAddress(new byte[]{8, 8, 8, 8}))
                .correctChecksumAtBuild(true)
                .correctLengthAtBuild(true)
                .payloadBuilder(
                        new UnknownPacket.Builder()
                                .rawData(new byte[]{1, 2, 3, 4, 5})
                );

        IpPacket ipOutPacket = new IpV4Packet.Builder()
                .version(IpVersion.IPV4)
                .tos(IpV4Rfc791Tos.newInstance((byte) 0))
                .protocol(IpNumber.UDP)
                .srcAddr((Inet4Address) Inet4Address.getByAddress(new byte[]{8, 8, 4, 4}))
                .dstAddr((Inet4Address) Inet4Address.getByAddress(new byte[]{8, 8, 8, 8}))
                .correctChecksumAtBuild(true)
                .correctLengthAtBuild(true)
                .payloadBuilder(payLoadBuilder)
                .build();

        dnsPacketProxy.handleDnsRequest(ipOutPacket.getRawData());
        assertNull(mockEventLoop.lastOutgoing);
        assertNull(mockEventLoop.lastResponse);
    }

    @Test
    public void testHandleDnsRequestEmptyPacket() throws Exception {
        UdpPacket.Builder payLoadBuilder = new UdpPacket.Builder()
                .srcPort(UdpPort.DOMAIN)
                .dstPort(UdpPort.DOMAIN)
                .srcAddr(InetAddress.getByAddress(new byte[]{8, 8, 4, 4}))
                .dstAddr(InetAddress.getByAddress(new byte[]{8, 8, 8, 8}))
                .correctChecksumAtBuild(true)
                .correctLengthAtBuild(true)
                .payloadBuilder(
                        new UnknownPacket.Builder()
                                .rawData(new byte[0])
                );

        IpPacket ipOutPacket = new IpV4Packet.Builder()
                .version(IpVersion.IPV4)
                .tos(IpV4Rfc791Tos.newInstance((byte) 0))
                .protocol(IpNumber.UDP)
                .srcAddr((Inet4Address) Inet4Address.getByAddress(new byte[]{8, 8, 4, 4}))
                .dstAddr((Inet4Address) Inet4Address.getByAddress(new byte[]{8, 8, 8, 8}))
                .correctChecksumAtBuild(true)
                .correctLengthAtBuild(true)
                .payloadBuilder(payLoadBuilder)
                .build();

        dnsPacketProxy.handleDnsRequest(ipOutPacket.getRawData());

        assertNotNull(mockEventLoop.lastOutgoing);
        assertEquals(0, mockEventLoop.lastOutgoing.getLength());
        assertEquals(Inet4Address.getByAddress(new byte[]{8, 8, 8, 8}), mockEventLoop.lastOutgoing.getAddress());

        assertNull(mockEventLoop.lastResponse);

        // Check the same thing with one upstream DNS server configured.
        tinySetUp();
        dnsPacketProxy.upstreamDnsServers.add(DnsUpstream.plain("1.1.1.2", 53,
                Inet4Address.getByAddress(new byte[]{1, 1, 1, 2})));
        dnsPacketProxy.handleDnsRequest(ipOutPacket.getRawData());

        assertNull(mockEventLoop.lastOutgoing);
        assertNull(mockEventLoop.lastResponse);

        // Check the same thing with enough upstream DNS servers configured.
        tinySetUp();
        for (byte i = 2; i < 9; i++)
            dnsPacketProxy.upstreamDnsServers.add(DnsUpstream.plain("1.1.1." + i, 53,
                    Inet4Address.getByAddress(new byte[]{1, 1, 1, i})));
        dnsPacketProxy.handleDnsRequest(ipOutPacket.getRawData());

        assertNotNull(mockEventLoop.lastOutgoing);
        assertEquals(0, mockEventLoop.lastOutgoing.getLength());
        assertEquals(Inet4Address.getByAddress(new byte[]{1, 1, 1, 8}), mockEventLoop.lastOutgoing.getAddress());
        assertNull(mockEventLoop.lastResponse);

    }

    @Test
    public void testDnsQuery() throws Exception {
        Message message = Message.newQuery(new ARecord(new Name("notblocked.example.com."),
                0x01,
                3600,
                Inet4Address.getByAddress(new byte[]{0, 0, 0, 0})
        ));

        UdpPacket.Builder payLoadBuilder = new UdpPacket.Builder()
                .srcPort(UdpPort.DOMAIN)
                .dstPort(UdpPort.DOMAIN)
                .srcAddr(InetAddress.getByAddress(new byte[]{8, 8, 4, 4}))
                .dstAddr(InetAddress.getByAddress(new byte[]{8, 8, 8, 8}))
                .correctChecksumAtBuild(true)
                .correctLengthAtBuild(true)
                .payloadBuilder(
                        new UnknownPacket.Builder()
                                .rawData(message.toWire())
                );

        IpPacket ipOutPacket = new IpV4Packet.Builder()
                .version(IpVersion.IPV4)
                .tos(IpV4Rfc791Tos.newInstance((byte) 0))
                .protocol(IpNumber.UDP)
                .srcAddr((Inet4Address) Inet4Address.getByAddress(new byte[]{8, 8, 4, 4}))
                .dstAddr((Inet4Address) Inet4Address.getByAddress(new byte[]{8, 8, 8, 8}))
                .correctChecksumAtBuild(true)
                .correctLengthAtBuild(true)
                .payloadBuilder(payLoadBuilder)
                .build();

        dnsPacketProxy.handleDnsRequest(ipOutPacket.getRawData());

        assertNull(mockEventLoop.lastResponse);
        assertNotNull(mockEventLoop.lastOutgoing);
        assertEquals(Inet4Address.getByAddress(new byte[]{8, 8, 8, 8}), mockEventLoop.lastOutgoing.getAddress());
    }

    @Test
    public void testNoQueryDnsQuery() throws Exception {
        Message message = new Message();

        UdpPacket.Builder payLoadBuilder = new UdpPacket.Builder()
                .srcPort(UdpPort.DOMAIN)
                .dstPort(UdpPort.DOMAIN)
                .srcAddr(InetAddress.getByAddress(new byte[]{8, 8, 4, 4}))
                .dstAddr(InetAddress.getByAddress(new byte[]{8, 8, 8, 8}))
                .correctChecksumAtBuild(true)
                .correctLengthAtBuild(true)
                .payloadBuilder(
                        new UnknownPacket.Builder()
                                .rawData(message.toWire())
                );

        IpPacket ipOutPacket = new IpV4Packet.Builder()
                .version(IpVersion.IPV4)
                .tos(IpV4Rfc791Tos.newInstance((byte) 0))
                .protocol(IpNumber.UDP)
                .srcAddr((Inet4Address) Inet4Address.getByAddress(new byte[]{8, 8, 4, 4}))
                .dstAddr((Inet4Address) Inet4Address.getByAddress(new byte[]{8, 8, 8, 8}))
                .correctChecksumAtBuild(true)
                .correctLengthAtBuild(true)
                .payloadBuilder(payLoadBuilder)
                .build();

        dnsPacketProxy.handleDnsRequest(ipOutPacket.getRawData());

        assertNull(mockEventLoop.lastResponse);
        assertNull(mockEventLoop.lastOutgoing);
        dnsPacketProxy.handleDnsRequest(ipOutPacket.getRawData());
    }

    @Test
    public void testBlockedDnsQuery() throws Exception {
        Message message = Message.newQuery(new ARecord(new Name("blocked.example.com."),
                0x01,
                3600,
                Inet4Address.getByAddress(new byte[]{0, 0, 0, 0})
        ));

        UdpPacket.Builder payLoadBuilder = new UdpPacket.Builder()
                .srcPort(UdpPort.DOMAIN)
                .dstPort(UdpPort.DOMAIN)
                .srcAddr(InetAddress.getByAddress(new byte[]{8, 8, 4, 4}))
                .dstAddr(InetAddress.getByAddress(new byte[]{8, 8, 8, 8}))
                .correctChecksumAtBuild(true)
                .correctLengthAtBuild(true)
                .payloadBuilder(
                        new UnknownPacket.Builder()
                                .rawData(message.toWire())
                );

        IpPacket ipOutPacket = new IpV4Packet.Builder()
                .version(IpVersion.IPV4)
                .tos(IpV4Rfc791Tos.newInstance((byte) 0))
                .protocol(IpNumber.UDP)
                .srcAddr((Inet4Address) Inet4Address.getByAddress(new byte[]{8, 8, 4, 4}))
                .dstAddr((Inet4Address) Inet4Address.getByAddress(new byte[]{8, 8, 8, 8}))
                .correctChecksumAtBuild(true)
                .correctLengthAtBuild(true)
                .payloadBuilder(payLoadBuilder)
                .build();

        dnsPacketProxy.handleDnsRequest(ipOutPacket.getRawData());

        assertNotNull(mockEventLoop.lastResponse);
        assertNull(mockEventLoop.lastOutgoing);
        assertTrue(mockEventLoop.lastResponse instanceof IpPacket);
        assertTrue(mockEventLoop.lastResponse.getPayload() instanceof UdpPacket);

        Message responseMsg = new Message(mockEventLoop.lastResponse.getPayload().getPayload().getRawData());
        assertEquals(NOERROR, responseMsg.getHeader().getRcode());
        assertArrayEquals(new Record[] {}, responseMsg.getSectionArray(Section.ANSWER));
        assertNotEquals(0, responseMsg.getSectionArray(Section.AUTHORITY).length);
        assertTrue(responseMsg.getSectionArray(Section.AUTHORITY)[0] instanceof SOARecord);
        assertTrue(responseMsg.getSectionArray(Section.AUTHORITY)[0].getTTL() > 0);
    }

    @Test
    public void testBlockedInet6DnsQuery() throws Exception {
        Message message = Message.newQuery(new ARecord(new Name("blocked.example.com."),
                0x01,
                3600,
                Inet4Address.getByAddress(new byte[]{0, 0, 0, 0})
        ));

        UdpPacket.Builder payLoadBuilder = new UdpPacket.Builder()
                .srcPort(UdpPort.DOMAIN)
                .dstPort(UdpPort.DOMAIN)
                .srcAddr((Inet6Address) Inet6Address.getByName("::0"))
                .dstAddr((Inet6Address) Inet6Address.getByName("::1"))
                .correctChecksumAtBuild(true)
                .correctLengthAtBuild(true)
                .payloadBuilder(
                        new UnknownPacket.Builder()
                                .rawData(message.toWire())
                );

        IpPacket ipOutPacket = new IpV6Packet.Builder()
                .version(IpVersion.IPV6)
                .trafficClass(IpV6SimpleTrafficClass.newInstance((byte) 0))
                .flowLabel(IpV6SimpleFlowLabel.newInstance(0))
                .nextHeader(IpNumber.UDP)
                .srcAddr((Inet6Address) Inet6Address.getByName("::0"))
                .dstAddr((Inet6Address) Inet6Address.getByName("::1"))
                .correctLengthAtBuild(true)
                .payloadBuilder(payLoadBuilder)
                .build();

        dnsPacketProxy.handleDnsRequest(ipOutPacket.getRawData());

        assertNotNull(mockEventLoop.lastResponse);
        assertNull(mockEventLoop.lastOutgoing);
        assertTrue(mockEventLoop.lastResponse instanceof IpPacket);
        assertTrue(mockEventLoop.lastResponse.getPayload() instanceof UdpPacket);

        Message responseMsg = new Message(mockEventLoop.lastResponse.getPayload().getPayload().getRawData());
        assertEquals(NOERROR, responseMsg.getHeader().getRcode());
        assertArrayEquals(new Record[] {}, responseMsg.getSectionArray(Section.ANSWER));
        assertNotEquals(0, responseMsg.getSectionArray(Section.AUTHORITY).length);
        assertTrue(responseMsg.getSectionArray(Section.AUTHORITY)[0] instanceof SOARecord);
        assertTrue(responseMsg.getSectionArray(Section.AUTHORITY)[0].getTTL() > 0);
    }

    // ------------------------------------------------------------------
    // Encrypted upstream (DoT/DoH) dispatch
    //
    // The secure resolution runs on a worker thread and replies through
    // queueDeviceWrite; a CountDownLatch on the mock event loop lets the
    // tests wait for that without sleeps. The proxies here override the
    // package-private secureUpstreamFor() seam with a mock pool - testing
    // the actual TLS exchange is the job of Dot/DohUpstreamTest.
    // ------------------------------------------------------------------

    /** Proxy whose "pool" is a mock; secureUpstreamFor is the injection seam. */
    private DnsPacketProxy proxyWithSecureUpstream(SecureUpstream secureUpstream) {
        DnsPacketProxy proxy = new DnsPacketProxy(mockEventLoop, ruleDatabase) {
            @Override
            SecureUpstream secureUpstreamFor(DnsUpstream upstream) {
                return secureUpstream;
            }
        };
        return proxy;
    }

    private static Message newQueryMessage(String name) throws Exception {
        return Message.newQuery(new ARecord(new Name(name),
                DClass.IN, 3600, Inet4Address.getByAddress(new byte[]{0, 0, 0, 0})));
    }

    /** A well-formed reply to the given query: same ID, QR, one A answer. */
    private static byte[] responseFor(Message query) throws Exception {
        Message response = new Message(query.getHeader().getID());
        response.getHeader().setFlag(Flags.QR);
        response.addRecord(query.getQuestion(), Section.QUESTION);
        response.addRecord(new ARecord(query.getQuestion().getName(), DClass.IN, 300,
                Inet4Address.getByAddress(new byte[]{(byte) 192, 0, 2, 99})), Section.ANSWER);
        return response.toWire();
    }

    /** IPv4 UDP/DNS packet destined to the given address and port. */
    private static IpPacket dnsQueryPacket(Message query, InetAddress dst, int dstPort) throws Exception {
        UdpPacket.Builder udpBuilder = new UdpPacket.Builder()
                .srcPort(UdpPort.DOMAIN)
                .dstPort(UdpPort.getInstance((short) dstPort))
                .srcAddr(InetAddress.getByAddress(new byte[]{8, 8, 4, 4}))
                .dstAddr(dst)
                .correctChecksumAtBuild(true)
                .correctLengthAtBuild(true)
                .payloadBuilder(new UnknownPacket.Builder().rawData(query.toWire()));

        return new IpV4Packet.Builder()
                .version(IpVersion.IPV4)
                .tos(IpV4Rfc791Tos.newInstance((byte) 0))
                .protocol(IpNumber.UDP)
                .srcAddr((Inet4Address) Inet4Address.getByAddress(new byte[]{8, 8, 4, 4}))
                .dstAddr((Inet4Address) dst)
                .correctChecksumAtBuild(true)
                .correctLengthAtBuild(true)
                .payloadBuilder(udpBuilder)
                .build();
    }

    private static Message deviceResponse(IpPacket responsePacket) throws Exception {
        return new Message(responsePacket.getPayload().getPayload().getRawData());
    }

    @Test
    public void testAllowedDnsQueryOverSecureUpstreamRepliesViaDevice() throws Exception {
        SecureUpstream secureUpstream = Mockito.mock(SecureUpstream.class);
        Mockito.when(secureUpstream.resolve(Mockito.any())).thenAnswer(invocation -> {
            // Round-trip through the wire format like a real server would
            Message query = new Message((byte[]) invocation.getArgument(0));
            return responseFor(query);
        });
        mockEventLoop.responseLatch = new CountDownLatch(1);
        DnsPacketProxy proxy = proxyWithSecureUpstream(secureUpstream);
        // Index 0: the alias address is 192.0.2.2 (last byte = index + 2)
        proxy.upstreamDnsServers.add(DnsUpstream.parse("https://doh.example.test/dns-query"));

        Message query = newQueryMessage("secure.example.com.");
        proxy.handleDnsRequest(dnsQueryPacket(query, Inet4Address.getByAddress(new byte[]{(byte) 192, 0, 2, 2}), 53).getRawData());

        assertTrue("No device write within 5s", mockEventLoop.responseLatch.await(5, TimeUnit.SECONDS));
        // Must not be relayed as a plain UDP packet...
        assertNull(mockEventLoop.lastOutgoing);
        // ...and the query the mock saw is the client's DNS payload
        Mockito.verify(secureUpstream).resolve(query.toWire());

        Message response = deviceResponse(mockEventLoop.lastResponse);
        assertEquals(query.getHeader().getID(), response.getHeader().getID());
        assertTrue(response.getHeader().getFlag(Flags.QR));
        assertEquals(1, response.getSectionArray(Section.ANSWER).length);
        proxy.shutdown();
    }

    @Test
    public void testSecureUpstreamFailureSendsServFail() throws Exception {
        SecureUpstream secureUpstream = Mockito.mock(SecureUpstream.class);
        Mockito.when(secureUpstream.resolve(Mockito.any())).thenAnswer(invocation -> {
            // Gotcha: the production failure path logs inside its catch
            // block, which runs on the executor thread - and MockedStatic
            // is thread-scoped, so the main thread's Log mock does not
            // apply there and the android.jar stub would throw. Register
            // a Log mock for this worker thread before failing.
            MockedStatic<Log> workerThreadLogMock = Mockito.mockStatic(Log.class);
            throw new IOException("upstream down");
        });
        mockEventLoop.responseLatch = new CountDownLatch(1);
        DnsPacketProxy proxy = proxyWithSecureUpstream(secureUpstream);
        proxy.upstreamDnsServers.add(DnsUpstream.parse("https://doh.example.test/dns-query"));

        Message query = newQueryMessage("secure.example.com.");
        proxy.handleDnsRequest(dnsQueryPacket(query, Inet4Address.getByAddress(new byte[]{(byte) 192, 0, 2, 2}), 53).getRawData());

        assertTrue("No device write within 5s", mockEventLoop.responseLatch.await(5, TimeUnit.SECONDS));
        assertNull(mockEventLoop.lastOutgoing);

        // The client gets a SERVFAIL for the original query, so it can
        // immediately fail over to its next configured server.
        Message response = deviceResponse(mockEventLoop.lastResponse);
        assertEquals(query.getHeader().getID(), response.getHeader().getID());
        assertTrue(response.getHeader().getFlag(Flags.QR));
        assertEquals(Rcode.SERVFAIL, response.getHeader().getRcode());
        proxy.shutdown();
    }

    @Test
    public void testSecureUpstreamWithoutPoolSendsServFail() throws Exception {
        // secureUpstreamFor returning null (e.g. a plain descriptor somehow
        // reaching the secure path) must not crash or hang: synchronous SERVFAIL.
        DnsPacketProxy proxy = proxyWithSecureUpstream(null);
        proxy.upstreamDnsServers.add(DnsUpstream.parse("https://doh.example.test/dns-query"));

        Message query = newQueryMessage("secure.example.com.");
        proxy.handleDnsRequest(dnsQueryPacket(query, Inet4Address.getByAddress(new byte[]{(byte) 192, 0, 2, 2}), 53).getRawData());

        assertNotNull(mockEventLoop.lastResponse);
        assertNull(mockEventLoop.lastOutgoing);
        Message response = deviceResponse(mockEventLoop.lastResponse);
        assertTrue(response.getHeader().getFlag(Flags.QR));
        assertEquals(Rcode.SERVFAIL, response.getHeader().getRcode());
    }

    @Test
    public void testPassthroughForwardsToPacketDestination() throws Exception {
        // No upstream rewriting configured: the query must go out to the
        // packet's own destination address and port (value unchanged).
        Message query = newQueryMessage("notblocked.example.com.");
        dnsPacketProxy.handleDnsRequest(
                dnsQueryPacket(query, Inet4Address.getByAddress(new byte[]{9, 9, 9, 9}), 5353).getRawData());

        assertNull(mockEventLoop.lastResponse);
        assertNotNull(mockEventLoop.lastOutgoing);
        assertEquals(Inet4Address.getByAddress(new byte[]{9, 9, 9, 9}), mockEventLoop.lastOutgoing.getAddress());
        assertEquals(5353, mockEventLoop.lastOutgoing.getPort());
        assertArrayEquals(query.toWire(),
                Arrays.copyOf(mockEventLoop.lastOutgoing.getData(), mockEventLoop.lastOutgoing.getLength()));
    }

    private static class MockEventLoop implements DnsPacketProxy.EventLoop {
        DatagramPacket lastOutgoing;
        IpPacket lastResponse;
        /** Set by tests waiting on the asynchronous secure-resolve path. */
        CountDownLatch responseLatch;

        @Override
        public void forwardPacket(DatagramPacket packet, IpPacket requestPacket) throws AdVpnThread.VpnNetworkException {
            lastOutgoing = packet;
        }

        @Override
        public void queueDeviceWrite(IpPacket packet) {
            lastResponse = packet;
            if (responseLatch != null)
                responseLatch.countDown();
        }
    }
}
