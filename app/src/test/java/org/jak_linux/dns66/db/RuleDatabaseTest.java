package org.jak_linux.dns66.db;

import android.content.Context;
import android.util.Log;

import org.jak_linux.dns66.Configuration;
import org.jak_linux.dns66.FileHelper;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import java.io.ByteArrayInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.io.StringReader;
import java.nio.CharBuffer;
import java.util.ArrayList;

import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.spy;

public class RuleDatabaseTest {

    private MockedStatic<Log> logMock;

    @Before
    public void setUp() {
        logMock = mockStatic(Log.class);
        // use Mockito to set up your expectation
        //Mockito.when(Log.d(param, msg)).thenReturn(0);
        //Mockito.when(Log.d(tag, msg, throwable)).thenReturn(0);
    }

    @After
    public void tearDown() {
        logMock.close();
    }

    @Test
    public void testGetInstance() throws Exception {
        RuleDatabase instance = RuleDatabase.getInstance();

        assertNotNull(instance);
        assertTrue(instance.isEmpty());
        assertFalse(instance.isBlocked("example.com"));
    }

    @Test
    public void testParseLine() throws Exception {
        // Standard format lines
        assertEquals("example.com", RuleDatabase.parseLine("0.0.0.0 example.com"));
        assertEquals("example.com", RuleDatabase.parseLine("127.0.0.1 example.com"));
        assertEquals("example.com", RuleDatabase.parseLine("::1 example.com"));
        assertEquals("example.com", RuleDatabase.parseLine("example.com"));
        // Comments
        assertEquals("example.com", RuleDatabase.parseLine("example.com # foo"));
        assertEquals("example.com", RuleDatabase.parseLine("0.0.0.0 example.com # foo"));
        assertEquals("example.com", RuleDatabase.parseLine("::1 example.com # foo"));
        // Check lower casing
        assertEquals("example.com", RuleDatabase.parseLine("example.cOm"));
        assertEquals("example.com", RuleDatabase.parseLine("127.0.0.1 example.cOm"));
        assertEquals("example.com", RuleDatabase.parseLine("::1 example.cOm"));
        // Space trimming
        assertNull(RuleDatabase.parseLine(" 127.0.0.1 example.com"));
        assertEquals("127.0.0.1.example.com", RuleDatabase.parseLine("127.0.0.1.example.com "));
        assertEquals("::1.example.com", RuleDatabase.parseLine("::1.example.com "));
        assertEquals("0.0.0.0.example.com", RuleDatabase.parseLine("0.0.0.0.example.com "));
        assertEquals("example.com", RuleDatabase.parseLine("127.0.0.1 example.com "));
        assertEquals("example.com", RuleDatabase.parseLine("127.0.0.1 example.com\t"));
        assertEquals("example.com", RuleDatabase.parseLine("127.0.0.1   example.com "));
        assertEquals("example.com", RuleDatabase.parseLine("127.0.0.1\t example.com "));
        assertEquals("example.com", RuleDatabase.parseLine("::1\t example.com "));
        // Space between values
        // Invalid lines
        assertNull(RuleDatabase.parseLine("127.0.0.1 "));
        assertNull(RuleDatabase.parseLine("127.0.0.1"));
        assertNull(RuleDatabase.parseLine("0.0.0.0"));
        assertNull(RuleDatabase.parseLine("0.0.0.0 "));
        assertNull(RuleDatabase.parseLine("::1 "));
        assertNull(RuleDatabase.parseLine("::1"));
        assertNull(RuleDatabase.parseLine("invalid example.com"));
        assertNull(RuleDatabase.parseLine("invalid\texample.com"));
        assertNull(RuleDatabase.parseLine("invalid long line"));
        assertNull(RuleDatabase.parseLine("# comment line"));
        assertNull(RuleDatabase.parseLine(""));
        assertNull(RuleDatabase.parseLine("\t"));
        assertNull(RuleDatabase.parseLine(" "));
    }

    @Test
    public void testLoadReader() throws Exception {
        RuleDatabase db = new RuleDatabase();
        db.nextBlockedHosts = db.blockedHosts.get();
        db.nextWildcardBlockedHosts = db.wildcardBlockedHosts.get();

        Configuration.Item item = new Configuration.Item();

        item.location = "<some random file>";
        item.state = Configuration.Item.STATE_IGNORE;

        // Ignore. Does nothing
        assertTrue(db.loadReader(item, new StringReader("example.com")));
        assertTrue(db.isEmpty());
        assertFalse(db.isBlocked("example.com"));

        // Deny, the host should be blocked now.
        item.state = Configuration.Item.STATE_DENY;
        assertTrue(db.loadReader(item, new StringReader("example.com")));
        assertFalse(db.isEmpty());
        assertTrue(db.isBlocked("example.com"));

        // Reallow again, the entry should disappear.
        item.state = Configuration.Item.STATE_ALLOW;
        assertTrue(db.loadReader(item, new StringReader("example.com")));
        assertTrue(db.isEmpty());
        assertFalse(db.isBlocked("example.com"));

        // Check multiple lines
        item.state = Configuration.Item.STATE_DENY;
        assertFalse(db.isBlocked("example.com"));
        assertFalse(db.isBlocked("foo.com"));
        assertTrue(db.loadReader(item, new StringReader("example.com\n127.0.0.1 foo.com")));
        assertFalse(db.isEmpty());
        assertTrue(db.isBlocked("example.com"));
        assertTrue(db.isBlocked("foo.com"));

        // Interrupted test
        Thread.currentThread().interrupt();
        try {
            db.loadReader(item, new StringReader("example.com"));
            fail("Interrupted thread did not cause reader to be interrupted");
        } catch (InterruptedException e) {

        }

        // Test with an invalid line before a valid one.
        item.state = Configuration.Item.STATE_DENY;
        assertTrue(db.loadReader(item, new StringReader("invalid line\notherhost.com")));
        assertTrue(db.isBlocked("otherhost.com"));

        // Allow again
        item.state = Configuration.Item.STATE_ALLOW;
        assertTrue(db.loadReader(item, new StringReader("invalid line\notherhost.com")));
        assertFalse(db.isBlocked("otherhost.com"));

        // Reader can't read, we are aborting.
        Reader reader = Mockito.mock(Reader.class);
        doThrow(new IOException()).when(reader).read((char[]) any());
        doThrow(new IOException()).when(reader).read((char[]) any(), anyInt(), anyInt());
        doThrow(new IOException()).when(reader).read(any(CharBuffer.class));

        assertFalse(db.loadReader(item, reader));
    }

    @Test
    public void testInitialize_host() throws Exception {
        RuleDatabase ruleDatabase = spy(new RuleDatabase());

        Configuration.Item item = new Configuration.Item();

        item.location = "ahost.com";
        item.state = Configuration.Item.STATE_DENY;

        Configuration configuration = new Configuration();
        configuration.hosts = new Configuration.Hosts();
        configuration.hosts.enabled = true;
        configuration.hosts.items = new ArrayList<>();
        configuration.hosts.items.add(item);

        Context context = mock(Context.class);
        try (MockedStatic<FileHelper> fileHelperMock = mockStatic(FileHelper.class)) {
            fileHelperMock.when(() -> FileHelper.loadCurrentSettings(context)).thenReturn(configuration);
            fileHelperMock.when(() -> FileHelper.openItemFile(context, item)).thenReturn(null);
            ruleDatabase.initialize(context);
        }

        assertTrue(ruleDatabase.isBlocked("ahost.com"));

        configuration.hosts.enabled = false;

        try (MockedStatic<FileHelper> fileHelperMock = mockStatic(FileHelper.class)) {
            fileHelperMock.when(() -> FileHelper.loadCurrentSettings(context)).thenReturn(configuration);
            fileHelperMock.when(() -> FileHelper.openItemFile(context, item)).thenReturn(null);
            ruleDatabase.initialize(context);
        }

        assertFalse(ruleDatabase.isBlocked("ahost.com"));
        assertTrue(ruleDatabase.isEmpty());
    }

    @Test
    public void testInitialize_disabled() throws Exception {
        RuleDatabase ruleDatabase = spy(new RuleDatabase());

        Configuration.Item item = new Configuration.Item();

        item.location = "ahost.com";
        item.state = Configuration.Item.STATE_DENY;

        Configuration configuration = new Configuration();
        configuration.hosts = new Configuration.Hosts();
        configuration.hosts.enabled = false;
        configuration.hosts.items = new ArrayList<>();
        configuration.hosts.items.add(item);

        Context context = mock(Context.class);
        try (MockedStatic<FileHelper> fileHelperMock = mockStatic(FileHelper.class)) {
            fileHelperMock.when(() -> FileHelper.loadCurrentSettings(context)).thenReturn(configuration);
            fileHelperMock.when(() -> FileHelper.openItemFile(context, item)).thenReturn(null);
            ruleDatabase.initialize(context);
        }

        assertFalse(ruleDatabase.isBlocked("ahost.com"));
        assertTrue(ruleDatabase.isEmpty());
    }

    @Test
    public void testInitialize_file() throws Exception {
        RuleDatabase ruleDatabase = spy(new RuleDatabase());

        Configuration.Item item = new Configuration.Item();

        item.location = "protocol://some-weird-file-uri";
        item.state = Configuration.Item.STATE_DENY;

        Configuration configuration = new Configuration();
        configuration.hosts = new Configuration.Hosts();
        configuration.hosts.enabled = true;
        configuration.hosts.items = new ArrayList<>();
        configuration.hosts.items.add(item);

        Context context = mock(Context.class);
        try (MockedStatic<FileHelper> fileHelperMock = mockStatic(FileHelper.class)) {
            fileHelperMock.when(() -> FileHelper.loadCurrentSettings(context)).thenReturn(configuration);
            fileHelperMock.when(() -> FileHelper.openItemFile(context, item)).thenReturn(new InputStreamReader(new ByteArrayInputStream("example.com".getBytes("utf-8"))));
            ruleDatabase.initialize(context);
        }

        assertTrue(ruleDatabase.isBlocked("example.com"));

        item.state = Configuration.Item.STATE_IGNORE;

        try (MockedStatic<FileHelper> fileHelperMock = mockStatic(FileHelper.class)) {
            fileHelperMock.when(() -> FileHelper.loadCurrentSettings(context)).thenReturn(configuration);
            fileHelperMock.when(() -> FileHelper.openItemFile(context, item)).thenReturn(new InputStreamReader(new ByteArrayInputStream("example.com".getBytes("utf-8"))));
            ruleDatabase.initialize(context);
        }

        assertTrue(ruleDatabase.isEmpty());

    }

    @Test
    public void testInitialize_fileNotFound() throws Exception {
        RuleDatabase ruleDatabase = spy(new RuleDatabase());

        Configuration.Item item = new Configuration.Item();

        item.location = "protocol://some-weird-file-uri";
        item.state = Configuration.Item.STATE_DENY;

        Configuration configuration = new Configuration();
        configuration.hosts = new Configuration.Hosts();
        configuration.hosts.enabled = true;
        configuration.hosts.items = new ArrayList<>();
        configuration.hosts.items.add(item);

        Context context = mock(Context.class);
        try (MockedStatic<FileHelper> fileHelperMock = mockStatic(FileHelper.class)) {
            fileHelperMock.when(() -> FileHelper.loadCurrentSettings(context)).thenReturn(configuration);
            fileHelperMock.when(() -> FileHelper.openItemFile(context, item)).thenThrow(new FileNotFoundException("foobar"));
            ruleDatabase.initialize(context);
        }
        assertTrue(ruleDatabase.isEmpty());
    }

    public static class FooException extends RuntimeException {
    }

    @Test
    public void testWildcardMatching() throws Exception {
        RuleDatabase db = new RuleDatabase();
        db.nextBlockedHosts = db.blockedHosts.get();
        db.nextWildcardBlockedHosts = db.wildcardBlockedHosts.get();

        Configuration.Item item = new Configuration.Item();
        item.location = "wildcard-list";
        item.state = Configuration.Item.STATE_DENY;

        // Bare-domain (wildcard) list: entry and all subdomains block
        assertTrue(db.loadReader(item, new StringReader("example.com\nother.example.com")));
        assertTrue(db.isBlocked("example.com"));
        assertTrue(db.isBlocked("sub.example.com"));
        assertTrue(db.isBlocked("a.b.example.com"));
        assertTrue(db.isBlocked("other.example.com"));
        assertTrue(db.isBlocked("deep.other.example.com"));
        // Unrelated domains stay unblocked
        assertFalse(db.isBlocked("notexample.com"));
        assertFalse(db.isBlocked("example.org"));

        // Hosts-file entry only blocks exactly what it names
        assertTrue(db.loadReader(item, new StringReader("0.0.0.0 exact.example.net")));
        assertTrue(db.isBlocked("exact.example.net"));
        assertFalse(db.isBlocked("sub.exact.example.net"));
    }

    @Test
    public void testWildcardAllowRemoval() throws Exception {
        RuleDatabase db = new RuleDatabase();
        db.nextBlockedHosts = db.blockedHosts.get();
        db.nextWildcardBlockedHosts = db.wildcardBlockedHosts.get();

        Configuration.Item deny = new Configuration.Item();
        deny.location = "wildcard-list";
        deny.state = Configuration.Item.STATE_DENY;
        assertTrue(db.loadReader(deny, new StringReader("example.com")));
        assertTrue(db.isBlocked("sub.example.com"));

        // An allowlist entry removes the wildcard entry entirely
        Configuration.Item allow = new Configuration.Item();
        allow.location = "allow-list";
        allow.state = Configuration.Item.STATE_ALLOW;
        assertTrue(db.loadReader(allow, new StringReader("example.com")));
        assertFalse(db.isBlocked("example.com"));
        assertFalse(db.isBlocked("sub.example.com"));
    }

    @Test
    public void testParseLineWildcardMarker() {
        assertEquals("example.com", RuleDatabase.parseLine("*.example.com"));
        assertEquals("example.com", RuleDatabase.parseLine("0.0.0.0 *.example.com"));
        assertNull(RuleDatabase.parseLine("*."));
    }

    @Test
    public void testHasHostsFilePrefix() {
        assertTrue(RuleDatabase.hasHostsFilePrefix("0.0.0.0 example.com"));
        assertTrue(RuleDatabase.hasHostsFilePrefix("127.0.0.1 example.com"));
        assertTrue(RuleDatabase.hasHostsFilePrefix("::1 example.com"));
        assertFalse(RuleDatabase.hasHostsFilePrefix("example.com"));
        assertFalse(RuleDatabase.hasHostsFilePrefix("0.0.0.0.example.com"));
    }

    @Test
    public void testManualEntries() throws Exception {
        RuleDatabase db = new RuleDatabase();
        db.nextBlockedHosts = db.blockedHosts.get();
        db.nextWildcardBlockedHosts = db.wildcardBlockedHosts.get();
        db.nextRegexPatterns = db.regexPatterns.get();

        // Exact manual entry: only the host itself
        Configuration.Item exact = new Configuration.Item();
        exact.location = "exact.example.com";
        exact.state = Configuration.Item.STATE_DENY;
        db.loadItem(null, exact);
        assertTrue(db.isBlocked("exact.example.com"));
        assertFalse(db.isBlocked("sub.exact.example.com"));

        // Wildcard manual entry: the domain and all subdomains
        Configuration.Item wildcard = new Configuration.Item();
        wildcard.location = "*.wild.example.org";
        wildcard.state = Configuration.Item.STATE_DENY;
        db.loadItem(null, wildcard);
        assertTrue(db.isBlocked("wild.example.org"));
        assertTrue(db.isBlocked("any.wild.example.org"));
        assertFalse(db.isBlocked("notwild.example.org"));

        // Regex manual entry: matched against the lower-case host
        Configuration.Item regex = new Configuration.Item();
        regex.location = "regex:^ads[0-9]+\\.tracker\\.example$";
        regex.state = Configuration.Item.STATE_DENY;
        db.loadItem(null, regex);
        assertTrue(db.isBlocked("ads123.tracker.example"));
        assertFalse(db.isBlocked("ads.tracker.example"));
        assertFalse(db.isBlocked("xads123.tracker.example"));

        // Invalid regex is skipped without breaking the load
        Configuration.Item badRegex = new Configuration.Item();
        badRegex.location = "regex:^unclosed[";
        badRegex.state = Configuration.Item.STATE_DENY;
        db.loadItem(null, badRegex);
        assertFalse(db.isBlocked("unclosedx"));

        // An allow entry removes a regex by identical pattern text
        Configuration.Item allowRegex = new Configuration.Item();
        allowRegex.location = "regex:^ads[0-9]+\\.tracker\\.example$";
        allowRegex.state = Configuration.Item.STATE_ALLOW;
        db.loadItem(null, allowRegex);
        assertFalse(db.isBlocked("ads123.tracker.example"));

        assertFalse(db.isEmpty());
    }
}
