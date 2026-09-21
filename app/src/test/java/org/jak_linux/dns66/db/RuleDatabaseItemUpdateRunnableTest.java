package org.jak_linux.dns66.db;

import android.content.ContentResolver;
import android.content.Context;
import android.content.res.Resources;
import android.net.Uri;
import android.util.Log;

import org.jak_linux.dns66.Configuration;
import org.jak_linux.dns66.SingleWriterMultipleReaderFile;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockito.MockedStatic;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.ArrayList;

import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doCallRealMethod;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

public class RuleDatabaseItemUpdateRunnableTest {
    private Context mockContext;
    private File file;
    private SingleWriterMultipleReaderFile singleWriterMultipleReaderFile;
    private HttpURLConnection connection;
    private CountingAnswer finishAnswer;
    private CountingAnswer failAnswer;
    private URL url;
    private RuleDatabaseUpdateTask realTask;
    private RuleDatabaseUpdateTask mockTask;
    private ContentResolver mockResolver;
    private MockedStatic<Log> logMock;

    @Before
    public void setUp() {
        logMock = mockStatic(Log.class);

        mockContext = mock(Context.class);
        file = mock(File.class);
        singleWriterMultipleReaderFile = mock(SingleWriterMultipleReaderFile.class);
        connection = mock(HttpURLConnection.class);
        finishAnswer = new CountingAnswer(null);
        failAnswer = new CountingAnswer(null);
        realTask = new RuleDatabaseUpdateTask(mockContext, null, false);
        mockTask = mock(RuleDatabaseUpdateTask.class);
        url = mock(URL.class);
        mockResolver = mock(ContentResolver.class);
        try {
            when(url.openConnection()).thenReturn(connection);
            when(mockContext.getContentResolver()).thenReturn(mockResolver);
            doAnswer(finishAnswer).when(singleWriterMultipleReaderFile).finishWrite(any(FileOutputStream.class));
            doAnswer(failAnswer).when(singleWriterMultipleReaderFile).failWrite(any(FileOutputStream.class));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @After
    public void tearDown() {
        logMock.close();
    }

    @Test
    public void testRun() throws Exception {
        CountingAnswer downloadCount = new CountingAnswer(null);
        when(mockTask.doInBackground()).thenCallRealMethod();

        mockTask.context = mockContext;
        mockTask.errors = new ArrayList<>();
        mockTask.done = new ArrayList<>();
        mockTask.pending = new ArrayList<>();
        mockTask.configuration = new Configuration();
        mockTask.configuration.hosts = new Configuration.Hosts();
        mockTask.configuration.hosts.items.add(new Configuration.Item());
        mockTask.configuration.hosts.items.add(new Configuration.Item());
        mockTask.configuration.hosts.items.add(new Configuration.Item());
        mockTask.configuration.hosts.items.add(new Configuration.Item());
        mockTask.configuration.hosts.items.get(0).title = "http-title";
        mockTask.configuration.hosts.items.get(0).state = Configuration.Item.STATE_DENY;
        mockTask.configuration.hosts.items.get(0).location = "http://foo";

        // any() for the message, not anyString(): mocked Context.getString()
        // returns null and anyString() does not match null in Mockito 2+.
        doCallRealMethod().when(mockTask).addError(any(Configuration.Item.class), any());
        doCallRealMethod().when(mockTask).addDone(any(Configuration.Item.class));

        RuleDatabaseItemUpdateRunnable itemUpdateRunnable = mock(RuleDatabaseItemUpdateRunnable.class);
        itemUpdateRunnable.parentTask = mockTask;
        itemUpdateRunnable.context = mockContext;
        itemUpdateRunnable.item = mockTask.configuration.hosts.items.get(0);

        doCallRealMethod().when(itemUpdateRunnable).run();
        when(itemUpdateRunnable.shouldDownload()).thenCallRealMethod();
        when(mockTask.getCommand(any(Configuration.Item.class))).thenReturn(itemUpdateRunnable);
        doAnswer(downloadCount).when(itemUpdateRunnable).downloadFile(any(File.class), any(SingleWriterMultipleReaderFile.class), any(HttpURLConnection.class));


        // Scenario 1: Validate response fails
        assertTrue(itemUpdateRunnable.shouldDownload());
        itemUpdateRunnable.run();
        assertEquals(0, downloadCount.numCalls);
        assertEquals(1, mockTask.done.size());

        // Scenario 2: Validate response succeeds
        when(itemUpdateRunnable.validateResponse(any(HttpURLConnection.class))).thenReturn(true);
        when(itemUpdateRunnable.getHttpURLConnection(any(File.class), any(SingleWriterMultipleReaderFile.class), any(URL.class))).thenCallRealMethod();
        when(itemUpdateRunnable.internalOpenHttpConnection(any(URL.class))).thenReturn(connection);
        assertTrue(itemUpdateRunnable.shouldDownload());
        itemUpdateRunnable.run();
        assertEquals(1, downloadCount.numCalls);
        assertEquals(2, mockTask.done.size());

        // Scenario 3: Download file throws an exception
        CountingAnswer downloadExceptionCount = new CountingAnswer(null) {
            @Override
            public Object answer(InvocationOnMock invocation) throws Throwable {
                super.answer(invocation);
                throw new IOException("FooBarException");
            }
        };
        doAnswer(downloadExceptionCount).when(itemUpdateRunnable).downloadFile(any(File.class), any(SingleWriterMultipleReaderFile.class), any(HttpURLConnection.class));
        assertTrue(itemUpdateRunnable.shouldDownload());
        itemUpdateRunnable.run();
        assertEquals(1, downloadExceptionCount.numCalls);
        assertEquals(1, mockTask.errors.size());
        assertEquals(3, mockTask.done.size());
        assertTrue("http-title in" + mockTask.errors.get(0), mockTask.errors.get(0).matches(".*http-title.*"));
    }

    @Test
    public void testRun_content() throws Exception {
        Configuration.Item item = new Configuration.Item();
        item.location = "content://foo";
        item.title = "content-uri";

        RuleDatabaseItemUpdateRunnable itemUpdateRunnable = mock(RuleDatabaseItemUpdateRunnable.class);
        itemUpdateRunnable.parentTask = realTask;
        itemUpdateRunnable.context = mockContext;
        itemUpdateRunnable.item = item;

        doCallRealMethod().when(itemUpdateRunnable).run();
        when(itemUpdateRunnable.shouldDownload()).thenCallRealMethod();
        when(itemUpdateRunnable.parseUri(anyString())).thenReturn(mock(Uri.class));
        CountingAnswer downloadCount = new CountingAnswer(null);
        doAnswer(downloadCount).when(itemUpdateRunnable).downloadFile(any(File.class), any(SingleWriterMultipleReaderFile.class), any(HttpURLConnection.class));
        when(mockResolver.openInputStream(any(Uri.class))).thenReturn(mock(InputStream.class));

        assertTrue(itemUpdateRunnable.shouldDownload());
        itemUpdateRunnable.run();

        assertEquals(0, downloadCount.numCalls);
        assertEquals(0, realTask.errors.size());
        assertEquals(0, realTask.done.size());
        assertEquals(0, realTask.pending.size());

        doThrow(new SecurityException("FooBar")).when(mockResolver).takePersistableUriPermission(any(Uri.class), anyInt());

        itemUpdateRunnable.run();

        assertEquals(0, downloadCount.numCalls);
        assertEquals(1, realTask.errors.size());
        assertEquals(0, realTask.done.size());
        assertEquals(0, realTask.pending.size());
    }

    @Test
    public void testShouldDownload() throws Exception {
        Configuration.Item item = new Configuration.Item();
        item.state = Configuration.Item.STATE_DENY;
        item.location = "example.com";
        item.title = "host-uri";

        RuleDatabaseItemUpdateRunnable itemUpdateRunnable = new RuleDatabaseItemUpdateRunnable(mockTask, mockContext, item);

        // File should not be downloaded
        assertFalse(itemUpdateRunnable.shouldDownload());

        // Content URI should
        item.location = "content://foo";
        assertTrue(itemUpdateRunnable.shouldDownload());

        // Do not download ignored URIs
        item.state = Configuration.Item.STATE_IGNORE;
        assertFalse(itemUpdateRunnable.shouldDownload());
        item.state = Configuration.Item.STATE_DENY;

        item.location = "https://foo";
        assertTrue(itemUpdateRunnable.shouldDownload());

        item.location = "http://foo";
        assertTrue(itemUpdateRunnable.shouldDownload());
    }

    @Test
    public void testValidateResponse() throws Exception {
        RuleDatabaseItemUpdateRunnable itemUpdateRunnable = new RuleDatabaseItemUpdateRunnable(realTask, mockContext, mock(Configuration.Item.class));

        Resources resources = mock(Resources.class);
        when(mockContext.getResources()).thenReturn(resources);
        when(resources.getString(anyInt(), anyString(), anyInt(), anyString())).thenReturn("%s %s %s");

        when(connection.getResponseCode()).thenReturn(200);
        assertTrue("200 is OK", itemUpdateRunnable.validateResponse(connection));
        assertEquals(0, realTask.errors.size());

        when(connection.getResponseCode()).thenReturn(404);
        assertFalse("404 is not OK", itemUpdateRunnable.validateResponse(connection));
        assertEquals(1, realTask.errors.size());

        when(connection.getResponseCode()).thenReturn(304);
        assertFalse("304 is not OK", itemUpdateRunnable.validateResponse(connection));
        assertEquals(1, realTask.errors.size());
    }

    @Test
    public void testDownloadFile() throws Exception {
        RuleDatabaseItemUpdateRunnable itemUpdateRunnable = new RuleDatabaseItemUpdateRunnable(realTask, mockContext, mock(Configuration.Item.class));

        byte[] bar = new byte[]{'h', 'a', 'l', 'l', 'o'};
        final ByteArrayInputStream bis = new ByteArrayInputStream(bar);
        final ByteArrayOutputStream bos = new ByteArrayOutputStream();

        FileOutputStream fos = mock(FileOutputStream.class);
        doAnswer(new Answer<Void>() {
            @Override
            public Void answer(InvocationOnMock invocation) throws Throwable {
                byte[] buffer = invocation.getArgument(0);
                int off = invocation.getArgument(1);
                int len = invocation.getArgument(2);

                bos.write(buffer, off, len);
                return null;
            }
        }).when(fos).write(any(byte[].class), anyInt(), anyInt());

        when(connection.getInputStream()).thenReturn(bis);
        when(singleWriterMultipleReaderFile.startWrite()).thenReturn(fos);
        itemUpdateRunnable.downloadFile(file, singleWriterMultipleReaderFile, connection);

        assertArrayEquals(bar, bos.toByteArray());
        assertEquals(0, failAnswer.numCalls);
        assertEquals(1, finishAnswer.numCalls);
        bis.reset();
        bos.reset();

    }

    @Test
    public void testDownloadFile_exception() throws Exception {
        RuleDatabaseItemUpdateRunnable itemUpdateRunnable = new RuleDatabaseItemUpdateRunnable(realTask, mockContext, mock(Configuration.Item.class));
        FileOutputStream fos = mock(FileOutputStream.class);
        InputStream is = mock(InputStream.class);

        when(connection.getInputStream()).thenReturn(is);
        when(singleWriterMultipleReaderFile.startWrite()).thenReturn(fos);

        doThrow(new IOException("foobar")).when(fos).write(any(byte[].class), anyInt(), anyInt());
        try {
            itemUpdateRunnable.downloadFile(file, singleWriterMultipleReaderFile, connection);
            fail("Should have thrown exception");
        } catch (IOException e) {
            assertEquals("foobar", e.getMessage());
            assertEquals(1, failAnswer.numCalls);
            assertEquals(0, finishAnswer.numCalls);
        }
    }

    @Test
    public void testDownloadFile_lastModifiedFail() throws Exception {
        CountingAnswer debugAnswer = new CountingAnswer(null);
        CountingAnswer setLastModifiedAnswerTrue = new CountingAnswer(true);
        CountingAnswer setLastModifiedAnswerFalse = new CountingAnswer(false);
        RuleDatabaseItemUpdateRunnable itemUpdateRunnable = new RuleDatabaseItemUpdateRunnable(realTask, mockContext, mock(Configuration.Item.class));
        FileOutputStream fos = mock(FileOutputStream.class);
        InputStream is = mock(InputStream.class);

        when(connection.getInputStream()).thenReturn(is);
        when(singleWriterMultipleReaderFile.startWrite()).thenReturn(fos);
        when(is.read(any(byte[].class))).thenReturn(-1);
        logMock.when(() -> Log.d(anyString(), anyString())).thenAnswer(debugAnswer);

        // Scenario 0: Connection has no last modified & we cannot set (0, 0)
        when(connection.getLastModified()).thenReturn(0L);
        when(file.setLastModified(anyLong())).thenAnswer(setLastModifiedAnswerFalse);

        itemUpdateRunnable.downloadFile(file, singleWriterMultipleReaderFile, connection);

        assertEquals(0, failAnswer.numCalls);
        assertEquals(1, debugAnswer.numCalls);
        assertEquals(1, finishAnswer.numCalls);

        // Scenario 1: Connect has no last modified & we can set (0, 1);
        when(connection.getLastModified()).thenReturn(0L);
        when(file.setLastModified(anyLong())).thenAnswer(setLastModifiedAnswerTrue);

        itemUpdateRunnable.downloadFile(file, singleWriterMultipleReaderFile, connection);

        assertEquals(0, failAnswer.numCalls);
        assertEquals(2, debugAnswer.numCalls);
        assertEquals(2, finishAnswer.numCalls);

        // Scenario 2: Connect has last modified & we cannot set (1, 0);
        when(connection.getLastModified()).thenReturn(1L);
        when(file.setLastModified(anyLong())).thenAnswer(setLastModifiedAnswerFalse);

        itemUpdateRunnable.downloadFile(file, singleWriterMultipleReaderFile, connection);

        assertEquals(0, failAnswer.numCalls);
        assertEquals(3, debugAnswer.numCalls);
        assertEquals(3, finishAnswer.numCalls);

        // Scenario 4: Connect has last modified & we cannot set (1, 1);
        when(connection.getLastModified()).thenReturn(1L);
        when(file.setLastModified(anyLong())).thenAnswer(setLastModifiedAnswerTrue);

        itemUpdateRunnable.downloadFile(file, singleWriterMultipleReaderFile, connection);

        assertEquals(0, failAnswer.numCalls);
        assertEquals(3, debugAnswer.numCalls); // as before
        assertEquals(4, finishAnswer.numCalls);
    }

    @Test
    public void testCopyStream() throws Exception {
        RuleDatabaseItemUpdateRunnable itemUpdateRunnable = new RuleDatabaseItemUpdateRunnable(realTask, mockContext, mock(Configuration.Item.class));

        byte[] bar = new byte[]{'h', 'a', 'l', 'l', 'o'};
        ByteArrayInputStream bis = new ByteArrayInputStream(bar);
        ByteArrayOutputStream bos = new ByteArrayOutputStream();

        itemUpdateRunnable.copyStream(bis, bos);
        assertArrayEquals(bar, bos.toByteArray());
    }

    @Test
    public void testGetHttpURLConnection() throws Exception {
        RuleDatabaseItemUpdateRunnable itemUpdateRunnable = mock(RuleDatabaseItemUpdateRunnable.class);

        when(itemUpdateRunnable.getHttpURLConnection(any(File.class), any(SingleWriterMultipleReaderFile.class), any(URL.class))).thenCallRealMethod();
        when(itemUpdateRunnable.internalOpenHttpConnection(any(URL.class))).thenReturn(connection);

        when(singleWriterMultipleReaderFile.openRead()).thenReturn(mock(FileInputStream.class));

        assertSame(connection, itemUpdateRunnable.getHttpURLConnection(file, singleWriterMultipleReaderFile, url));

        // Setting modified.
        CountingAnswer setIfModifiedAnswer = new CountingAnswer(null);
        when(file.lastModified()).thenReturn(42L);
        doAnswer(setIfModifiedAnswer).when(connection).setIfModifiedSince(42L);

        assertSame(connection, itemUpdateRunnable.getHttpURLConnection(file, singleWriterMultipleReaderFile, url));
        assertEquals(1, setIfModifiedAnswer.numCalls);

        // If we do not have a last modified value, do not set if-modified-since.
        setIfModifiedAnswer.numCalls = 0;
        when(file.lastModified()).thenReturn(0L);

        assertSame(connection, itemUpdateRunnable.getHttpURLConnection(file, singleWriterMultipleReaderFile, url));
        assertEquals(0, setIfModifiedAnswer.numCalls);
    }

    private class CountingAnswer implements Answer<Object> {

        private final Object result;
        private int numCalls;

        CountingAnswer(Object result) {
            this.result = result;
            this.numCalls = 0;
        }

        @Override
        public Object answer(InvocationOnMock invocation) throws Throwable {
            numCalls++;
            // Log.d returns int while the other stubbed methods are void or
            // boolean; Mockito cannot translate a null answer to a primitive,
            // so fall back to 0 when no result was given.
            return result != null ? result : 0;
        }
    }

}
