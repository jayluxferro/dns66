package org.jak_linux.dns66;

import android.content.Context;
import android.content.res.AssetManager;
import android.os.Environment;
import android.system.ErrnoException;
import android.system.Os;
import android.system.OsConstants;
import android.util.Log;

import org.junit.After;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;

import java.io.Closeable;
import java.io.File;
import java.io.FileDescriptor;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.Reader;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.Field;

import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

/**
 * Created by jak on 07/04/17.
 */
public class FileHelperTest {
    Context mockContext;
    AssetManager mockAssets;
    int testResult;

    private MockedStatic<Log> logMock;
    private MockedStatic<Os> osMock;

    @Before
    public void setUp() {
        mockContext = mock(Context.class);
        mockAssets = mock(AssetManager.class);
        testResult = 0;

        logMock = mockStatic(Log.class);
        osMock = mockStatic(Os.class);

        when(mockContext.getAssets()).thenReturn(mockAssets);
    }

    @After
    public void tearDown() {
        logMock.close();
        osMock.close();
    }

    @Test
    public void testGetItemFile() throws Exception {
        File file = new File("/dir/");
        when(mockContext.getExternalFilesDir(null)).thenReturn(file);

        Configuration.Item item = new Configuration.Item();
        item.location = "http://example.com/";
        assertEquals(new File("/dir/http%3A%2F%2Fexample.com%2F"), FileHelper.getItemFile(mockContext, item));

        item.location = "https://example.com/";
        assertEquals(new File("/dir/https%3A%2F%2Fexample.com%2F"), FileHelper.getItemFile(mockContext, item));

        item.location = "file:/myfile";
        assertNull(FileHelper.getItemFile(mockContext, item));

        try (MockedStatic<Environment> environmentMock = mockStatic(Environment.class)) {
            environmentMock.when(Environment::getExternalStorageDirectory).thenReturn(new File("/sdcard/"));

            item.location = "file:myfile";
            assertNull(null, FileHelper.getItemFile(mockContext, item));

            item.location = "ahost.com";
            assertNull(FileHelper.getItemFile(mockContext, item));
        }
    }

    @Test
    @Ignore("The exception throwing does not work")
    public void testGetItemFile_encodingError() throws Exception {
        File file = new File("/dir/");
        when(mockContext.getExternalFilesDir(null)).thenReturn(file);

        Configuration.Item item = new Configuration.Item();
        // Test encoding fails
        item.location = "https://example.com/";
        assertEquals(new File("/dir/https%3A%2F%2Fexample.com%2F"), FileHelper.getItemFile(mockContext, item));

        // TODO: The following code prints the exception, but does not fail
        // (same behavior as before the Mockito migration; the test stays @Ignore'd).
        try (MockedStatic<java.net.URLEncoder> urlEncoderMock = mockStatic(java.net.URLEncoder.class)) {
            urlEncoderMock.when(() -> java.net.URLEncoder.encode(anyString(), anyString())).thenThrow(new UnsupportedEncodingException("foo"));
            assertNull(FileHelper.getItemFile(mockContext, item));
        }
    }

    @Test
    public void testOpenItemFile() throws Exception {
        Configuration.Item item = new Configuration.Item();
        // Test encoding fails
        item.location = "hexample.com";
        assertNull(FileHelper.openItemFile(mockContext, item));
    }

    @Test
    public void testOpenRead_existingFile() throws Exception {
        FileInputStream stream = mock(FileInputStream.class);
        when(mockContext.openFileInput(anyString())).thenReturn(stream);
        when(mockAssets.open(anyString())).thenThrow(new IOException());

        assertSame(stream, FileHelper.openRead(mockContext, "file"));
    }

    @Test
    public void testOpenRead_fallbackToAsset() throws Exception {
        FileInputStream stream = mock(FileInputStream.class);
        when(mockContext.openFileInput(anyString())).thenThrow(new FileNotFoundException("Test"));
        when(mockAssets.open(anyString())).thenReturn(stream);

        assertSame(stream, FileHelper.openRead(mockContext, "file"));
    }

    @Test
    public void testOpenWrite() throws Exception {
        File file = mock(File.class);
        File file2 = mock(File.class);
        FileOutputStream fos = mock(FileOutputStream.class);
        when(mockContext.getFileStreamPath(eq("filename"))).thenReturn(file);
        when(mockContext.getFileStreamPath(eq("filename.bak"))).thenReturn(file2);
        when(mockContext.openFileOutput(eq("filename"), anyInt())).thenReturn(fos);

        assertSame(fos, FileHelper.openWrite(mockContext, "filename"));

        Mockito.verify(file).renameTo(file2);
        Mockito.verify(mockContext).openFileOutput(eq("filename"), anyInt());
    }

    @Test
    public void testLoadDefaultSettings() throws Exception {
        InputStream mockInStream = mock(InputStream.class);
        Configuration mockConfig = mock(Configuration.class);
        when(mockAssets.open(anyString())).thenReturn(mockInStream);
        when(mockContext.getAssets()).thenReturn(mockAssets);

        try (MockedStatic<Configuration> configurationMock = mockStatic(Configuration.class)) {
            configurationMock.when(() -> Configuration.read(any(Reader.class))).thenReturn(mockConfig);

            assertSame(mockConfig, FileHelper.loadDefaultSettings(mockContext));
        }

        Mockito.verify(mockAssets).open(anyString());
    }

    @Test
    public void testPoll_retryInterrupt() throws Exception {
        // any() rather than any(StructPollfd[].class): the test passes null fds
        // and any(Class) does not match null in Mockito 2+.
        osMock.when(() -> Os.poll(any(), anyInt())).thenAnswer(new Answer<Integer>() {
            @Override
            public Integer answer(InvocationOnMock invocation) throws Throwable {
                // First try fails with EINTR, seconds returns success.
                if (testResult++ == 0) {
                    // Android actually sets all OsConstants to 0 when running the
                    // unit tests, so this works, but another constant would have
                    // exactly the same result.
                    throw new ErrnoException("poll", OsConstants.EINTR);
                }
                return 0;
            }
        });

        // poll() will be interrupted first time, so called a second time.
        assertEquals(0, FileHelper.poll(null, 0));
        assertEquals(2, testResult);
    }

    @Test
    public void testPoll_interrupted() throws Exception {
        Thread.currentThread().interrupt();
        try {
            FileHelper.poll(null, 0);
            fail("Did not interrupt");
        } catch (InterruptedException e) {

        }
    }

    @Test
    public void testPoll_fault() throws Exception {
        // Eww, Android is playing dirty and setting all errno values to 0.
        // Hack around it so we can test that aborting the loop works.
        final ErrnoException e = new ErrnoException("foo", 42);
        // errno is final, so setAccessible is needed for the write to stick.
        Field errno = e.getClass().getDeclaredField("errno");
        errno.setAccessible(true);
        errno.setInt(e, 42);
        osMock.when(() -> Os.poll(any(), anyInt())).thenAnswer(new Answer<Integer>() {
            @Override
            public Integer answer(InvocationOnMock invocation) throws Throwable {
                testResult++;
                throw e;
            }
        });

        try {
            FileHelper.poll(null, 0);
            fail("Did not throw");
        } catch (ErrnoException e1) {
            assertEquals(42, e1.errno);
            assertSame(e, e1);
        }
        assertEquals(1, testResult);
    }

    @Test
    public void testPoll_success() throws Exception {
        osMock.when(() -> Os.poll(any(), anyInt())).thenAnswer(new CountingAnswer(42));
        assertEquals(42, FileHelper.poll(null, 0));
        assertEquals(1, testResult);
    }


    @Test
    public void testCloseOrWarn_fileDescriptor() throws Exception {
        FileDescriptor fd = mock(FileDescriptor.class);
        logMock.when(() -> Log.e(anyString(), anyString(), any(Throwable.class))).thenAnswer(new CountingAnswer(null));

        // Closing null should work just fine
        testResult = 0;
        assertNull(FileHelper.closeOrWarn((FileDescriptor) null, "tag", "msg"));
        assertEquals(0, testResult);

        // Successfully closing the file should not log.
        testResult = 0;
        assertNull(FileHelper.closeOrWarn(fd, "tag", "msg"));
        assertEquals(0, testResult);

        // If closing fails, it should log.
        testResult = 0;
        osMock.when(() -> Os.close(any(FileDescriptor.class))).thenThrow(new ErrnoException("close", 0));
        assertNull(FileHelper.closeOrWarn(fd, "tag", "msg"));
        assertEquals(1, testResult);
    }

    @Test
    public void testCloseOrWarn_closeable() throws Exception {
        Closeable closeable = mock(Closeable.class);
        logMock.when(() -> Log.e(anyString(), anyString(), any(Throwable.class))).thenAnswer(new CountingAnswer(null));

        // Closing null should work just fine
        testResult = 0;
        assertNull(FileHelper.closeOrWarn((Closeable) null, "tag", "msg"));
        assertEquals(0, testResult);

        // Successfully closing the file should not log.
        testResult = 0;
        assertNull(FileHelper.closeOrWarn(closeable, "tag", "msg"));
        assertEquals(0, testResult);

        // If closing fails, it should log.
        doThrow(new IOException("Foobar")).when(closeable).close();

        testResult = 0;
        assertNull(FileHelper.closeOrWarn(closeable, "tag", "msg"));
        assertEquals(1, testResult);
    }

    private class CountingAnswer implements Answer<Object> {

        private final Object result;

        public CountingAnswer(Object result) {
            this.result = result;
        }

        @Override
        public Object answer(InvocationOnMock invocation) throws Throwable {
            testResult++;
            // Os.poll returns an int; Mockito cannot translate a null answer
            // to a primitive, so fall back to 0 when no result was given.
            return result != null ? result : 0;
        }
    }
}
