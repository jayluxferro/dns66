package org.jak_linux.dns66.db;

import android.content.ContentResolver;
import android.content.Context;
import android.content.UriPermission;
import android.net.Uri;
import android.util.Log;

import org.jak_linux.dns66.Configuration;
import org.jak_linux.dns66.FileHelper;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

/**
 * Created by jak on 19/05/17.
 */
public class RuleDatabaseUpdateTaskTest {

    HashMap<String, Uri> uriLocations = new HashMap<>();

    private MockedStatic<Log> logMock;
    private MockedStatic<Uri> uriMock;

    private Configuration.Item newItemForLocation(String location) {
        Configuration.Item item = new Configuration.Item();
        item.location = location;
        return item;
    }

    @Before
    public void setUp() throws Exception {
        logMock = mockStatic(Log.class);
        uriMock = mockStatic(Uri.class);

        uriMock.when(() -> Uri.parse(anyString())).thenAnswer(new Answer<Uri>() {

            @Override
            public Uri answer(InvocationOnMock invocation) throws Throwable {
                return newUri(invocation.getArgument(0));
            }
        });

    }

    @After
    public void tearDown() throws Exception {
        logMock.close();
        uriMock.close();
    }

    @Test
    public void testReleaseGarbagePermissions() throws Exception {
        Context mockContext = mock(Context.class);
        ContentResolver mockResolver = mock(ContentResolver.class);
        when(mockContext.getContentResolver()).thenReturn(mockResolver);

        final List<UriPermission> persistedPermissions = new LinkedList<>();
        when(mockResolver.getPersistedUriPermissions()).thenReturn(persistedPermissions);

        UriPermission usedPermission = mock(UriPermission.class);
        when(usedPermission.getUri()).thenReturn(newUri("content://used"));
        persistedPermissions.add(usedPermission);

        UriPermission garbagePermission = mock(UriPermission.class);
        when(garbagePermission.getUri()).thenReturn(newUri("content://garbage"));
        persistedPermissions.add(garbagePermission);

        doAnswer(new Answer<Void>() {
            @Override
            public Void answer(InvocationOnMock invocation) throws Throwable {
                Iterator<UriPermission> iter = persistedPermissions.iterator();
                while (iter.hasNext()) {
                    UriPermission perm = iter.next();
                    if (perm.getUri() == invocation.getArgument(0))
                        iter.remove();
                }
                return null;
            }
        }).when(mockResolver).releasePersistableUriPermission(any(Uri.class), anyInt());

        Configuration configuration = new Configuration();
        configuration.hosts.items.add(newItemForLocation("content://used"));

        assertTrue(persistedPermissions.contains(usedPermission));
        assertTrue(persistedPermissions.contains(garbagePermission));

        new RuleDatabaseUpdateTask(mockContext, configuration, false).releaseGarbagePermissions();

        assertTrue(persistedPermissions.contains(usedPermission));
        assertFalse(persistedPermissions.contains(garbagePermission));
    }

    /**
     * The task must iterate a snapshot of configuration.hosts.items, not the
     * live list: the UI thread can remove items while an update is running.
     */
    @Test
    public void testItemsAreSnapshottedAtConstruction() throws Exception {
        Context mockContext = mock(Context.class);
        ContentResolver mockResolver = mock(ContentResolver.class);
        when(mockContext.getContentResolver()).thenReturn(mockResolver);

        List<UriPermission> persistedPermissions = new LinkedList<>();
        when(mockResolver.getPersistedUriPermissions()).thenReturn(persistedPermissions);

        UriPermission usedPermission = mock(UriPermission.class);
        when(usedPermission.getUri()).thenReturn(newUri("content://used-while-running"));
        persistedPermissions.add(usedPermission);

        Configuration configuration = new Configuration();
        configuration.hosts.items.add(newItemForLocation("content://used-while-running"));

        RuleDatabaseUpdateTask task = new RuleDatabaseUpdateTask(mockContext, configuration, false);

        // Simulate the UI thread deleting the item mid-update.
        configuration.hosts.items.clear();

        task.releaseGarbagePermissions();

        // With a live view of the list, the item would now be treated as
        // garbage and its permission released behind the UI's back.
        assertTrue(persistedPermissions.contains(usedPermission));
    }

    /**
     * A location that opens into a non-HTTP connection must fail the item via
     * the normal error path (IOException in run()) instead of killing the
     * worker thread with a ClassCastException.
     */
    @Test
    public void testGetCommandRejectsNonHttpConnection() throws Exception {
        Context mockContext = mock(Context.class);
        Configuration.Item item = new Configuration.Item();
        item.location = "ftp://example.com/hosts.txt";
        item.title = "hosts";

        RuleDatabaseItemUpdateRunnable runnable =
                new RuleDatabaseUpdateTask(mockContext, null, false).getCommand(item);

        URL url = mock(URL.class);

        when(url.openConnection()).thenReturn(mock(URLConnection.class));
        try {
            runnable.internalOpenHttpConnection(url);
            fail("non-HTTP connections must be rejected with an IOException");
        } catch (IOException e) {
            assertTrue("Unexpected message: " + e.getMessage(), e.getMessage().contains("HTTP"));
        }

        // HTTP connections pass through unchanged.
        HttpURLConnection httpConnection = mock(HttpURLConnection.class);
        when(url.openConnection()).thenReturn(httpConnection);
        assertSame(httpConnection, runnable.internalOpenHttpConnection(url));
    }

    /**
     * Cancelling the task (AsyncTask.cancel(true) interrupts the thread
     * running doInBackground) must abort the awaitTermination wait and the
     * stuck download, not be swallowed by the wait loop. Before the fix this
     * test hung until its timeout.
     */
    @Test(timeout = 30000)
    public void testDoInBackgroundReturnsWhenInterrupted() throws Exception {
        // JUnit's @Test(timeout) runs this method on a thread of its own, and
        // static mocks are thread-local: the mocks from @Before are not visible
        // here, so Log is mocked again on this thread.
        try (MockedStatic<Log> timeoutThreadLogMock = mockStatic(Log.class);
             MockedStatic<FileHelper> fileHelperMock = mockStatic(FileHelper.class)) {
            // postExecute re-initializes the rule database, which loads the
            // configuration again; hand it an empty one.
            fileHelperMock.when(() -> FileHelper.loadCurrentSettings(any(Context.class)))
                    .thenReturn(new Configuration());

            Context mockContext = mock(Context.class);
            ContentResolver mockResolver = mock(ContentResolver.class);
            when(mockContext.getContentResolver()).thenReturn(mockResolver);
            when(mockResolver.getPersistedUriPermissions()).thenReturn(new LinkedList<>());

            Configuration configuration = new Configuration();
            Configuration.Item item = new Configuration.Item();
            item.location = "content://stuck-download";
            item.title = "stuck-download";
            configuration.hosts.items.add(item);

            // Signals from the stubbed worker: started, allowed to finish, and
            // whether cancellation reached it. The worker runs on a pool thread
            // where android.* statics are not mocked, so it must avoid Log and
            // therefore addBegin/addDone.
            final CountDownLatch downloadStarted = new CountDownLatch(1);
            final CountDownLatch downloadMayFinish = new CountDownLatch(1);
            final AtomicBoolean downloadInterrupted = new AtomicBoolean(false);

            RuleDatabaseUpdateTask task = new RuleDatabaseUpdateTask(mockContext, configuration, false) {
                @Override
                RuleDatabaseItemUpdateRunnable getCommand(Configuration.Item configuredItem) {
                    return new RuleDatabaseItemUpdateRunnable(this, mockContext, configuredItem) {
                        @Override
                        public void run() {
                            downloadStarted.countDown();
                            try {
                                downloadMayFinish.await();
                            } catch (InterruptedException e) {
                                downloadInterrupted.set(true);
                            }
                        }
                    };
                }
            };

            // A helper thread plays the role of AsyncTask.cancel(true).
            final Thread runner = Thread.currentThread();
            Thread canceller = new Thread(new Runnable() {
                @Override
                public void run() {
                    try {
                        downloadStarted.await();
                        runner.interrupt();
                    } catch (InterruptedException e) {
                    }
                }
            });
            canceller.start();

            try {
                task.doInBackground();

                assertTrue("Cancellation did not reach the stuck download", downloadInterrupted.get());
                assertTrue("Interrupted update must not record errors", task.errors.isEmpty());
            } finally {
                // Unblock the worker if an assertion above failed early.
                downloadMayFinish.countDown();
            }
        }
    }

    private Uri newUri(String location) throws Exception {
        if (uriLocations.containsKey(location))
            return uriLocations.get(location);

        Uri uri = Mockito.mock(Uri.class);
        uriLocations.put(location, uri);

        return uri;
    }
}
