package org.jak_linux.dns66.db;

import android.content.ContentResolver;
import android.content.Context;
import android.content.UriPermission;
import android.net.Uri;
import android.util.Log;

import org.jak_linux.dns66.Configuration;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;

import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

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

    private Uri newUri(String location) throws Exception {
        if (uriLocations.containsKey(location))
            return uriLocations.get(location);

        Uri uri = Mockito.mock(Uri.class);
        uriLocations.put(location, uri);

        return uri;
    }
}
