/* Copyright (C) 2017 Software Freedom Conservancy (author: Julian Andres Klode) <jak@jak-linux.org>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */
package org.jak_linux.dns66.db;

import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.ContentResolver;
import android.content.Context;
import android.content.Intent;
import android.content.UriPermission;
import android.net.Uri;
import android.os.AsyncTask;
import androidx.annotation.NonNull;
import androidx.core.app.NotificationCompat;
import androidx.core.content.ContextCompat;

import android.util.Log;

import org.jak_linux.dns66.Configuration;
import org.jak_linux.dns66.MainActivity;
import org.jak_linux.dns66.NotificationChannels;
import org.jak_linux.dns66.R;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Asynchronous task to update the database.
 * <p>
 * This spawns a thread pool fetching updating host files from
 * remote servers.
 */
public class RuleDatabaseUpdateTask extends AsyncTask<Void, Void, Void> {
    public static final AtomicReference<List<String>> lastErrors = new AtomicReference<>(null);
    private static final String TAG = "RuleDatabaseUpdateTask";
    private static final int UPDATE_NOTIFICATION_ID = 42;
    Context context;
    Configuration configuration;
    ArrayList<String> errors = new ArrayList<>();
    List<String> pending = new ArrayList<>();
    List<String> done = new ArrayList<>();
    // Snapshot of configuration.hosts.items taken at construction time. The live
    // list is shared with the UI thread (MainActivity.refresh passes the active
    // configuration), where add/delete/toggle can run while this task iterates it
    // on worker threads; iterating an aliased list would throw
    // ConcurrentModificationException and kill the refresh mid-way.
    private List<Configuration.Item> items;
    private NotificationManager notificationManager;
    private NotificationCompat.Builder notificationBuilder;

    public RuleDatabaseUpdateTask(Context context, Configuration configuration, boolean notifications) {
        Log.d(TAG, "RuleDatabaseUpdateTask: Begin");
        this.context = context;
        this.configuration = configuration;
        // The configuration is optional (unit tests construct bare tasks); only
        // its items list is read below.
        this.items = configuration == null ? new ArrayList<>() : new ArrayList<>(configuration.hosts.items);

        if (notifications)
            setupNotificationBuilder();

        Log.d(TAG, "RuleDatabaseUpdateTask: Setup");
    }

    private void setupNotificationBuilder() {
        notificationManager =
                (NotificationManager) context.getSystemService(Context.NOTIFICATION_SERVICE);
        notificationBuilder = new NotificationCompat.Builder(context, NotificationChannels.UPDATE_STATUS)
                .setContentTitle(context.getString(R.string.updating_hostfiles))
                .setSmallIcon(R.drawable.ic_refresh)
                .setColor(ContextCompat.getColor(context, R.color.colorPrimaryDark))
                .setProgress(items.size(), 0, false);
    }

    @Override
    protected Void doInBackground(final Void... configurations) {
        Log.d(TAG, "doInBackground: begin");
        long start = System.currentTimeMillis();
        ExecutorService executor = Executors.newCachedThreadPool();

        // Iterate the snapshot taken in the constructor, never the live list.
        for (Configuration.Item item : items) {
            RuleDatabaseItemUpdateRunnable runnable = getCommand(item);
            if (runnable.shouldDownload())
                executor.execute(runnable);
        }

        releaseGarbagePermissions();

        executor.shutdown();
        while (true) {
            try {
                if (executor.awaitTermination(1, TimeUnit.HOURS))
                    break;

                Log.d(TAG, "doInBackground: Waiting for completion");
            } catch (InterruptedException e) {
                // The task was cancelled (AsyncTask.cancel(true) from onStopJob
                // interrupts this thread). Stop waiting and interrupt the
                // workers, so in-flight downloads abort instead of pinning this
                // task (and with Fix 1, the job) for up to another hour. The
                // interrupt flag is deliberately not restored: postExecute()
                // below still has to run to finish the cancellation cleanly.
                executor.shutdownNow();
                break;
            }
        }
        long end = System.currentTimeMillis();
        Log.d(TAG, "doInBackground: end after " + (end - start) + "milliseconds");

        postExecute();

        return null;
    }

    /**
     * Releases all persisted URI permissions that are no longer referenced
     */
    void releaseGarbagePermissions() {
        ContentResolver contentResolver = context.getContentResolver();
        for (UriPermission permission : contentResolver.getPersistedUriPermissions()) {
            if (isGarbage(permission.getUri())) {
                Log.i(TAG, "releaseGarbagePermissions: Releasing permission for " + permission.getUri());
                contentResolver.releasePersistableUriPermission(permission.getUri(), Intent.FLAG_GRANT_READ_URI_PERMISSION);
            } else {
                Log.v(TAG, "releaseGarbagePermissions: Keeping permission for " + permission.getUri());
            }
        }
    }

    /**
     * Returns whether URI is no longer referenced in the configuration
     *
     * @param uri URI to check
     */
    private boolean isGarbage(Uri uri) {
        for (Configuration.Item item : items) {
            if (Uri.parse(item.location).equals(uri))
                return false;
        }
        return true;
    }

    /**
     * RuleDatabaseItemUpdateRunnable factory for unit tests
     */
    @NonNull
    RuleDatabaseItemUpdateRunnable getCommand(Configuration.Item item) {
        return new RuleDatabaseItemUpdateRunnable(this, context, item) {
            @Override
            HttpURLConnection internalOpenHttpConnection(URL url) throws IOException {
                // url.openConnection() does not return an HttpURLConnection for
                // every location reaching this point (e.g. a non-http scheme);
                // the blind cast in the base implementation would kill this
                // worker thread with an unhandled ClassCastException before any
                // error is recorded. Throwing IOException instead routes the
                // failure through run()'s existing error reporting.
                URLConnection connection = url.openConnection();
                if (!(connection instanceof HttpURLConnection))
                    throw new IOException("Not an HTTP(S) URL: " + url);
                return (HttpURLConnection) connection;
            }
        };
    }

    /**
     * Sets progress message.
     */
    private synchronized void updateProgressNotification() {
        StringBuilder builder = new StringBuilder();
        for (String p : pending) {
            if (builder.length() > 0)
                builder.append("\n");
            builder.append(p);
        }

        if (notificationBuilder != null) {
            notificationBuilder.setProgress(pending.size() + done.size(), done.size(), false)
                    .setStyle(new NotificationCompat.BigTextStyle().bigText(builder.toString()))
                    .setContentText(context.getString(R.string.updating_n_host_files, pending.size()));
            notificationManager.notify(UPDATE_NOTIFICATION_ID, notificationBuilder.build());
        }
    }

    /**
     * Clears the notifications or updates it for viewing errors.
     */
    private synchronized void postExecute() {
        Log.d(TAG, "postExecute: Sending notification");
        try {
            RuleDatabase.getInstance().initialize(context);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        if (notificationBuilder != null) {
            if (errors.isEmpty()) {
                notificationManager.cancel(UPDATE_NOTIFICATION_ID);
            } else {
                notificationBuilder.setProgress(0, 0, false);
                notificationBuilder.setContentText(context.getString(R.string.could_not_update_all_hosts));
                notificationBuilder.setSmallIcon(R.drawable.ic_warning);

                Intent intent = new Intent(context, MainActivity.class);
                intent.addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP);

                lastErrors.set(errors);
                PendingIntent pendingIntent = PendingIntent.getActivity(context, 0,
                        intent, PendingIntent.FLAG_ONE_SHOT | PendingIntent.FLAG_IMMUTABLE);


                notificationBuilder.setContentIntent(pendingIntent);

                notificationBuilder.setAutoCancel(true);
                notificationManager.notify(UPDATE_NOTIFICATION_ID, notificationBuilder.build());
            }
        }
    }

    /**
     * Adds an error message related to the item to the log.
     *
     * @param item    The item
     * @param message Message
     */
    synchronized void addError(Configuration.Item item, String message) {
        Log.d(TAG, "error: " + item.title + ":" + message);
        errors.add("<b>" + item.title + "</b><br>" + message);
    }

    /**
     * Marks an item as done.
     *
     * @param item Item that has finished.
     */
    synchronized void addDone(Configuration.Item item) {
        Log.d(TAG, "done: " + item.title);
        pending.remove(item.title);
        done.add(item.title);
        updateProgressNotification();
    }

    /**
     * Adds an item to the notification
     *
     * @param item The item currently being processed.
     */
    synchronized void addBegin(Configuration.Item item) {
        pending.add(item.title);
        updateProgressNotification();
    }

    synchronized long pendingCount() {
        return pending.size();
    }
}
