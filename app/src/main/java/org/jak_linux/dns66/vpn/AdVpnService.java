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

import android.app.Notification;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ServiceInfo;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.NetworkRequest;
import android.net.VpnService;
import android.os.Build;
import android.os.Handler;
import android.os.Message;
import android.os.SystemClock;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.core.app.NotificationCompat;
import androidx.core.app.ServiceCompat;
import androidx.core.content.ContextCompat;
import androidx.localbroadcastmanager.content.LocalBroadcastManager;
import android.util.Log;

import org.jak_linux.dns66.Configuration;
import org.jak_linux.dns66.FileHelper;
import org.jak_linux.dns66.MainActivity;
import org.jak_linux.dns66.NotificationChannels;
import org.jak_linux.dns66.R;

import java.lang.ref.WeakReference;
import java.util.Collections;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

public class AdVpnService extends VpnService implements Handler.Callback {

    public static final int NOTIFICATION_ID_STATE = 10;
    public static final int NOTIFICATION_ID_PAUSED = 11;
    public static final int REQUEST_CODE_START = 43;
    public static final int REQUEST_CODE_PAUSE = 42;

    /* The handler may only keep a weak reference around, otherwise it leaks */
    private static class MyHandler extends Handler {
        private final WeakReference<Handler.Callback> callback;
        public MyHandler(Handler.Callback callback) {
            this.callback = new WeakReference<Callback>(callback);
        }
        @Override
        public void handleMessage(Message msg) {
            Handler.Callback callback = this.callback.get();
            if (callback != null) {
                callback.handleMessage(msg);
            }
            super.handleMessage(msg);
        }
    }
    public static final int VPN_STATUS_STARTING = 0;
    public static final int VPN_STATUS_RUNNING = 1;
    public static final int VPN_STATUS_STOPPING = 2;
    public static final int VPN_STATUS_WAITING_FOR_NETWORK = 3;
    public static final int VPN_STATUS_RECONNECTING = 4;
    public static final int VPN_STATUS_RECONNECTING_NETWORK_ERROR = 5;
    public static final int VPN_STATUS_STOPPED = 6;
    public static final String VPN_UPDATE_STATUS_INTENT = "org.jak_linux.dns66.VPN_UPDATE_STATUS";
    public static final String VPN_UPDATE_STATUS_EXTRA = "VPN_STATUS";
    private static final int VPN_MSG_STATUS_UPDATE = 0;
    private static final int VPN_MSG_NETWORK_CHANGED = 1;
    private static final String TAG = "VpnService";
    /* For this long after a (re-)registration, network callbacks only update
     * availableNetworks without telling the VPN thread: registerNetworkCallback
     * replays all currently present networks, and the thread that just started
     * configures with exactly those networks. Relaying the replay would make
     * it reconnect again and again before it is even up. Genuine changes
     * within the window are rare and self-heal through the thread's own
     * retry loop. */
    private static final long NETWORK_SETTLE_MILLIS = 2000;
    // TODO: Temporary Hack til refactor is done
    public static int vpnStatus = VPN_STATUS_STOPPED;
    private final Handler handler = new MyHandler(this);
    private AdVpnThread vpnThread = createVpnThread();
    private final Set<Network> availableNetworks = Collections.newSetFromMap(new ConcurrentHashMap<Network, Boolean>());
    /* Whether networkCallback is currently registered: registering it a
     * second time throws IllegalArgumentException */
    private boolean networkCallbackRegistered = false;
    /* When networkCallback was last registered (SystemClock.elapsedRealtime()) */
    private long networkCallbackRegisteredAt = 0;
    /* Set while onDestroy is running: startForeground must not be called
     * again, it would replace the paused notification. */
    private boolean destroying = false;
    private final ConnectivityManager.NetworkCallback networkCallback = new ConnectivityManager.NetworkCallback() {
        @Override
        public void onAvailable(Network network) {
            availableNetworks.add(network);
            notifyNetworkChanged(1);
        }

        @Override
        public void onLost(Network network) {
            availableNetworks.remove(network);
            notifyNetworkChanged(availableNetworks.isEmpty() ? 0 : 1);
        }
    };
    private final NotificationCompat.Builder notificationBuilder = new NotificationCompat.Builder(this, NotificationChannels.SERVICE_RUNNING)
            .setSmallIcon(R.drawable.ic_state_deny) // TODO: Notification icon
            .setPriority(Notification.PRIORITY_MIN);

    /* Creates a VPN thread reporting status updates back to our handler.
     * Recreated on demand: stopVpn() nulls the thread, and a later start
     * on the same service instance needs a fresh one. */
    private AdVpnThread createVpnThread() {
        return new AdVpnThread(this, new AdVpnThread.Notify() {
            @Override
            public void run(int value) {
                handler.sendMessage(handler.obtainMessage(VPN_MSG_STATUS_UPDATE, value, 0));
            }
        });
    }

    private void notifyNetworkChanged(int arg) {
        if (SystemClock.elapsedRealtime() - networkCallbackRegisteredAt < NETWORK_SETTLE_MILLIS)
            return;
        handler.sendMessage(handler.obtainMessage(VPN_MSG_NETWORK_CHANGED, arg, 0));
    }

    public static int vpnStatusToTextId(int status) {
        switch (status) {
            case VPN_STATUS_STARTING:
                return R.string.notification_starting;
            case VPN_STATUS_RUNNING:
                return R.string.notification_running;
            case VPN_STATUS_STOPPING:
                return R.string.notification_stopping;
            case VPN_STATUS_WAITING_FOR_NETWORK:
                return R.string.notification_waiting_for_net;
            case VPN_STATUS_RECONNECTING:
                return R.string.notification_reconnecting;
            case VPN_STATUS_RECONNECTING_NETWORK_ERROR:
                return R.string.notification_reconnecting_error;
            case VPN_STATUS_STOPPED:
                return R.string.notification_stopped;
            default:
                throw new IllegalArgumentException("Invalid vpnStatus value (" + status + ")");
        }
    }

    @Override
    public void onCreate() {
        super.onCreate();
        NotificationChannels.onCreate(this);

        notificationBuilder.addAction(R.drawable.ic_pause_black_24dp, getString(R.string.notification_action_pause),
                PendingIntent.getService(this, REQUEST_CODE_PAUSE, new Intent(this, AdVpnService.class)
                                .putExtra("COMMAND", Command.PAUSE.ordinal()), PendingIntent.FLAG_IMMUTABLE))
                .setColor(ContextCompat.getColor(this, R.color.colorPrimaryDark));
    }

    public static void checkStartVpnOnBoot(Context context) {
        Log.i("BOOT", "Checking whether to start ad buster on boot");
        Configuration config = FileHelper.loadCurrentSettings(context);
        if (config == null || !config.autoStart) {
            return;
        }
        if (!context.getSharedPreferences("state", MODE_PRIVATE).getBoolean("isActive", false)) {
            return;
        }

        if (VpnService.prepare(context) != null) {
            Log.i("BOOT", "VPN preparation not confirmed by user, changing enabled to false");
        }

        Log.i("BOOT", "Starting ad buster from boot");
        NotificationChannels.onCreate(context);

        Intent intent = getStartIntent(context);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            context.startForegroundService(intent);
        } else {
            context.startService(intent);
        }
    }

    @NonNull
    private static Intent getStartIntent(Context context) {
        Intent intent = new Intent(context, AdVpnService.class);
        intent.putExtra("COMMAND", Command.START.ordinal());
        intent.putExtra("NOTIFICATION_INTENT",
                PendingIntent.getActivity(context, 0,
                        new Intent(context, MainActivity.class), PendingIntent.FLAG_IMMUTABLE));
        return intent;
    }

    @NonNull
    private static Intent getResumeIntent(Context context) {
        Intent intent = new Intent(context, AdVpnService.class);
        intent.putExtra("COMMAND", Command.RESUME.ordinal());
        intent.putExtra("NOTIFICATION_INTENT",
                PendingIntent.getActivity(context, 0,
                        new Intent(context, MainActivity.class), PendingIntent.FLAG_IMMUTABLE));
        return intent;
    }

    @Override
    public int onStartCommand(@Nullable Intent intent, int flags, int startId) {
        Log.i(TAG, "onStartCommand" + intent);
        Command command = Command.START;
        if (intent != null) {
            int ordinal = intent.getIntExtra("COMMAND", Command.START.ordinal());
            Command[] values = Command.values();
            if (ordinal >= 0 && ordinal < values.length) {
                command = values[ordinal];
            } else {
                // The service is guarded by BIND_VPN_SERVICE, so this can only
                // be a stale intent of ours (e.g. from before an update that
                // reordered the enum). Ignore the command instead of crashing
                // on the lookup, but keep the START_STICKY return.
                Log.w(TAG, "onStartCommand: Ignoring invalid command " + ordinal);
                return Service.START_STICKY;
            }
        }
        switch (command) {
            case RESUME:
                // Cancel only the notifications we own: cancelAll() here also
                // dropped unrelated notifications like rule update errors.
                NotificationManager notificationManager = (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);
                notificationManager.cancel(NOTIFICATION_ID_PAUSED);
                notificationManager.cancel(NOTIFICATION_ID_STATE);
                // fallthrough
            case START:
                getSharedPreferences("state", MODE_PRIVATE).edit().putBoolean("isActive", true).apply();
                startVpn(intent == null ? null : (PendingIntent) intent.getParcelableExtra("NOTIFICATION_INTENT"));
                break;
            case STOP:
                getSharedPreferences("state", MODE_PRIVATE).edit().putBoolean("isActive", false).apply();
                stopVpn();
                break;
            case PAUSE:
                pauseVpn();
                break;
        }

        return Service.START_STICKY;
    }

    private void pauseVpn() {
        stopVpn();
        NotificationManager notificationManager = (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);
        notificationManager.notify(NOTIFICATION_ID_PAUSED, new NotificationCompat.Builder(this, NotificationChannels.SERVICE_PAUSED)
                .setSmallIcon(R.drawable.ic_state_deny) // TODO: Notification icon
                .setPriority(Notification.PRIORITY_LOW)
                .setColor(ContextCompat.getColor(this, R.color.colorPrimaryDark))
                .setContentTitle(getString(R.string.notification_paused_title))
                .setContentText(getString(R.string.notification_paused_text))
                .setContentIntent(PendingIntent.getService(this, REQUEST_CODE_START, getResumeIntent(this), PendingIntent.FLAG_ONE_SHOT | PendingIntent.FLAG_IMMUTABLE))
                .build());
    }

    private void updateVpnStatus(int status) {
        vpnStatus = status;
        int notificationTextId = vpnStatusToTextId(status);
        notificationBuilder.setContentTitle(getString(notificationTextId));

        // While destroying, do not call startForeground again: it would
        // replace the paused notification (posted with notify()) and get
        // cancelled with the service's foreground teardown. The service is
        // going away, only the status broadcast below still matters.
        if (!destroying && (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O || FileHelper.loadCurrentSettings(getApplicationContext()).showNotification)) {
            // When targeting 34+, the foreground service type must be passed explicitly.
            int fgsType = Build.VERSION.SDK_INT >= 34 ? ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE : 0;
            ServiceCompat.startForeground(this, NOTIFICATION_ID_STATE, notificationBuilder.build(), fgsType);
        }

        Intent intent = new Intent(VPN_UPDATE_STATUS_INTENT);
        intent.putExtra(VPN_UPDATE_STATUS_EXTRA, status);
        LocalBroadcastManager.getInstance(this).sendBroadcast(intent);
    }


    private void startVpn(PendingIntent notificationIntent) {
        notificationBuilder.setContentTitle(getString(R.string.notification_title));
        if (notificationIntent != null)
            notificationBuilder.setContentIntent(notificationIntent);
        updateVpnStatus(VPN_STATUS_STARTING);

        // NOT_VPN is a default capability of a network request, so our own VPN network is
        // never reported here and cannot trigger reconnect loops.
        ConnectivityManager connectivityManager = (ConnectivityManager) getSystemService(Context.CONNECTIVITY_SERVICE);
        if (!networkCallbackRegistered) {
            // Networks may have changed while we were not running. The
            // callback replays all currently present networks right after
            // registration, so clearing here recomputes our connectivity
            // state from scratch.
            availableNetworks.clear();
            connectivityManager.registerNetworkCallback(
                    new NetworkRequest.Builder().addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET).build(),
                    networkCallback);
            networkCallbackRegistered = true;
            networkCallbackRegisteredAt = SystemClock.elapsedRealtime();
        }

        restartVpnThread();
    }

    private void restartVpnThread() {
        if (vpnThread == null) {
            // Only stopVpn() nulls the thread; recreate it so that starting
            // the VPN again works on the same service instance.
            Log.i(TAG, "restartVpnThread: Recreating previously stopped thread.");
            vpnThread = createVpnThread();
        }

        vpnThread.stopThread();
        vpnThread.startThread();
    }


    private void stopVpnThread() {
        vpnThread.stopThread();
    }

    private void waitForNetVpn() {
        if (vpnThread == null) {
            // Stale message after stopVpn(), nothing left to pause.
            Log.i(TAG, "waitForNetVpn: Not waiting for network, could not find thread.");
            return;
        }
        stopVpnThread();
        updateVpnStatus(VPN_STATUS_WAITING_FOR_NETWORK);
    }

    private void reconnect() {
        if (vpnThread == null) {
            // Stale message after stopVpn(): restarting here would bring the
            // VPN back up against the user's decision to stop it.
            Log.i(TAG, "reconnect: Not reconnecting, could not find thread.");
            return;
        }
        updateVpnStatus(VPN_STATUS_RECONNECTING);
        restartVpnThread();
    }

    private void stopVpn() {
        Log.i(TAG, "Stopping Service");
        if (vpnThread != null)
            stopVpnThread();
        vpnThread = null;
        if (networkCallbackRegistered) {
            try {
                ConnectivityManager connectivityManager = (ConnectivityManager) getSystemService(Context.CONNECTIVITY_SERVICE);
                connectivityManager.unregisterNetworkCallback(networkCallback);
                networkCallbackRegistered = false;
            } catch (IllegalArgumentException e) {
                Log.i(TAG, "Ignoring exception on unregistering network callback");
            }
        }
        // Forget the networks seen by the callback, so a later start
        // computes the connectivity state fresh.
        availableNetworks.clear();
        updateVpnStatus(VPN_STATUS_STOPPED);
        stopSelf();
    }

    @Override
    public void onDestroy() {
        Log.i(TAG, "Destroyed, shutting down");
        destroying = true;
        stopVpn();
    }

    @Override
    public boolean handleMessage(Message message) {
        if (message == null) {
            return true;
        }

        switch (message.what) {
            case VPN_MSG_STATUS_UPDATE:
                updateVpnStatus(message.arg1);
                break;
            case VPN_MSG_NETWORK_CHANGED:
                if (message.arg1 == 0) {
                    Log.i(TAG, "Connectivity changed to no connectivity, wait for a network");
                    waitForNetVpn();
                } else {
                    Log.i(TAG, "Network changed, try to reconnect");
                    reconnect();
                }
                break;
            default:
                throw new IllegalArgumentException("Invalid message with what = " + message.what);
        }
        return true;
    }
}
