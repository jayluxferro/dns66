package org.jak_linux.dns66;

import android.content.Context;
import android.net.Uri;
import android.os.Handler;
import android.os.Looper;
import android.system.ErrnoException;
import android.system.Os;
import android.system.OsConstants;
import android.system.StructPollfd;
import android.util.Log;
import android.widget.Toast;

import java.io.Closeable;
import java.io.File;
import java.io.FileDescriptor;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.UnsupportedEncodingException;
import java.io.Writer;

/**
 * Utility class for working with files.
 */

public final class FileHelper {

    /**
     * Show a toast from any thread. FileHelper methods are also called from
     * threads without a Looper (e.g. the VPN thread loading the config at
     * boot), where calling Toast directly throws
     * "Can't toast on a thread that has not called Looper.prepare()" and
     * kills the process.
     */
    private static void showToast(final Context context, final String message, final int duration) {
        new Handler(Looper.getMainLooper()).post(new Runnable() {
            @Override
            public void run() {
                Toast.makeText(context, message, duration).show();
            }
        });
    }

    /**
     * Try open the file with {@link Context#openFileInput(String)}, falling back to a file of
     * the same name in the assets.
     */
    public static InputStream openRead(Context context, String filename) throws IOException {
        try {
            return context.openFileInput(filename);
        } catch (FileNotFoundException e) {
            return context.getAssets().open(filename);
        }
    }

    /**
     * Write to the given file in the private files dir, first renaming an old one to .bak
     *
     * Warning: unsafe for irreplaceable data. The rotation to .bak has already
     * happened when this returns, and the first write to the returned stream
     * truncates the live file, so a failed write leaves a broken file behind.
     * writeSettings() no longer uses this for settings.json for exactly that
     * reason; it stages writes through a .tmp file instead. Kept as tested
     * public API.
     *
     * @param context  A context
     * @param filename A filename as for @{link {@link Context#openFileOutput(String, int)}}
     * @return See @{link {@link Context#openFileOutput(String, int)}}
     * @throws IOException See @{link {@link Context#openFileOutput(String, int)}}
     */
    public static OutputStream openWrite(Context context, String filename) throws IOException {
        File out = context.getFileStreamPath(filename);

        // Create backup
        out.renameTo(context.getFileStreamPath(filename + ".bak"));

        return context.openFileOutput(filename, Context.MODE_PRIVATE);
    }

    private static Configuration readConfigFile(Context context, String name, boolean defaultsOnly) throws IOException {
        InputStream stream;
        if (defaultsOnly)
            stream = context.getAssets().open(name);
        else
            stream = FileHelper.openRead(context, name);

        // Gson does not close the reader, so close the stream ourselves;
        // closeOrWarn keeps a close error from masking a read error.
        try {
            return Configuration.read(new InputStreamReader(stream));
        } finally {
            FileHelper.closeOrWarn(stream, "FileHelper", "readConfigFile: Cannot close " + name);
        }
    }

    public static Configuration loadCurrentSettings(Context context) {
        try {
            return readConfigFile(context, "settings.json", false);
        } catch (Exception e) {
            showToast(context, context.getString(R.string.cannot_read_config, e.getLocalizedMessage()), Toast.LENGTH_LONG);
            return loadPreviousSettings(context);
        }
    }

    public static Configuration loadPreviousSettings(Context context) {
        try {
            return readConfigFile(context, "settings.json.bak", false);
        } catch (Exception e) {
            showToast(context, context.getString(R.string.cannot_restore_previous_config, e.getLocalizedMessage()), Toast.LENGTH_LONG);
            return loadDefaultSettings(context);
        }
    }

    public static Configuration loadDefaultSettings(Context context) {
        try {
            return readConfigFile(context, "settings.json", true);
        } catch (Exception e) {
            showToast(context, context.getString(R.string.cannot_load_default_config, e.getLocalizedMessage()), Toast.LENGTH_LONG);
            return null;
        }
    }

    /**
     * Write settings.json atomically: the new configuration first goes to
     * settings.json.tmp, and the live settings.json is only replaced once the
     * replacement is complete on disk.
     *
     * Writing through openWrite() instead used to truncate settings.json
     * (openFileOutput uses MODE_PRIVATE) before a single byte of the new
     * content existed, and the rotation to .bak had already happened. Gson
     * reports stream errors as JsonIOException, a RuntimeException that a
     * plain IOException catch does not see, so a failed write left a 0-byte
     * settings.json — and the next write rotated that empty file over the
     * good .bak, destroying the last resort of loadPreviousSettings().
     */
    public static void writeSettings(Context context, Configuration config) {
        Log.d("FileHelper", "writeSettings: Writing the settings file");
        File out = context.getFileStreamPath("settings.json");
        File tmp = context.getFileStreamPath("settings.json.tmp");

        Writer writer = null;
        boolean written = false;
        try {
            writer = new OutputStreamWriter(context.openFileOutput(tmp.getName(), Context.MODE_PRIVATE));
            config.write(writer);
            // close() would flush too, but flush explicitly: only a fully
            // written file may be rotated into place below.
            writer.flush();
            written = true;
        } catch (Throwable e) {
            // Throwable, not IOException: JsonIOException is a RuntimeException.
            showToast(context, context.getString(R.string.cannot_write_config, e.getLocalizedMessage()), Toast.LENGTH_SHORT);
        } finally {
            if (writer != null) {
                try {
                    writer.close();
                } catch (IOException e) {
                    if (written) {
                        // The tail end did not make it to disk; report it, once.
                        written = false;
                        showToast(context, context.getString(R.string.cannot_write_config, e.getLocalizedMessage()), Toast.LENGTH_SHORT);
                    }
                }
            }
        }

        if (!written) {
            // Drop the partial file; settings.json and .bak stay untouched.
            tmp.delete();
            return;
        }

        // The staged file is complete, rotate it into place. Renaming the old
        // file to .bak may fail if it does not exist yet; that is fine. If the
        // final rename fails, settings.json still holds the previous content.
        out.renameTo(context.getFileStreamPath("settings.json.bak"));
        if (!tmp.renameTo(out)) {
            showToast(context, context.getString(R.string.cannot_write_config, "could not rename " + tmp.getName()), Toast.LENGTH_SHORT);
            tmp.delete();
        }
    }

    /**
     * Returns a file where the item should be downloaded to.
     *
     * @param context A context to work in
     * @param item    A configuration item.
     * @return File or null, if that item is not downloadable.
     */
    public static File getItemFile(Context context, Configuration.Item item) {
        if (item.isDownloadable()) {
            try {
                return new File(context.getExternalFilesDir(null), java.net.URLEncoder.encode(item.location, "UTF-8"));
            } catch (UnsupportedEncodingException e) {
                e.printStackTrace();
                return null;
            }
        } else {
            return null;
        }
    }

    public static InputStreamReader openItemFile(Context context, Configuration.Item item) throws FileNotFoundException {
        if (item.location.startsWith("content://")) {
            try {
                return new InputStreamReader(context.getContentResolver().openInputStream(Uri.parse(item.location)));
            } catch (SecurityException e) {
                Log.d("FileHelper", "openItemFile: Cannot open", e);
                throw new FileNotFoundException(e.getMessage());
            }
        } else {
            File file = getItemFile(context, item);
            if (file == null)
                return null;
            if (item.isDownloadable())
                return new InputStreamReader(new SingleWriterMultipleReaderFile(getItemFile(context, item)).openRead());
            return new FileReader(getItemFile(context, item));
        }
    }

    /**
     * Wrapper around {@link Os#poll(StructPollfd[], int)} that automatically restarts on EINTR
     * While post-Lollipop devices handle that themselves, we need to do this for Lollipop.
     *
     * @param fds     Descriptors and events to wait on
     * @param timeout Timeout. Should be -1 for infinite, as we do not lower the timeout when
     *                retrying due to an interrupt
     * @return The number of fds that have events
     * @throws ErrnoException See {@link Os#poll(StructPollfd[], int)}
     */
    public static int poll(StructPollfd[] fds, int timeout) throws ErrnoException, InterruptedException {
        while (true) {
            if (Thread.interrupted())
                throw new InterruptedException();
            try {
                return Os.poll(fds, timeout);
            } catch (ErrnoException e) {
                if (e.errno == OsConstants.EINTR)
                    continue;
                throw e;
            }
        }
    }

    public static FileDescriptor closeOrWarn(FileDescriptor fd, String tag, String message) {
        try {
            if (fd != null)
                Os.close(fd);
        } catch (ErrnoException e) {
            Log.e(tag, "closeOrWarn: " + message, e);
        } finally {
            return null;
        }
    }

    public static <T extends Closeable> T closeOrWarn(T fd, String tag, String message) {
        try {
            if (fd != null)
                fd.close();
        } catch (Exception e) {
            Log.e(tag, "closeOrWarn: " + message, e);
        } finally {
            return null;
        }
    }
}
