/* Copyright (C) 2016 - 2017 Software Freedom Conservancy (author: Julian Andres Klode) <jak@jak-linux.org>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */
package org.jak_linux.dns66.db;

import android.content.Context;
import androidx.annotation.Nullable;
import android.util.Log;

import org.jak_linux.dns66.Configuration;
import org.jak_linux.dns66.FileHelper;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Represents hosts that are blocked.
 * <p>
 * This is a very basic set of hosts. But it supports lock-free
 * readers with writers active at the same time, only the writers
 * having to take a lock.
 */
public class RuleDatabase {

    private static final String TAG = "RuleDatabase";
    private static final RuleDatabase instance = new RuleDatabase();
    final AtomicReference<HashSet<String>> blockedHosts = new AtomicReference<>(new HashSet<String>());
    /**
     * Hosts from bare-domain lists (e.g. oisd's domainswild or justdomains
     * style files: one second-level domain per line, no 127.0.0.1 prefix).
     * Their publishers mean them to be matched with wildcards, so any
     * subdomain of an entry is blocked; hosts-file entries stay exact.
     */
    final AtomicReference<HashSet<String>> wildcardBlockedHosts = new AtomicReference<>(new HashSet<String>());
    /**
     * Manually added regular expressions (location "regex:<pattern>"),
     * keyed by the pattern text so an allow entry can remove one again.
     */
    final AtomicReference<LinkedHashMap<String, Pattern>> regexPatterns = new AtomicReference<>(new LinkedHashMap<String, Pattern>());
    HashSet<String> nextBlockedHosts = null;
    HashSet<String> nextWildcardBlockedHosts = null;
    LinkedHashMap<String, Pattern> nextRegexPatterns = null;

    /**
     * Package-private constructor for instance and unit tests.
     */
    RuleDatabase() {

    }


    /**
     * Returns the instance of the rule database.
     */
    public static RuleDatabase getInstance() {
        return instance;
    }

    /**
     * Parse a single line in a hosts file
     *
     * @param line A line to parse
     * @return A host
     */
    @Nullable
    static String parseLine(String line) {
        int endOfLine = line.indexOf('#');

        if (endOfLine == -1)
            endOfLine = line.length();

        // Trim spaces
        while (endOfLine > 0 && Character.isWhitespace(line.charAt(endOfLine - 1)))
            endOfLine--;

        // The line is empty.
        if (endOfLine <= 0)
            return null;

        // Find beginning of host field
        int startOfHost = 0;

        if (line.regionMatches(0, "127.0.0.1", 0, 9) && (endOfLine <= 9 || Character.isWhitespace(line.charAt(9))))
            startOfHost += 10;
        else if (line.regionMatches(0, "::1", 0, 3) && (endOfLine <= 3 || Character.isWhitespace(line.charAt(3))))
            startOfHost += 4;
        else if (line.regionMatches(0, "0.0.0.0", 0, 7) && (endOfLine <= 7 || Character.isWhitespace(line.charAt(7))))
            startOfHost += 8;

        // Trim of space at the beginning of the host.
        while (startOfHost < endOfLine && Character.isWhitespace(line.charAt(startOfHost)))
            startOfHost++;

        // Reject lines containing a space
        for (int i = startOfHost; i < endOfLine; i++) {
            if (Character.isWhitespace(line.charAt(i)))
                return null;
        }

        if (startOfHost >= endOfLine)
            return null;

        String host = line.substring(startOfHost, endOfLine).toLowerCase(Locale.ENGLISH);
        // A leading wildcard marker ("*.example.com" in oisd's domainswild)
        // means "this domain and any subdomain" - exactly what the wildcard
        // set implements, so strip it there.
        if (host.startsWith("*.")) {
            host = host.substring(2);
            if (host.isEmpty())
                return null;
        }
        return host;
    }

    /**
     * Checks if a host is blocked.
     *
     * @param host A hostname
     * @return true if the host is blocked, false otherwise.
     */
    public boolean isBlocked(String host) {
        if (blockedHosts.get().contains(host))
            return true;
        // Wildcard entries (bare-domain lists) match the host itself and any
        // subdomain: walk the host and its parent domains ("a.b.example.com"
        // -> "b.example.com" -> "example.com" -> "com").
        HashSet<String> wildcards = wildcardBlockedHosts.get();
        if (!wildcards.isEmpty()) {
            String candidate = host;
            while (candidate != null) {
                if (wildcards.contains(candidate))
                    return true;
                int dot = candidate.indexOf('.');
                candidate = dot == -1 ? null : candidate.substring(dot + 1);
            }
        }
        // Manually added regular expressions (matched against the
        // lower-case host name).
        LinkedHashMap<String, Pattern> patterns = regexPatterns.get();
        if (!patterns.isEmpty()) {
        for (Pattern pattern : patterns.values()) {
            if (pattern.matcher(host).matches())
                return true;
        }
        }
        return false;
    }

    /**
     * Check if any hosts are blocked
     *
     * @return true if any hosts are blocked, false otherwise.
     */
    boolean isEmpty() {
        return blockedHosts.get().isEmpty() && wildcardBlockedHosts.get().isEmpty() && regexPatterns.get().isEmpty();
    }

    /**
     * Load the hosts according to the configuration
     *
     * @param context A context used for opening files.
     * @throws InterruptedException Thrown if the thread was interrupted, so we don't waste time
     *                              reading more host files than needed.
     */
    public synchronized void initialize(Context context) throws InterruptedException {
        Configuration config = FileHelper.loadCurrentSettings(context);

        nextBlockedHosts = new HashSet<>(blockedHosts.get().size());
        nextWildcardBlockedHosts = new HashSet<>(wildcardBlockedHosts.get().size());
        nextRegexPatterns = new LinkedHashMap<>(regexPatterns.get().size());

        Log.i(TAG, "Loading block list");

        if (!config.hosts.enabled) {
            Log.d(TAG, "loadBlockedHosts: Not loading, disabled.");
        } else {
            for (Configuration.Item item : config.hosts.items) {
                if (Thread.interrupted())
                    throw new InterruptedException("Interrupted");
                loadItem(context, item);
            }
        }

        blockedHosts.set(nextBlockedHosts);
        wildcardBlockedHosts.set(nextWildcardBlockedHosts);
        regexPatterns.set(nextRegexPatterns);
        Runtime.getRuntime().gc();
    }

    /**
     * Loads an item. An item can be backed by a file or contain a value in the location field.
     *
     * @param context Context to open files
     * @param item    The item to load.
     * @throws InterruptedException If the thread was interrupted.
     */
    void loadItem(Context context, Configuration.Item item) throws InterruptedException {
        if (item.state == Configuration.Item.STATE_IGNORE)
            return;

        InputStreamReader reader;
        try {
            reader = FileHelper.openItemFile(context, item);
        } catch (FileNotFoundException e) {
            Log.d(TAG, "loadItem: File not found: " + item.location);
            return;
        }

        if (reader == null) {
            addManualEntry(item);
            return;
        } else {
            loadReader(item, reader);
        }
    }

    /**
     * Applies a manually entered location (no downloadable list). Supported
     * forms: {@code regex:<pattern>} for a regular expression matched
     * against the lower-case host name, {@code *.example.com} for a domain
     * with all its subdomains, and a plain hostname for an exact match.
     */
    private void addManualEntry(Configuration.Item item) {
        String location = item.location.toLowerCase(Locale.ENGLISH);
        if (location.startsWith("regex:")) {
            addRegex(item, item.location.substring("regex:".length()));
        } else if (location.startsWith("*.")) {
            addHost(item, location.substring(2), true);
        } else {
            addHost(item, location, false);
        }
    }

    /**
     * Adds (or, for an allow item, removes by identical pattern text) a
     * regular expression entry. Invalid patterns are logged and skipped
     * rather than crashing the load.
     */
    private void addRegex(Configuration.Item item, String patternText) {
        if (item.state == Configuration.Item.STATE_ALLOW) {
            nextRegexPatterns.remove(patternText);
            return;
        }
        if (item.state != Configuration.Item.STATE_DENY)
            return;
        try {
            nextRegexPatterns.put(patternText, Pattern.compile(patternText));
        } catch (PatternSyntaxException e) {
            Log.e(TAG, "addRegex: Invalid regular expression in item " + item.title + ": " + patternText, e);
        }
    }

    /**
     * Whether a line from a host list uses the hosts-file shape
     * ("0.0.0.0 example.com" or "127.0.0.1 example.com"), as opposed to a
     * bare domain. Mirrors the prefix handling in {@link #parseLine(String)}.
     */
    static boolean hasHostsFilePrefix(String line) {
        return (line.regionMatches(0, "127.0.0.1", 0, 9) && (line.length() <= 9 || Character.isWhitespace(line.charAt(9))))
                || (line.regionMatches(0, "::1", 0, 3) && (line.length() <= 3 || Character.isWhitespace(line.charAt(3))))
                || (line.regionMatches(0, "0.0.0.0", 0, 7) && (line.length() <= 7 || Character.isWhitespace(line.charAt(7))));
    }

    /**
     * Add a single host for an item.
     *
     * @param item     The item the host belongs to
     * @param host     The host
     * @param wildcard Whether the host comes from a bare-domain list, where
     *                 the publisher means it to cover subdomains as well
     */
    private void addHost(Configuration.Item item, String host, boolean wildcard) {
        // Single address to block
        if (item.state == Configuration.Item.STATE_ALLOW) {
            nextBlockedHosts.remove(host);
            nextWildcardBlockedHosts.remove(host);
        } else if (item.state == Configuration.Item.STATE_DENY) {
            if (wildcard)
                nextWildcardBlockedHosts.add(host);
            else
                nextBlockedHosts.add(host);
        }
    }

    /**
     * Load a single file
     *
     * @param item   The configuration item referencing the file
     * @param reader A reader to read lines from
     * @throws InterruptedException If thread was interrupted
     */
    boolean loadReader(Configuration.Item item, Reader reader) throws InterruptedException {
        int count = 0;
        try {
            Log.d(TAG, "loadBlockedHosts: Reading: " + item.location);
            try (BufferedReader br = new BufferedReader(reader)) {
                String line;
                while ((line = br.readLine()) != null) {
                    if (Thread.interrupted())
                        throw new InterruptedException("Interrupted");
                    String host = parseLine(line);
                    if (host != null) {
                        count += 1;
                        // Lines with an 0.0.0.0/127.0.0.1 prefix are hosts-file
                        // entries and block exactly what they name; bare lines
                        // are wildcard-style domain lists (see addHost).
                        // Single-label bare lines (junk like "localhost" or a
                        // stray "com" in sloppy lists) stay exact: wildcarding
                        // them would block a whole TLD's subtree.
                        addHost(item, host, !hasHostsFilePrefix(line) && host.indexOf('.') != -1);
                    }
                }
            }
            Log.d(TAG, "loadBlockedHosts: Loaded " + count + " hosts from " + item.location);
            return true;
        } catch (IOException e) {
            Log.e(TAG, "loadBlockedHosts: Error while reading " + item.location + " after " + count + " items", e);
            return false;
        } finally {
            FileHelper.closeOrWarn(reader, TAG, "loadBlockedHosts: Error closing " + item.location);
        }
    }
}
