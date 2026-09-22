/* Copyright (C) 2016-2019 Software Freedom Conservancy (author: Julian Andres Klode) <jak@jak-linux.org>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */
package org.jak_linux.dns66.main;

import android.content.Intent;
import android.os.Bundle;
import com.google.android.material.floatingactionbutton.FloatingActionButton;
import androidx.fragment.app.Fragment;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import androidx.recyclerview.widget.ItemTouchHelper;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.CompoundButton;
import android.widget.Switch;

import org.jak_linux.dns66.Configuration;
import org.jak_linux.dns66.FileHelper;
import org.jak_linux.dns66.ItemActivity;
import org.jak_linux.dns66.MainActivity;
import org.jak_linux.dns66.R;

import static android.app.Activity.RESULT_OK;

public class DNSFragment extends Fragment implements FloatingActionButtonFragment {

    /** Request code for the item editor, unique among this fragment's requests. */
    private static final int REQUEST_ITEM_EDIT = 3;

    /** Saved-state key for {@link #editingPosition}. */
    private static final String STATE_EDITING_POSITION = "editingPosition";

    /**
     * Position passed to a currently open item editor, -1 for a new item.
     * Stored in the saved instance state: MainActivity can be recreated
     * while the editor is open, and the result must still be applied to the
     * right row of the freshly built adapter.
     */
    private int editingPosition = -1;

    private ItemRecyclerViewAdapter mAdapter;

    public DNSFragment() {
    }

    @Override
    public View onCreateView(LayoutInflater inflater, ViewGroup container,
                             Bundle savedInstanceState) {
        if (savedInstanceState != null)
            editingPosition = savedInstanceState.getInt(STATE_EDITING_POSITION, -1);

        View rootView = inflater.inflate(R.layout.fragment_dns, container, false);

        RecyclerView mRecyclerView = (RecyclerView) rootView.findViewById(R.id.dns_entries);

        // use this setting to improve performance if you know that changes
        // in content do not change the layout size of the RecyclerView
        mRecyclerView.setHasFixedSize(true);

        // use a linear layout manager
        RecyclerView.LayoutManager mLayoutManager = new LinearLayoutManager(getContext());
        mRecyclerView.setLayoutManager(mLayoutManager);

        mAdapter = new ItemRecyclerViewAdapter(MainActivity.config.dnsServers.items, 2,
                new ItemRecyclerViewAdapter.ItemEditListener() {
                    @Override
                    public void onEditItem(int position) {
                        editItem(position);
                    }
                });
        mRecyclerView.setAdapter(mAdapter);

        ItemTouchHelper itemTouchHelper = new ItemTouchHelper(new ItemTouchHelperCallback(mAdapter));
        itemTouchHelper.attachToRecyclerView(mRecyclerView);

        Switch dnsEnabled = (Switch) rootView.findViewById(R.id.dns_enabled);
        dnsEnabled.setChecked(MainActivity.config.dnsServers.enabled);
        dnsEnabled.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
            @Override
            public void onCheckedChanged(CompoundButton buttonView, boolean isChecked) {
                MainActivity.config.dnsServers.enabled = isChecked;
                FileHelper.writeSettings(getContext(), MainActivity.config);
            }
        });
        ExtraBar.setup(rootView.findViewById(R.id.extra_bar), "dns");
        return rootView;
    }

    /**
     * Open the item editor for the item at position, or for a new item if
     * position is negative. The result is handled by {@link #onActivityResult},
     * which the framework delivers to this fragment even if MainActivity is
     * recreated while the editor is open — the activity-level listener this
     * replaces used to drop the edit in that case.
     */
    private void editItem(int position) {
        Intent editIntent = new Intent(getActivity(), ItemActivity.class);

        editingPosition = position;
        if (position >= 0) {
            Configuration.Item item = MainActivity.config.dnsServers.items.get(position);
            editIntent.putExtra("ITEM_TITLE", item.title);
            editIntent.putExtra("ITEM_LOCATION", item.location);
            editIntent.putExtra("ITEM_STATE", item.state);
        }
        editIntent.putExtra("STATE_CHOICES", 2);
        startActivityForResult(editIntent, REQUEST_ITEM_EDIT);
    }

    /**
     * Apply the item returned by the editor: replace the edited one, remove
     * it (item == null, the DELETE path), or append it for a new item.
     */
    private void applyEditedItem(int position, Configuration.Item item) {
        if (position < 0) {
            MainActivity.config.dnsServers.items.add(item);
            if (mAdapter != null)
                mAdapter.notifyItemInserted(mAdapter.getItemCount() - 1);
        } else if (item == null) {
            MainActivity.config.dnsServers.items.remove(position);
            if (mAdapter != null)
                mAdapter.notifyItemRemoved(position);
        } else {
            MainActivity.config.dnsServers.items.set(position, item);
            if (mAdapter != null)
                mAdapter.notifyItemChanged(position);
        }
        FileHelper.writeSettings(getContext(), MainActivity.config);
    }

    @Override
    public void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode != REQUEST_ITEM_EDIT)
            return;
        // The editor round-trip is over either way; don't let a stale
        // position leak into the next edit.
        int position = editingPosition;
        editingPosition = -1;
        if (resultCode != RESULT_OK)
            return;

        Configuration.Item item = null;
        if (!data.hasExtra("DELETE")) {
            item = new Configuration.Item();
            item.title = data.getStringExtra("ITEM_TITLE");
            item.location = data.getStringExtra("ITEM_LOCATION");
            item.state = data.getIntExtra("ITEM_STATE", 0);
        }
        applyEditedItem(position, item);
    }

    @Override
    public void onSaveInstanceState(Bundle outState) {
        super.onSaveInstanceState(outState);
        outState.putInt(STATE_EDITING_POSITION, editingPosition);
    }

    @Override
    public void setupFloatingActionButton(FloatingActionButton fab) {
        fab.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                editItem(-1);
            }
        });
    }
}
