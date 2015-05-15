/**
 *  Copyright 2015 Cristian Sava
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package com.sivu22.asyncclient;

import android.app.Service;
import android.content.Intent;
import android.os.Binder;
import android.os.Handler;
import android.os.IBinder;
import android.util.Log;

import com.sivu22.asyncclient.Socket.AsyncTLSSocket;
import com.sivu22.asyncclient.Socket.AsyncTLSSocketEvents;

import java.security.KeyStore;

/**
 * A started & bound service used to handle the tls connection
 * Created by Cristian Sava on 07.05.2015.
 */
public class CommService extends Service implements AsyncTLSSocketEvents {
    private static final String LOG_TAG = CommService.class.getName();

    private AsyncTLSSocket mClient = null;

    // Queue messages from the networking threads
    private Handler mHandler = new Handler();

    private final IBinder mBinder = new LocalBinder();

    private ClientStatusChangeEvent mActivityCallback = null;
    // Used only to report the service client status when the activity is binding
    private AsyncTLSSocket.SOCKET_STATUS mServiceClientStatus = AsyncTLSSocket.SOCKET_STATUS.STATUS_OK;


    public CommService() {
    }

    @Override
    public void onCreate() {
        super.onCreate();

        if(LogApp.LOG) Log.d(LOG_TAG, "service is created");

        // Create the network client
        mClient = new AsyncTLSSocket(this, this, "192.168.1.22", 4444);
    }

    @Override
    public void onDestroy() {
        super.onDestroy();

        if(LogApp.LOG) Log.d(LOG_TAG, "service will destroy now");

        if(mClient != null && mClient.isConnected()) mClient.disconnect();
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if(LogApp.LOG) Log.d(LOG_TAG, "onStartCommand() called with intent " + intent);

        // Depending on how the service is stopped and how it should work, use START_STICKY
        return START_NOT_STICKY;
    }

    public class LocalBinder extends Binder {
        public CommService getService() {
            return CommService.this;
        }
    }
    @Override
    public IBinder onBind(Intent intent) {
        return mBinder;
    }

    @Override
    public boolean onUnbind(Intent intent) {
        // No more activity notifications
        mActivityCallback = null;

        return false;
    }


    public void setActivityCallback(ClientStatusChangeEvent activity) {
        mActivityCallback = activity;

        // Immediately notify the current client status
        // Useful for updating the UI, when the activity comes to foreground and binds to the service
        if(mActivityCallback != null) mActivityCallback.reportClientStatus(mServiceClientStatus);
    }

    public void connect() {
        KeyStore trustStore = AsyncTLSSocket.loadLocalTrustStore(this, "trust_store_filename.bks", "store_password");
        mClient.connect(trustStore);
    }

    public void disconnect() {
        mClient.disconnect();
    }

    public void write(byte[] data) {
        mClient.write(data);
    }

    private void reportClientStatus(AsyncTLSSocket.SOCKET_STATUS clientStatus) {
        mServiceClientStatus = clientStatus;

        // If there is an activity that was bind to the service and implements the callback interface,
        // notify the change of the client's status
        if(mActivityCallback != null) mActivityCallback.reportClientStatus(clientStatus);
    }

    @Override
    public void onConnect() {
        if(LogApp.LOG) Log.i(LOG_TAG, "onConnect() called");

        reportClientStatus(AsyncTLSSocket.SOCKET_STATUS.CONNECT_OK);

        // Start reading immediately
        mClient.startRead();

        // Take it to the UI thread
        mHandler.post(new Runnable() {
            @Override
            public void run() {
                // TODO: do things when the connection is established, like authenticating the user
            }
        });
    }

    @Override
    public void onFailedToConnect(final AsyncTLSSocket.SOCKET_STATUS clientStatus) {
        if(LogApp.LOG) Log.i(LOG_TAG, "onFailedToConnect() called");

        // Take it to the UI thread
        mHandler.post(new Runnable() {
            @Override
            public void run() {
                reportClientStatus(clientStatus);
            }
        });
    }

    @Override
    public void onDisconnect() {
        if(LogApp.LOG) Log.i(LOG_TAG, "onDisconnect() called");

        // Take it to the UI thread
        mHandler.post(new Runnable() {
            @Override
            public void run() {
                // Set the right status for disconnect
                reportClientStatus(AsyncTLSSocket.SOCKET_STATUS.STATUS_OK);
            }
        });
    }

    @Override
    public void onRead(final byte[] bytes) {
        if(LogApp.LOG) Log.i(LOG_TAG, "onRead() called");

        // Take it to the UI thread
        mHandler.post(new Runnable() {
            @Override
            public void run() {
                networkRead(bytes);
            }
        });
    }

    private void networkRead(byte[] data) {
        // TODO: on the UI thread, do something with received data
    }
}
