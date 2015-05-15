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

package com.sivu22.asyncclient.Socket;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.util.Log;

import com.sivu22.asyncclient.BuildConfig;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.InetSocketAddress;
import java.security.KeyStore;
import java.security.SecureRandom;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;


/**
 * Asynchronous socket used to establish a TLS connection
 * Created by Cristian Sava on 07.05.2015.
 */
public class AsyncTLSSocket {
    public static final boolean USE_LOG = BuildConfig.DEBUG;
    private static final String LOG_TAG = AsyncTLSSocket.class.getName();

    // Used to provide feedback on the connection state
    // Useful to present UI notifications
    public enum SOCKET_STATUS {
        STATUS_OK,                  // Not connected
        NO_NETWORK,                 // Network unavailable
        NO_CONTEXT,                 // A valid context was not provided
        BAD_STORE,                  // An invalid trust store was found
        CONNECT_FAIL,               // Failed to connect
        BAD_SERVER,                 // Server is untrustworthy
        TRUST_FAILED,               // Trust evaluation failed
        CONNECT_TRY,                // Trying to connect
        CONNECT_OK                  // Connected successfully
    }

    private static final int READ_BUFFER_SIZE = 1024;
    private static final int CONNECT_TIMEOUT_MS = 7000;

    private Context mContext = null;                // Context is used only for checking network availability,
                                                    // could be easily refactored and mContext removed if desired
    private AsyncTLSSocketEvents mCallbacks;
    private String mServerAddr = "";
    private int mServerPort = 0;

    private boolean mConnected = false;
    private boolean mConnectRuns = false;
    private boolean mReadRuns = false;

    private SSLSocket mSocket = null;


    public AsyncTLSSocket(Context context, AsyncTLSSocketEvents callbacks, String addr, int port) {
        this.mContext = context;
        this.mCallbacks = callbacks;
        this.mServerAddr = addr;
        this.mServerPort = port;

        if(USE_LOG) Log.i(LOG_TAG, "client created with address " + this.mServerAddr + " and port " + this.mServerPort);
        if(this.mContext == null)
            if(USE_LOG) Log.e(LOG_TAG, "no context provided, will not be able to connect!");
    }

    /**
     * Checks if client is connected
     * @return true if connected, false otherwise
     */
    public boolean isConnected() {
        // DO NOT use socket.isConnected()
        return mConnected;
    }

    /**
     * Try to connect to the specified address and port
     * Starts the communication thread
     * @param trustStore nonnull for a custom trust store, null for the system default one
     */
    public void connect(@Nullable KeyStore trustStore) {
        if(USE_LOG) Log.i(LOG_TAG, "connect() called");

        if(trustStore == null) {
            if(USE_LOG) Log.e(LOG_TAG, "invalid trust store, will return now!");
            if(mCallbacks != null) mCallbacks.onFailedToConnect(SOCKET_STATUS.BAD_STORE);
            return;
        }

        if(mConnected || mConnectRuns) {
            if(USE_LOG) Log.i(LOG_TAG, "client is already connected or in the process, will return now!");
            if(mCallbacks != null) mCallbacks.onFailedToConnect(SOCKET_STATUS.CONNECT_TRY);
            return;
        }
        if(this.mContext == null) {
            if(USE_LOG) Log.e(LOG_TAG, "client has no valid context, will return now!");
            if(mCallbacks != null) mCallbacks.onFailedToConnect(SOCKET_STATUS.NO_CONTEXT);
            return;
        }

        if(!isNetworkAvailable()) {
            if(USE_LOG) Log.e(LOG_TAG, "network unavailable! can not connect");
            if(mCallbacks != null) mCallbacks.onFailedToConnect(SOCKET_STATUS.NO_NETWORK);
            return;
        }

        // Handle connecting in a dedicated thread
        Thread connThread = new Thread(new ConnectionThread(trustStore));
        connThread.start();
    }

    /**
     * Should be called when client finishes, closes the socket
     */
    public void disconnect() {
        if(USE_LOG) Log.i(LOG_TAG, "disconnect() called");

        // Can't execute network code on main thread, create another thread for this
        Thread disconnectThread = new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    // First set this to false, so the reading thread knows the client initiated the disconnect
                    // And thus not to invoke the onDisconnect() callback
                    mConnected = false;
                    if(mSocket != null && !mSocket.isClosed()) mSocket.close();
                } catch (Exception ex) {
                    if(USE_LOG) Log.e(LOG_TAG, "Error closing socket! " + ex.getMessage());
                }
            }
        });
        disconnectThread.start();
    }

    /**
     * Start reading from the socket in a separate thread
     */
    public void startRead() {
        // Obviously
        if(!mConnected) return;
        if(mReadRuns) return;

        // Handle reading from socket in another thread
        Thread readThread = new Thread(new ReadThread());
        readThread.start();
    }

    /**
     * Write data to socket
     * @param data array of bytes to be written
     */
    public void write(final byte[] data) {
        // Obviously
        if(!mConnected) return;

        // Can't execute network code on main thread, create another thread for this
        Thread writeThread = new Thread(new Runnable() {
            @Override
            public void run() {
                try
                {
                    PrintWriter out = new PrintWriter(new BufferedWriter(new OutputStreamWriter(mSocket.getOutputStream())), true);
                    String dataString = new String(data, "UTF-8");
                    char[] chars = dataString.toCharArray();
                    out.println(chars);

                    if(USE_LOG) Log.i(LOG_TAG, "Client sent: " + dataString);
                } catch (Exception ex)
                {
                    if(USE_LOG) Log.e(LOG_TAG, "failed to send network data!" + ex.getMessage());
                }
            }
        });
        writeThread.start();
    }

    /**
     * Checks if network connectivity is present
     * @return true if network is reachable, false otherwise
     */
    private boolean isNetworkAvailable() {
        ConnectivityManager connectivityManager = (ConnectivityManager)mContext.getSystemService(Context.CONNECTIVITY_SERVICE);
        NetworkInfo activeNI = connectivityManager.getActiveNetworkInfo();

        return activeNI != null && activeNI.isConnected();
    }

    /**
     * Loads a trust store to be used when connecting
     * @param context Activity
     * @param fileName name of the trust store
     * @param password password needed to load the trust store
     * @return a valid KeyStore on success, null otherwise
     */
    @Nullable
    public static KeyStore loadLocalTrustStore(@NonNull Context context, @NonNull String fileName, @NonNull String password) {
        try {
            KeyStore trustStore = KeyStore.getInstance("BKS");
            InputStream trustStoreStream = new FileInputStream(new File(context.getFilesDir(), fileName));
            trustStore.load(trustStoreStream, password.toCharArray());
            trustStoreStream.close();

            return trustStore;
        } catch(Exception ex) {
            if(USE_LOG) Log.e(LOG_TAG, "error while loading local trust store " + ex.toString());
        }

        return null;
    }


    /**
     * Thread that tries connecting to the server
     * connected will be true if the socket connected, the TLS handshake was successful and the server certificate's hostname matches
     */
    private class ConnectionThread implements Runnable {
        private KeyStore mTrustStore;

        public ConnectionThread(KeyStore trustStore) {
            mTrustStore = trustStore;
        }

        public void run() {
            mConnectRuns = true;
            mConnected = false;

            try {
                TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
                // If mTrustStore is null, the system default store will be used
                // To be kept in mind if self-signed CAs are needed, then a valid trust store MUST be used
                trustManagerFactory.init(mTrustStore);

                SSLContext sslContext = SSLContext.getInstance("TLS");
                // No client authentication
                sslContext.init(null, trustManagerFactory.getTrustManagers(), new SecureRandom());

                SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();
                mSocket = (SSLSocket)sslSocketFactory.createSocket();

                mSocket.setUseClientMode(true);
                mSocket.connect(new InetSocketAddress(mServerAddr, mServerPort), CONNECT_TIMEOUT_MS);
                // If there is no exception here, the server certificate is trusted
                mSocket.startHandshake();

                HostnameVerifier hostnameVerifier = HttpsURLConnection.getDefaultHostnameVerifier();
                // No bueno
                if(!hostnameVerifier.verify(mServerAddr, mSocket.getSession())) {
                    if(USE_LOG) Log.e(LOG_TAG, "server is untrustworthy!");

                    if(mCallbacks != null) mCallbacks.onFailedToConnect(SOCKET_STATUS.BAD_SERVER);

                    mConnectRuns = false;
                    return;
                }

                // Finally connected
                mConnected = true;
                if(USE_LOG) Log.i(LOG_TAG, "connected successfully");

                if (mCallbacks != null) mCallbacks.onConnect();
            } catch(Exception ex) {
                // CONNECT_FAIL almost certainly means a timeout
                SOCKET_STATUS clientStatus = SOCKET_STATUS.CONNECT_FAIL;

                if(ex instanceof SSLHandshakeException) {
                    if(USE_LOG) Log.e(LOG_TAG, "error validating server certificate! " + ex.getMessage());

                    clientStatus = SOCKET_STATUS.TRUST_FAILED;
                }
                else if(USE_LOG) Log.e(LOG_TAG, "connecting error! " + ex.getMessage());

                if(mCallbacks != null) mCallbacks.onFailedToConnect(clientStatus);
            }

            if(!mConnected) try {
                mSocket.close();
            } catch(Exception ex) {
                if(USE_LOG) Log.i(LOG_TAG, "failed to close socket! " + ex.getMessage());
            }

            mConnectRuns = false;
        }
    }


    /**
     * Thread that keeps reading from the connected socket
     */
    private class ReadThread implements Runnable {
        public void run() {
            mReadRuns = true;

            int numRead;
            byte[] buffer = new byte[READ_BUFFER_SIZE];
            try {
                InputStream in = mSocket.getInputStream();
                while((numRead = in.read(buffer, 0, READ_BUFFER_SIZE - 1)) != -1) {
                    byte[] readData = new byte[numRead-1];
                    System.arraycopy(buffer, 0, readData, 0, numRead - 1);

                    if(USE_LOG) Log.d("Server sent: ", new String(readData, "UTF-8"));

                    if(mCallbacks != null) mCallbacks.onRead(readData);
                }
            } catch(Exception ex) {
                if(USE_LOG) Log.e(LOG_TAG, "read error! client disconnected" + ex.getMessage());

                // mConnected will be false if the client disconnected
                if(mConnected && mCallbacks != null) mCallbacks.onDisconnect();
                mConnected = false;
            }

            mReadRuns = false;
        }
    }
}
