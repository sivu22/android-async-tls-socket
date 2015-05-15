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

/**
 * Callbacks of the async socket
 * Created by Cristian Sava on 07.05.2015.
 */
public interface AsyncTLSSocketEvents {
    /**
     * Called when the TLS handshake was successful and the server authenticated
     */
    void onConnect();

    /**
     * Connection failed, reasons: TLS could not be established, server not authenticated,
     * server rejected the connection, timeout, already trying to connect, ...
     */
    void onFailedToConnect(AsyncTLSSocket.SOCKET_STATUS clientStatus);

    /**
     * Server terminated the connection
     * Will not be called when the socket disconnects
     */
    void onDisconnect();

    /**
     * Presents read-data to the observer
     * @param bytes data read from the socket
     */
    void onRead(byte[] bytes);
}
