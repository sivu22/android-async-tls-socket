# android-async-tls-socket
Simple to use asynchronous socket for establishing a TLS connection from an Android phone.<br>
Born from the frustration of lacking a simple and fast way to achieve this on Android, where the focus seems to be only on https. And SSLEngine seems overkill.

### Self-signed certificates
Sometimes you are using self-signed certificates when establishing trust. But the system store doesn't allow you to use them, because the trust anchors are already loaded and the default SSLContext is already initialized by the time the app starts.<br>
In this (quite common) case, when the client wants to connect to the server while using a self-signed certificate, a custom trust store must be used - 'trust all' is not a solution.<br><br>


First, create your own trust store and add the trust anchor(s) inside. Then you add the store to your app. This <a href="http://stackoverflow.com/a/15531475">SO answer</a> (points 1 and 2) describe the process in great detail.<br>
Second, load the custom store inside the app, before connecting the socket. Use the static function <br>
```java
public static KeyStore loadLocalTrustStore(@NonNull Context context, 
                                            @NonNull String fileName, @NonNull String password)
```
<br> from the AsyncTLSSocket class to accomplish this.<br><br>


A detailed and informative article on custom trust stores and Android can be found <a href="http://nelenkov.blogspot.no/2011/12/using-custom-certificate-trust-store-on.html">here</a>.

### Callbacks
All operations are asynchronous. The caller will be notified of events and status via
```java
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
```

### Service
Continous networking should be done in a service. That's why the socket comes embedded inside an Android service.<br>
The service is both Started and Bound and will handle the socket notifications. An activity that binds to the service is notified of the socket status via a callback.<br><br>
The network client should be implemented completely inside the service, while the binding Activity can handle the appropriate UI response.<br><br>

##### Completing the service
* Create the client with the correct IP and port number
```java
mClient = new AsyncTLSSocket(this, this, "server_ip", server_port);
```
* Decide how trust should be verified. If self-signed certificate and custom trust store are used, implement the connecting function like this<br>
```java
public void connect() {
    KeyStore trustStore = AsyncTLSSocket.loadLocalTrustStore(this, "trust_store_filename.bks", "store_password");
    mClient.connect(trustStore);
}
```
* Or just use the system default<br>
```java
public void connect() {
    mClient.connect(null);
}
```
* Implement network logic when bytes are read from the socket
```java
private void networkRead(byte[] data) {
    // TODO: on the UI thread, do something with received data
}
```

### Usage
* Create an activity (for example LoginActivity) and declare the service and the bound status
```java
private CommService mService;
private boolean mIsBound = false;
```
* Start and stop the service accordingly.
```java
@Override
protected void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    ...
    startService(new Intent(this, CommService.class));
}

@Override
protected void onDestroy() {
    super.onDestroy();

    if(isFinishing()) stopService(new Intent(this, CommService.class));
}
```
* Handle binding and unbinding from service. This usually happens when the Activity switches from background to foreground and vice-versa.
``` java
@Override
protected void onStart() {
    super.onStart();
    ...
    if(!mIsBound) doBindToService();
}

@Override
protected void onStop() {
    super.onStop();

    if(mIsBound) doUnbindFromService();
}

private void doBindToService() {
    Intent bindIntent = new Intent(this, CommService.class);
    bindService(bindIntent, mConnection, Context.BIND_AUTO_CREATE);
}

private void doUnbindFromService() {
    unbindService(mConnection);
    mIsBound = false;
}
```
* Make sure the Activity implements the ClientStatusChangeEvent interface and then code the appropriate logic
``` java
@Override
public void reportClientStatus(AsyncTLSSocket.SOCKET_STATUS clientStatus) {
    // TODO: UI or functional changes, depending on the reported status
    // For example when the client failed to connect or the server disconnected
}
```
* Create the ServiceConnection, get the server reference and set up the callback to be notified when the client status changes.
``` java
private ServiceConnection mConnection = new ServiceConnection() {
    @Override
    public void onServiceConnected(ComponentName componentName, IBinder iBinder) {
        CommService.LocalBinder binder = (CommService.LocalBinder)iBinder;
        mService = binder.getService();
        mIsBound = true;

        mService.setActivityCallback(LoginActivity.this);
    }

    @Override
    public void onServiceDisconnected(ComponentName componentName) {
        mIsBound = false;
    }
};
```
<br>That's it. Since the networking protocol is implemented in the service, all there is left to do is call the service functions for connecting
```java
mService.connect();
```
and disconnecting
```java
mService.disconnect();
```
