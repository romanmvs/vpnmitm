package com.m.w.vpnservice.vpn.tunel;


import com.m.w.vpnservice.vpn.ProxyConfig;
import com.m.w.vpnservice.vpn.http.HttpResponse;
import com.m.w.vpnservice.vpn.util.VpnServiceHelper;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;

/**
 * Created by zengzheying on 15/12/29.
 */
public abstract class Tunnel extends NioSslPeer{

	final static ByteBuffer GL_BUFFER = ByteBuffer.allocate(20000);
	public static long SessionCount;
	protected InetSocketAddress mDestAddress;
	protected boolean isRemoteTunnel = false;
	private SocketChannel mInnerChannel; //Own Channel
	private ByteBuffer mSendRemainBuffer; //Send data cache
	private Selector mSelector;
	private HttpResponse mHttpResponse; //
	private boolean isHttpsRequest = false; //Http message
	private String Tag = "AdultBlock_tunnel";
	private Tunnel mBrotherTunnel;
	private boolean mDisposed;
	private InetSocketAddress mServerEP;

	public Tunnel(SocketChannel innerChannel, Selector selector) {
		mInnerChannel = innerChannel;
		mSelector = selector;
		SessionCount++;
	}

	public Tunnel(InetSocketAddress serverAddress, Selector selector) throws IOException {
		SocketChannel innerChannel = SocketChannel.open();
		innerChannel.configureBlocking(false);
		this.mInnerChannel = innerChannel;
		this.mSelector = selector;
		this.mServerEP = serverAddress;
		SessionCount++;
	}

	/**
	 * Method call order:
	 * connect() -> onConnectable() -> onConnected() [subclass implementation]
	 * beginReceived() ->  onReadable() -> afterReceived() [subclass implementation]
	 */

	protected abstract void onConnected(ByteBuffer buffer) throws Exception;

	protected abstract boolean isTunnelEstablished();

	protected abstract void beforeSend(ByteBuffer buffer) throws Exception;

	protected abstract void afterReceived(ByteBuffer buffer) throws Exception;

	protected abstract void onDispose();

	public void setBrotherTunnel(Tunnel brotherTunnel) {
		this.mBrotherTunnel = brotherTunnel;
	}


	public void connect(InetSocketAddress destAddress) throws Exception {
		if (VpnServiceHelper.protect(mInnerChannel.socket())) { //Protect the socket from the VPN
			mDestAddress = destAddress;
			mInnerChannel.register(mSelector, SelectionKey.OP_CONNECT, this); //Register connection event
			mInnerChannel.connect(mServerEP);
		} else {
			throw new Exception("VPN protect socket failed.");
		}
	}

	public void onConnectable() {
		try {
			if (mInnerChannel.finishConnect()) {
				onConnected(GL_BUFFER); //Notify the subclass TCP that it is connected, and the subclass can implement handshake according to the protocol.
			} else {
				this.dispose();
			}
		} catch (Exception e) {
			this.dispose();
		}
	}

	protected void beginReceived() throws Exception {
		if (mInnerChannel.isBlocking()) {
			mInnerChannel.configureBlocking(false);
		}
		mInnerChannel.register(mSelector, SelectionKey.OP_READ, this); //Registered read event
	}

	public void onReadable(SelectionKey key) {
		try {
			ByteBuffer buffer = GL_BUFFER;
			buffer.clear();
			int bytesRead = mInnerChannel.read(buffer);
			if (bytesRead > 0) {
				buffer.flip();
				//Let the subclass first, such as decrypting data
				afterReceived(buffer);

				sendToBrother(key, buffer);

			} else if (bytesRead < 0) {

				this.dispose();
			}
		} catch (Exception ex) {
			this.dispose();
		}
	}


	protected void sendToBrother(SelectionKey key, ByteBuffer buffer) throws Exception {
		if (isTunnelEstablished() && buffer.hasRemaining()) { //Forward the read data to the brother
			mBrotherTunnel.beforeSend(buffer); //Before sending, let the subclass handle it, such as encryption.
			if (!mBrotherTunnel.write(buffer, true)) {
				key.cancel(); //If the brother can't eat, cancel the read event.
			}
		}
	}

	protected boolean write(ByteBuffer buffer, boolean copyRemainData) throws Exception {
		int byteSent;
		while (buffer.hasRemaining()) {
			byteSent = mInnerChannel.write(buffer);
			if (byteSent == 0) {
				break; //Can't send again, terminate the loop
			}
		}
		if (buffer.hasRemaining()) { //Data has not been sent
			if (copyRemainData) { //Copy the remaining data, then listen for write events, write when writable
				//Copy remaining data
				if (mSendRemainBuffer == null) {
					mSendRemainBuffer = ByteBuffer.allocate(buffer.capacity());
				}
				mSendRemainBuffer.clear();
				mSendRemainBuffer.put(buffer);
				mSendRemainBuffer.flip();
				mInnerChannel.register(mSelector, SelectionKey.OP_WRITE, this); //Registered write event
			}
			return false;
		} else { //Sent finished
			return true;
		}
	}


	public void onWritable(SelectionKey key) {
		try {
			this.beforeSend(mSendRemainBuffer); //Before sending, let the subclass handle it, such as encryption, etc.
			if (this.write(mSendRemainBuffer, false)) { //If the remaining data has been sent
				key.cancel();
				if (isTunnelEstablished()) {
					mBrotherTunnel.beginReceived(); //After the data is sent, the brother can be notified to receive the data.
				} else {
					this.beginReceived(); //Start accepting response data from the proxy server
				}
			}
		} catch (Exception ex) {
			this.dispose();
		}
	}

	protected void onTunnelEstablished() throws Exception {
		this.beginReceived(); //Start receiving data
		mBrotherTunnel.beginReceived(); //Brothers are also starting to receive data.
	}

	public void dispose() {
		disposeInternal(true);
	}

	void disposeInternal(boolean disposeBrother) {
		if (!mDisposed) {
			try {
				mInnerChannel.close();
			} catch (Exception ex) {

			}

			if (mBrotherTunnel != null && disposeBrother) {
				mBrotherTunnel.disposeInternal(false); //Released the resources of the brothers
			}

			mInnerChannel = null;
			mSendRemainBuffer = null;
			mSelector = null;
			mBrotherTunnel = null;
			mHttpResponse = null;
			mDisposed = true;
			SessionCount--;

			onDispose();
		}
	}

	public void setIsHttpsRequest(boolean isHttpsRequest) {
		this.isHttpsRequest = isHttpsRequest;
	}

	public boolean isHttpsRequest() {
		return isHttpsRequest;
	}

	public void sendBlockInformation() throws IOException {
		ByteBuffer buffer = ProxyConfig.Instance.getBlockingInfo();
		mInnerChannel.write(buffer);
	}
}
