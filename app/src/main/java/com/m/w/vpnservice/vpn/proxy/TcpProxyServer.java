package com.m.w.vpnservice.vpn.proxy;

import android.content.Context;

import com.m.w.vpnservice.vpn.ProxyConfig;
import com.m.w.vpnservice.vpn.nat.NatSession;
import com.m.w.vpnservice.vpn.nat.NatSessionManager;
import com.m.w.vpnservice.vpn.tunel.Tunnel;
import com.m.w.vpnservice.vpn.tunel.TunnelFactory;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.util.Iterator;

/**
 * Created by zengzheying on 15/12/30.
 * Tun <-> LocalChannel (Host Cert) <-> RemoteChannel (Client Cert) <-> Server
 */
public class TcpProxyServer implements Runnable {

	public boolean Stopped;
	public short Port;

	Selector mSelector;
	ServerSocketChannel mServerSocketChannel;
	Thread mServerThread;
	String Tag = "AdultBlock_TCPProxyServer";
	Context context;

	public TcpProxyServer(int port, Context ctx) throws IOException {
	    context = ctx;
		mSelector = Selector.open();
		mServerSocketChannel = ServerSocketChannel.open();
		mServerSocketChannel.configureBlocking(false);
		mServerSocketChannel.socket().bind(new InetSocketAddress(port));
		mServerSocketChannel.register(mSelector, SelectionKey.OP_ACCEPT);
		this.Port = (short) mServerSocketChannel.socket().getLocalPort();

	}

	/**
	 * Start the TcpProxyServer thread
	 */
	public void start() {
		mServerThread = new Thread(this, "TcpProxyServerThread");
		mServerThread.start();
	}

	public void stop() {
		this.Stopped = true;
		if (mSelector != null) {
			try {
				mSelector.close();
				mSelector = null;
			} catch (Exception ex) {

			}
		}

		if (mServerSocketChannel != null) {
			try {
				mServerSocketChannel.close();
				mServerSocketChannel = null;
			} catch (Exception ex) {

			}
		}
	}


	@Override
	public void run() {
		try {
			while (true) {
				mSelector.select();
				Iterator<SelectionKey> keyIterator = mSelector.selectedKeys().iterator();
				while (keyIterator.hasNext()) {
					SelectionKey key = keyIterator.next();
					if (key.isValid()) {
						try {
							if (key.isAcceptable()) {
								// Принимаем соединение
								onAccepted();
							}else if (key.isConnectable()) {
								// Устанавливаем соединение
								((Tunnel) key.attachment()).onConnectable();
							}else if (key.isReadable()) {
								// Читаем данные
								((Tunnel) key.attachment()).onReadable(key);
							} else if (key.isWritable()) {
								// Пишем данные
								((Tunnel) key.attachment()).onWritable(key);
							}
						} catch (Exception ex) {

						}
					}
					keyIterator.remove();
				}

			}
		} catch (Exception e) {

		} finally {
			this.stop();
		}
	}

	InetSocketAddress getDestAddress(SocketChannel localChannel) {
		short portKey = (short) localChannel.socket().getPort();
		NatSession session = NatSessionManager.getSession(portKey);
		if (session != null) {
			if (ProxyConfig.Instance.needProxy(session.RemoteHost, session.RemoteIP)) {
				//TODO Complete with specific interception strategy? ? ?

				return null;
			} else {
				return new InetSocketAddress(localChannel.socket().getInetAddress(), session.RemotePort & 0xFFFF);
			}
		}
		return null;
	}
	public interface isBlockingComplete {
		void processFinish(int result, Tunnel tunnel, SocketChannel localChannel);
	}

	void onAccepted() {
		Tunnel localTunnel = null;
		try {
			SocketChannel localChannel = mServerSocketChannel.accept();
			localTunnel = TunnelFactory.wrap(localChannel, mSelector);

			InetSocketAddress destAddress = getDestAddress(localChannel);
			if (destAddress != null) {
				Tunnel remoteTunnel = TunnelFactory.createTunnelByConfig(destAddress, mSelector);
				remoteTunnel.setIsHttpsRequest(localTunnel.isHttpsRequest());
				remoteTunnel.setBrotherTunnel(localTunnel);
				localTunnel.setBrotherTunnel(remoteTunnel);
				remoteTunnel.connect(destAddress); //Start connecting
			} else {
				short portKey = (short) localChannel.socket().getPort();
				NatSession session = NatSessionManager.getSession(portKey);
				if (session != null) {
					localTunnel.sendBlockInformation();
				}

				localTunnel.dispose();
			}
		} catch (Exception ex) {
			if (localTunnel != null) {
				localTunnel.dispose();
			}
		}
	}
}
