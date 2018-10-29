package com.m.w.vpnservice.vpn.tunel;

import com.m.w.vpnservice.vpn.nat.NatSession;
import com.m.w.vpnservice.vpn.nat.NatSessionManager;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;

/**
 * Created by zengzheying on 15/12/30.
 */
public class TunnelFactory {

	public static Tunnel wrap(SocketChannel channel, Selector selector) {
		Tunnel tunnel = new RawTunnel(channel, selector);
		NatSession session = NatSessionManager.getSession((short) channel.socket().getPort());
		if (session != null) {
			tunnel.setIsHttpsRequest(session.IsHttpsSession);
		}
		return tunnel;
	}

	public static Tunnel createTunnelByConfig(InetSocketAddress destAddress, Selector selector) throws IOException {
		//TODO Here is just a simple creation of a RawTunnel, in the future you can create different Tunnels based on the type of proxy.
		return new RemoteTunnel(destAddress, selector);
	}
}
