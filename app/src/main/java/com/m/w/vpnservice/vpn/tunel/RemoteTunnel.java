package com.m.w.vpnservice.vpn.tunel;

import android.util.Log;

import com.m.w.vpnservice.vpn.util.Utils;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;

/**
 * Created by zengzheying on 15/12/31.
 */
public class RemoteTunnel extends RawTunnel {
	private String Tag = "AdultBlock_RemoteTunnel";
	public RemoteTunnel(SocketChannel innerChannel, Selector selector) {
		super(innerChannel, selector);
		isRemoteTunnel = true;
	}

	public RemoteTunnel(InetSocketAddress serverAddress, Selector selector) throws IOException {
		super(serverAddress, selector);
		isRemoteTunnel = true;
	}
	@Override
	protected void beforeSend(ByteBuffer buffer) throws Exception {
		//To site
		super.beforeSend(buffer);
	}

	@Override
	protected void afterReceived(ByteBuffer buffer) throws Exception {
		super.afterReceived(buffer);
	}
}
