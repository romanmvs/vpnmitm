package com.m.w.vpnservice.vpn.service;

import android.app.PendingIntent;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.net.VpnService;
import android.os.Handler;
import android.os.ParcelFileDescriptor;
import android.util.Log;

import com.m.w.vpnservice.MainActivity;
import com.m.w.vpnservice.vpn.ProxyConfig;
import com.m.w.vpnservice.vpn.builder.DefaultBlockingInfoBuilder;
import com.m.w.vpnservice.vpn.dns.DnsPacket;
import com.m.w.vpnservice.vpn.filter.BlackListFilter;
import com.m.w.vpnservice.vpn.http.HttpRequestHeaderParser;
import com.m.w.vpnservice.vpn.nat.NatSession;
import com.m.w.vpnservice.vpn.nat.NatSessionManager;
import com.m.w.vpnservice.vpn.proxy.DnsProxy;
import com.m.w.vpnservice.vpn.proxy.TcpProxyServer;
import com.m.w.vpnservice.vpn.tcpip.CommonMethods;
import com.m.w.vpnservice.vpn.tcpip.IPHeader;
import com.m.w.vpnservice.vpn.tcpip.TCPHeader;
import com.m.w.vpnservice.vpn.tcpip.UDPHeader;
import com.m.w.vpnservice.vpn.util.Utils;
import com.m.w.vpnservice.vpn.util.VpnServiceHelper;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.lang.reflect.Method;
import java.nio.ByteBuffer;
import java.util.ArrayList;


/**
 * Created by zengzheying on 15/12/28.
 */
public class FirewallVpnService extends VpnService implements Runnable {

	private static int ID;
	private static int LOCAL_IP;
	private boolean IsRunning = false;
	private Thread mVPNThread;
	private ParcelFileDescriptor mVPNInterface;
	private TcpProxyServer mTcpProxyServer;
	private DnsProxy mDnsProxy;
	private String Tag = "AdultBlock_VpnService";
	private FileOutputStream mVPNOutputStream;

	private byte[] mPacket;
	private IPHeader mIPHeader;
	private TCPHeader mTCPHeader;
	private UDPHeader mUDPHeader;
	private ByteBuffer mDNSBuffer;
	private Handler mHandler;
	private long mSentBytes;
	private long mReceivedBytes;

	public FirewallVpnService() {
		ID++;
		mHandler = new Handler();
		mPacket = new byte[20000];
		mIPHeader = new IPHeader(mPacket, 0);
		//Offset = ip报文头部长度
		mTCPHeader = new TCPHeader(mPacket, 20);
		mUDPHeader = new UDPHeader(mPacket, 20);
		//Offset = ip报文头部长度 + udp报文头部长度 = 28
		mDNSBuffer = ((ByteBuffer) ByteBuffer.wrap(mPacket).position(28)).slice();

		VpnServiceHelper.onVpnServiceCreated(this);

	}

	//启动Vpn工作线程
	@Override
	public void onCreate() {
		mVPNThread = new Thread(this, "VPNServiceThread");
		mVPNThread.start();
		setVpnRunningStatus(true);
		//notifyStatus(new VPNEvent(VPNEvent.Status.STARTING));
		super.onCreate();
	}

	//只设置IsRunning = true;
	@Override
	public int onStartCommand(Intent intent, int flags, int startId) {
		return super.onStartCommand(intent, flags, startId);
	}

	//停止Vpn工作线程
	@Override
	public void onDestroy() {
		if (mVPNThread != null) {
			mVPNThread.interrupt();
		}
		VpnServiceHelper.onVpnServiceDestroy();
		super.onDestroy();
	}

	//发送UDP数据报
	public void sendUDPPacket(IPHeader ipHeader, UDPHeader udpHeader) {
		try {
			CommonMethods.ComputeUDPChecksum(ipHeader, udpHeader);
			this.mVPNOutputStream.write(ipHeader.mData, ipHeader.mOffset, ipHeader.getTotalLength());
		} catch (IOException e) {

		}
	}

	//Establish a VPN and listen for outgoing traffic
	private void runVPN() throws Exception {
		this.mVPNInterface = establishVPN();
		this.mVPNOutputStream = new FileOutputStream(mVPNInterface.getFileDescriptor());
		FileInputStream in = new FileInputStream(mVPNInterface.getFileDescriptor());
		int size = 0;
		while (size != -1 && IsRunning) {
			while ((size = in.read(mPacket)) > 0 && IsRunning) {
				if (mDnsProxy.Stopped || mTcpProxyServer.Stopped) {
					in.close();
					throw new Exception("LocalServer stopped.");
				}
				//get packet with in
				//put packet to tunnel
				//get packet form tunnel
				//return packet with out
				//sleep is a must
				onIPPacketReceived(mIPHeader, size);
			}
			Thread.sleep(100);
		}
		in.close();
		disconnectVPN();
	}

	void onIPPacketReceived(IPHeader ipHeader, int size) throws IOException {

		switch (ipHeader.getProtocol()) {
			case IPHeader.TCP:
				TCPHeader tcpHeader = mTCPHeader;
				tcpHeader.mOffset = ipHeader.getHeaderLength(); //Correct the offset in TCPHeader to point to the actual TCP data address
				if (tcpHeader.getSourcePort() == mTcpProxyServer.Port) {

					NatSession session = NatSessionManager.getSession(tcpHeader.getDestinationPort());
					if (session != null) {
						ipHeader.setSourceIP(ipHeader.getDestinationIP());
						tcpHeader.setSourcePort(session.RemotePort);
						ipHeader.setDestinationIP(LOCAL_IP);

						CommonMethods.ComputeTCPChecksum(ipHeader, tcpHeader);
						mVPNOutputStream.write(ipHeader.mData, ipHeader.mOffset, size);
						mReceivedBytes += size;
					}

				} else {

					//Add port mapping
					int portKey = tcpHeader.getSourcePort();
					NatSession session = NatSessionManager.getSession(portKey);
					if (session == null || session.RemoteIP != ipHeader.getDestinationIP() || session.RemotePort != tcpHeader.getDestinationPort()) {
						session = NatSessionManager.createSession(portKey, ipHeader.getDestinationIP(), tcpHeader
								.getDestinationPort());
					}

					session.LastNanoTime = System.nanoTime();
					session.PacketSent++; //Note order

					int tcpDataSize = ipHeader.getDataLength() - tcpHeader.getHeaderLength();
					if (session.PacketSent == 2 && tcpDataSize == 0) {
						return; //Discard the second ACK packet of the tcp handshake. Because the client will also send an ACK when sending data, this can analyze the HOST information before the server Accept.
					}

					//Analyze the data and find the host
					if (session.BytesSent == 0 && tcpDataSize > 10) {
						int dataOffset = tcpHeader.mOffset + tcpHeader.getHeaderLength();
						HttpRequestHeaderParser.parseHttpRequestHeader(session, tcpHeader.mData, dataOffset,
								tcpDataSize);
						//Log.i(Tag, session.RemoteHost);
					}
					//Forward to local TCP server
					ipHeader.setSourceIP(ipHeader.getDestinationIP());
					ipHeader.setDestinationIP(LOCAL_IP);
					tcpHeader.setDestinationPort(mTcpProxyServer.Port);

					CommonMethods.ComputeTCPChecksum(ipHeader, tcpHeader);
					mVPNOutputStream.write(ipHeader.mData, ipHeader.mOffset, size);
					session.BytesSent += tcpDataSize; //Note order
					mSentBytes += size;
				}
				break;
			case IPHeader.UDP:
				UDPHeader udpHeader = mUDPHeader;
				udpHeader.mOffset = ipHeader.getHeaderLength();
				if (ipHeader.getSourceIP() == LOCAL_IP && udpHeader.getDestinationPort() == 53) {
					mDNSBuffer.clear();
					mDNSBuffer.limit(udpHeader.getTotalLength() - 8);
					DnsPacket dnsPacket = DnsPacket.fromBytes(mDNSBuffer);
					if (dnsPacket != null && dnsPacket.Header.QuestionCount > 0) {
						mDnsProxy.onDnsRequestReceived(ipHeader, udpHeader, dnsPacket);
					}
				}
				break;
		}

	}

	private void waitUntilPrepared() {
		while (prepare(this) != null) {
			try {
				Thread.sleep(100);
			} catch (InterruptedException e) {

			}
		}
	}

	private ParcelFileDescriptor establishVPN() throws Exception {
		Builder builder = new Builder();
		//builder.setMtu(ProxyConfig.Instance.getMTU());

		ProxyConfig.IPAddress ipAddress = ProxyConfig.Instance.getDefaultLocalIP();
		LOCAL_IP = CommonMethods.ipStringToInt(ipAddress.Address);
		builder.addAddress(ipAddress.Address, ipAddress.PrefixLength);

        builder.addRoute("0.0.0.0", 0);
		/*/Intent intent = new Intent(this, MainActivity.class);
		PendingIntent pendingIntent = PendingIntent.getActivity(this, 0, intent, 0);
		builder.setConfigureIntent(pendingIntent);/*/
		builder.setSession("Easy Firewall");
		builder.allowBypass();
		ParcelFileDescriptor pfdDescriptor = builder.establish();
		//notifyStatus(new VPNEvent(VPNEvent.Status.ESTABLISHED));
		return pfdDescriptor;
	}

	@Override
	public void run() {
		try {

			waitUntilPrepared();

			ProxyConfig.Instance.setDomainFilter(new BlackListFilter());
			ProxyConfig.Instance.setBlockingInfoBuilder(new DefaultBlockingInfoBuilder());
			ProxyConfig.Instance.prepare();

			//启动TCP代理服务
			//StopWords.LoadWords(this);
			mTcpProxyServer = new TcpProxyServer(0, this);
			mTcpProxyServer.start();

			mDnsProxy = new DnsProxy();
			mDnsProxy.start();


			ProxyConfig.Instance.onVpnStart(this);
			while (IsRunning) {
				runVPN();
			}
			ProxyConfig.Instance.onVpnEnd(this);

		} catch (InterruptedException e) {

		} catch (Exception e) {


		} finally {

			dispose();
		}
	}

	public void disconnectVPN() {
		try {
			if (mVPNInterface != null) {
				mVPNInterface.close();
				mVPNInterface = null;
			}
		} catch (Exception e) {
			//ignore
		}
		//notifyStatus(new VPNEvent(VPNEvent.Status.UNESTABLISHED));
		this.mVPNOutputStream = null;
	}

	private synchronized void dispose() {
		//断开VPN
		disconnectVPN();

		//停止TCP代理服务
		if (mTcpProxyServer != null) {
			mTcpProxyServer.stop();
			mTcpProxyServer = null;
		}

		if (mDnsProxy != null) {
			mDnsProxy.stop();
			mDnsProxy = null;
		}

		stopSelf();
		setVpnRunningStatus(false);
//		System.exit(0);
	}

	/*/private void notifyStatus(VPNEvent event) {
		EventBus.getDefault().post(event);
	}/*/

	public boolean vpnRunningStatus() {
		return IsRunning;
	}

	public void setVpnRunningStatus(boolean isRunning) {
		IsRunning = isRunning;
	}
}
