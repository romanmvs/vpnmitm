package com.m.w.vpnservice.vpn.util;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.NetworkRequest;
import android.util.Log;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.ConnectException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.concurrent.TimeUnit;

import javax.net.SocketFactory;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

public class Get {
    private static String Tag = "AdultBlock_GET";
    public interface onApiStringResponse {
        void processFinish(String output);
    }
    public static void Get(final String url, final Context context, final onApiStringResponse listener){
        Log.i(Tag, "HTTP: "+url);
        new Thread(new Runnable() {
            public void run() {
                NetworkRequest.Builder requestbuilder = new NetworkRequest.Builder();
                requestbuilder.addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN);

                ConnectivityManager cm = (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
                cm.requestNetwork(requestbuilder.build(), new ConnectivityManager.NetworkCallback(){
                    @Override
                    public void onAvailable(Network network) {
                        getOkHTTP(url, network.getSocketFactory(), new Get.onApiStringResponse() {
                            @Override
                            public void processFinish(String output) {
                                listener.processFinish(output);
                            }
                        });
                    }
                });
            }
        }).start();


    }


    public static void getOkHTTP(final String url, SocketFactory sf, final onApiStringResponse listener) {
        OkHttpClient okClient = new OkHttpClient().newBuilder()
                .followRedirects(true)
                .followSslRedirects(true)
                .socketFactory(sf)
                .hostnameVerifier(new HostnameVerifier() {
                    @Override
                    public boolean verify(String hostname, SSLSession session) {
                        return true;
                    }
                })
                //.connectTimeout(30, TimeUnit.SECONDS)
                .build();

        Request request = new Request.Builder()
                .url(url)
                .build();

        okClient.newCall(request).enqueue(new Callback() {
            @Override
            public void onFailure(Call call, IOException e) {
                if(e.toString().toLowerCase().contains("unable to resolve host")){
                    listener.processFinish("Error");
                    return;
                }
                Log.i(Tag, url + " " + e.toString());
                listener.processFinish("NError223");
            }

            @Override
            public void onResponse(Call call, Response response) throws IOException {
                listener.processFinish(response.body().string());
            }
        });

    }

}