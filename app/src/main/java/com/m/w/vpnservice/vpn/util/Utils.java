package com.m.w.vpnservice.vpn.util;

import android.util.Log;

import com.google.common.net.InternetDomainName;

import java.net.URL;

public class Utils {

    public static String getStringFromByte(byte[] packetBody){
        StringBuilder s = new StringBuilder(packetBody.length);
        for(int i = 0; i < packetBody.length; i++)
        {
            s.append((char)packetBody[i]);
        }
        return s.toString();
    }

    public static boolean checkValidDomain(String host){
        //InternetDomainName.from("subhost.example.co.uk").topPrivateDomain().name
        String sub = getSubdomain(host);
        if(sub.equals(""))
            return true;
        if(sub.equals("error")) return false;
        return sub.matches ("[a-zA-Z]+");
    }

    //porno365.xxx
    //1porno.online Error

    public static String getRootUrl(String site, boolean withProtocol){
        try {
            URL url = new URL(site);
            String protocol = url.getProtocol();
            String host = url.getHost();
            String baseDomain = InternetDomainName.from(host).topDomainUnderRegistrySuffix().toString();
            if(withProtocol)
                return protocol+"://"+baseDomain;
            else
                return baseDomain;
        }catch (Exception ex){}
        return "";
    }

    public static String getSubdomain(String host) {
        try {
            String domain = InternetDomainName.from(host).topPrivateDomain().toString();
            String subDomain = host.replaceAll(domain, "");
            String sd = subDomain.replaceAll("\\.", "");
            return sd;
        }catch (Exception ex){}
        return "error";
    }
}
