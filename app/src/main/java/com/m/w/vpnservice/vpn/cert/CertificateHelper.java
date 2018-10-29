package com.m.w.vpnservice.vpn.cert;

import android.content.Context;
import android.util.Log;

import com.m.w.vpnservice.vpn.util.Utils;

import org.spongycastle.asn1.x500.X500Name;
import org.spongycastle.asn1.x500.X500NameBuilder;
import org.spongycastle.asn1.x500.style.BCStyle;
import org.spongycastle.asn1.x509.AuthorityKeyIdentifier;
import org.spongycastle.asn1.x509.BasicConstraints;
import org.spongycastle.asn1.x509.SubjectPublicKeyInfo;
import org.spongycastle.asn1.x509.X509Extension;
import org.spongycastle.cert.X509CertificateHolder;
import org.spongycastle.cert.X509v1CertificateBuilder;
import org.spongycastle.cert.X509v3CertificateBuilder;
import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.operator.ContentSigner;
import org.spongycastle.operator.OperatorCreationException;
import org.spongycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;
import java.util.Enumeration;
import java.util.Random;

import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

public class CertificateHelper {
    public static String Tag = "AdultBlock_CertGen";
    public static int REGISTER_CLIENT_CERT = 2016;
    public static X509Certificate CaCert;

    public interface onCertificateResponse {
        void processFinish(X509Certificate output);
    }

    public interface onGetCAResponse {
        void processFinish(X509Certificate output);
    }

    public static void GetCA(final Context context, final onGetCAResponse response){
        KeyStore ks = CertificateManager.getServerKeystore(context);
        if(ks == null) {
            GenerateCA(context, new onCertificateResponse() {
                @Override
                public void processFinish(X509Certificate cert) {
                    try {
                        KeyStore ks = CertificateManager.saveServerKeystore(context, cert);
                        CaCert = cert;
                        response.processFinish(cert);
                    }catch (Exception ex){
                        Log.i(Tag, ex.toString());
                        response.processFinish(null);
                    }
                }
            });
        }else{
            try {
                X509Certificate cert = (X509Certificate) ks.getCertificate("ca");
                CaCert = cert;
                response.processFinish(cert);
            }catch (KeyStoreException ex){
                Log.i(Tag, ex.toString());
                response.processFinish(null);
            }

        }
    }

    public static void GenerateCA(final Context context, final onCertificateResponse response){

        new Thread(new Runnable() {
            public void run() {
                try {

                    KeyPairGenerator rsa = KeyPairGenerator.getInstance("RSA");
                    rsa.initialize(1024);
                    KeyPair kp = rsa.generateKeyPair();

                    Calendar cal = Calendar.getInstance();
                    cal.add(Calendar.YEAR, 1000);

                    byte[] pk = kp.getPublic().getEncoded();
                    SubjectPublicKeyInfo bcPk = SubjectPublicKeyInfo.getInstance(pk);
                    X509v3CertificateBuilder certGen = new X509v3CertificateBuilder(
                            new X500Name("CN=AdultBlock Root CA v1"), //CN=AdultBlock Root CA v1
                            BigInteger.ONE,
                            new Date(),
                            cal.getTime(),
                            new X500Name("CN=AdultBlock Root CA v1"), //CN=AdultBlock Root CA v1
                            bcPk
                    );
                    certGen.addExtension(X509Extension.basicConstraints,
                            false,
                            new BasicConstraints(true));

                    X509CertificateHolder certHolder = certGen
                            .build(new JcaContentSignerBuilder("SHA1withRSA").build(kp.getPrivate()));

                    InputStream in = new ByteArrayInputStream(certHolder.getEncoded());

                    CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
                    X509Certificate cert = (X509Certificate) certFactory.generateCertificate(in);
                    in.close();

                    response.processFinish(cert);
                }catch (Exception ex){
                    Log.i(Tag, ex.toString());
                    response.processFinish(null);
                }

            }
        }).start();
    }

    public static void GenerateCert(final Context context, String host, X509Certificate ca, final onCertificateResponse response){
        new Thread(new Runnable() {
            public void run() {
                try {

                    KeyPairGenerator rsa = KeyPairGenerator.getInstance("RSA");
                    rsa.initialize(1024);
                    KeyPair kp = rsa.generateKeyPair();
                    Calendar cal = Calendar.getInstance();
                    cal.add(Calendar.YEAR, 1);

                    byte[] pk = kp.getPublic().getEncoded();
                    SubjectPublicKeyInfo bcPk = SubjectPublicKeyInfo.getInstance(pk);
                    X509v3CertificateBuilder certGen = new X509v3CertificateBuilder(
                            new X500Name("CN=AdultBlock Root CA v1"), //CN=AdultBlock Root CA v1
                            BigInteger.ONE,
                            new Date(),
                            cal.getTime(),
                            new X500Name("CN=AdultBlock Root CA v1"), //CN=AdultBlock Root CA v1
                            bcPk
                    );

                    certGen.addExtension(X509Extension.basicConstraints,
                            false,
                            new BasicConstraints(true));

                    X509CertificateHolder certHolder = certGen
                            .build(new JcaContentSignerBuilder("SHA1withRSA").build(kp.getPrivate()));

                    InputStream in = new ByteArrayInputStream(certHolder.getEncoded());

                    CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
                    X509Certificate cert = (X509Certificate) certFactory.generateCertificate(in);
                    in.close();

                    response.processFinish(cert);

                }catch (CertificateException ex){
                    Log.i(Tag, ex.toString());
                    response.processFinish(null);
                }catch (IOException ex){
                    Log.i(Tag, ex.toString());
                    response.processFinish(null);
                }catch (OperatorCreationException ex){
                    Log.i(Tag, ex.toString());
                    response.processFinish(null);
                }catch (NoSuchAlgorithmException ex){
                    Log.i(Tag, ex.toString());
                    response.processFinish(null);
                }

            }
        }).start();
    }

    public static boolean isCertificateTrusted(Certificate[] ca) {
        try {
            X509Certificate[] cert = (X509Certificate[]) ca;
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init((KeyStore) null);
            TrustManager[] tms = tmf.getTrustManagers();
            X509TrustManager tm = (X509TrustManager)tms[0];
            tm.checkClientTrusted(cert, "RSA"); // throws CertificateException on error
        }catch (Exception ex){
            Log.i(Tag, "UnTrusted");
            Log.i(Tag, ex.toString());
            return false;
        }
        Log.i(Tag, "Trusted");
        return true;
    }
    public static boolean isCertInstalled(){
        try
        {
            KeyStore ks = KeyStore.getInstance("AndroidCAStore");
            if (ks != null)
            {
                ks.load(null, null);
                Enumeration aliases = ks.aliases();
                while (aliases.hasMoreElements())
                {
                    String alias = (String) aliases.nextElement();
                    java.security.cert.X509Certificate cert = (java.security.cert.X509Certificate) ks.getCertificate(alias);
                    if (cert.getIssuerDN().getName().contains("Adult Block")) {
                        return true;
                    }
                }
            }
            return false;
        } catch (Exception e) {
            Log.i(Tag, e.toString());
            return false;
        }
    }

}
/*/
KeyPairGenerator rsa = KeyPairGenerator.getInstance("RSA");
                    rsa.initialize(1024);
                    KeyPair kp = rsa.generateKeyPair();

                    Calendar cal = Calendar.getInstance();
                    cal.add(Calendar.YEAR, 1000);

                    X500NameBuilder nameBuilder = new X500NameBuilder(BCStyle.INSTANCE);
                    nameBuilder.addRDN(BCStyle.O, "AdultBlock");
                    nameBuilder.addRDN(BCStyle.OU, "LLP");
                    nameBuilder.addRDN(BCStyle.L, "London");
                    X500Name x500Name = nameBuilder.build();
                    Random random = new Random();

                    byte[] pk = kp.getPublic().getEncoded();
                    SubjectPublicKeyInfo bcPk = SubjectPublicKeyInfo.getInstance(pk);

                    X509v3CertificateBuilder certGen = new X509v3CertificateBuilder(
                            x500Name, //CN=AdultBlock Root CA v1
                            BigInteger.valueOf(random.nextLong()),
                            new Date(),
                            cal.getTime(),
                            x500Name, //CN=AdultBlock Root CA v1
                            bcPk
                    );
                    Security.addProvider(new BouncyCastleProvider());
                    ContentSigner sigGen = new JcaContentSignerBuilder("SHA256WithRSAEncryption").setProvider("SC").build(kp.getPrivate());

                    X509CertificateHolder certHolder = certGen.build(sigGen);

                    InputStream in = new ByteArrayInputStream(certHolder.getEncoded());

                    CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
                    X509Certificate cert = (X509Certificate) certFactory.generateCertificate(in);
                    in.close();

 */