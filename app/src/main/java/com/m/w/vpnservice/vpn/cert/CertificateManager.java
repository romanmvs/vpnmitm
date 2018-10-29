package com.m.w.vpnservice.vpn.cert;

import android.content.Context;
import android.util.Log;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

public class CertificateManager {
    private static String Tag = "AdultBlock_CertManager";
    private static final String CUSTOMER_CERTIFICATE_STORE = "AdultBlockKeyStore.keystore";
    private static final String CUSTOMER_CERTIFICATE_ALIAS = "CR1212121218";
    private static final String CUSTOMER_KS_PASSWORD = "adultblockeet";

    private static final String SERVER_CERTIFICATE_STORE = "AdultBlockCA.keystore";
    private static final String SERVER_CERTIFICATE_ALIAS = "ca";
    private static final String SERVER_KS_PASSWORD = "adultblockeet";

    /**
     * Get Customer's Keystore, containing personal certificate.
     *
     * @param context
     * @return Customer's Keystore
     */
    private static KeyStore getCustomerKeystore(Context context) {
        try {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            // Load Keystore form internal storage
            FileInputStream fis = context.openFileInput(CUSTOMER_CERTIFICATE_STORE);
            keyStore.load(fis, CUSTOMER_KS_PASSWORD.toCharArray());
            return keyStore;
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException("Keystore not found.");
        }
    }

    /**
     * Get customer's certificate for signature.
     *
     * @param context
     * @return Customer's certificate
     */
    public static X509Certificate getCustomersCertificate(Context context) {
        try {
            KeyStore keyStore = getCustomerKeystore(context);

            KeyStore.PrivateKeyEntry keyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(
                    CUSTOMER_CERTIFICATE_ALIAS,
                    new KeyStore.PasswordProtection(CUSTOMER_KS_PASSWORD.toCharArray())
            );

            return (X509Certificate) keyEntry.getCertificate();
        } catch (Exception e) {
            // Keystore not found ask user for uploading his certificate.
            e.printStackTrace();
            throw new RuntimeException("Wrong KeyStore");
        }
    }

    /**
     * Get customer's PrivateKey for encryption.
     *
     * @param context
     * @return customer's PrivateKey
     */
    public static PrivateKey getCustomersPrivateKey(Context context) {
        try {
            KeyStore keyStore = getCustomerKeystore(context);

            //return customer's certificate
            return (PrivateKey) keyStore.getKey(CUSTOMER_CERTIFICATE_ALIAS, CUSTOMER_KS_PASSWORD.toCharArray());
        } catch (Exception e) {

            e.printStackTrace();
            throw new RuntimeException("Wrong KeyStore");
        }
    }

    /**
     * Loads Customer .p12 or .pfx certificate to keystore with password to Internal Storage
     *
     * @param context
     * @return customer's PrivateKey
     */
    public static void loadCustomerCertificate(Context context, InputStream inputStream) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("pkcs12");
        keyStore.load(inputStream, CUSTOMER_KS_PASSWORD.toCharArray());

        //Save KeyStore in Internal Storage
        FileOutputStream fos = context.openFileOutput(CUSTOMER_CERTIFICATE_STORE, Context.MODE_PRIVATE);
        keyStore.store(fos, CUSTOMER_KS_PASSWORD.toCharArray());
        fos.close();
    }

    /**
     * Server certificate for SLL communication
     *
     * @param context
     * @return HTTPS TrustStore
     */
    public static KeyStore getServerKeystore(Context context) {
        try {
            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());

            // Load Keystore form internal storage
            FileInputStream fis = context.openFileInput(SERVER_CERTIFICATE_STORE);
            keyStore.load(fis, null);
            return keyStore;
        } catch (Exception e) {
            return null;
        }
    }


    public static KeyStore saveServerKeystore(Context context, X509Certificate ca) throws Exception {

        // Create a KeyStore containing our trusted CAs
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(null, null);
        keyStore.setCertificateEntry(SERVER_CERTIFICATE_ALIAS, ca);

        // Save keystore to Internal Storage.
        FileOutputStream fos = context.openFileOutput(SERVER_CERTIFICATE_STORE, Context.MODE_PRIVATE);
        keyStore.store(fos, null);
        fos.close();

        return keyStore;
    }
}