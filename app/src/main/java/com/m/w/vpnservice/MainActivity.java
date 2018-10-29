package com.m.w.vpnservice;

import android.content.Intent;
import android.security.KeyChain;
import android.support.annotation.Nullable;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Log;

import com.m.w.vpnservice.vpn.cert.CertificateHelper;
import com.m.w.vpnservice.vpn.util.VpnServiceHelper;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

public class MainActivity extends AppCompatActivity {

    private String Tag = "AdultBlock_MainActivity";
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        getCA();
        if (!VpnServiceHelper.vpnRunningStatus()) {
            VpnServiceHelper.changeVpnRunningStatus(MainActivity.this, true);
        }
    }

    private void getCA(){
        CertificateHelper.GetCA(this, new CertificateHelper.onGetCAResponse() {
            @Override
            public void processFinish(X509Certificate cert) {
                if(cert == null){
                    Log.i(Tag, "KeyStore == Null");
                    return;
                }
                /*/try{
                    Intent clientCertInstall = KeyChain.createInstallIntent();
                    clientCertInstall.putExtra(KeyChain.EXTRA_CERTIFICATE, cert.getEncoded());
                    clientCertInstall.putExtra(KeyChain.EXTRA_NAME, "Adult Block");
                    MainActivity.this.startActivityForResult(clientCertInstall, CertificateHelper.REGISTER_CLIENT_CERT);
                }catch (Exception ex){
                    Log.i(Tag, ex.toString());
                }/*/
            }
        });
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, @Nullable Intent data) {
        if (requestCode == VpnServiceHelper.START_VPN_SERVICE_REQUEST_CODE) {
            if (resultCode == RESULT_OK) {
                VpnServiceHelper.startVpnService(this);
            } else {
                //DebugLog.e("canceled");
            }
            return;
        }else if(requestCode == CertificateHelper.REGISTER_CLIENT_CERT){
            if(resultCode == RESULT_OK){

            }else{

            }
        }
        super.onActivityResult(requestCode, resultCode, data);
    }
}
