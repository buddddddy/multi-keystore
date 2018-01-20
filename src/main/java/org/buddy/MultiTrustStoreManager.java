package org.buddy;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.X509TrustManager;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

/**
 * Short description text.
 * <p>
 * Long detailed description text for the specific class file.
 *
 * @author SSukhanov
 * @version 20.01.2018
 * @package org.buddy
 */
public class MultiTrustStoreManager implements X509TrustManager {

    private static final Logger logger = LoggerFactory.getLogger(MultiTrustStoreManager.class);
    private final Collection<X509TrustManager> trustManagers;

    public MultiTrustStoreManager(X509TrustManager... trustManagers) {
        this.trustManagers = new ArrayList<>();
        this.trustManagers.addAll(Arrays.asList(trustManagers));
    }


    @Override
    public void checkClientTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {
        for (X509TrustManager manager : trustManagers) {
            manager.checkClientTrusted(x509Certificates, s);
        }
    }

    @Override
    public void checkServerTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {
        for (X509TrustManager manager : trustManagers) {
            manager.checkServerTrusted(x509Certificates, s);
        }
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        List<X509Certificate> x509CertificateList = new ArrayList<>();
        for (X509TrustManager manager : trustManagers) {
            x509CertificateList.addAll(Arrays.asList(manager.getAcceptedIssuers()));
        }
        return (X509Certificate[]) x509CertificateList.toArray();
    }
}
