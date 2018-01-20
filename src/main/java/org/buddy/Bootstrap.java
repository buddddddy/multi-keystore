package org.buddy;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.*;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Properties;

/**
 * Short description text.
 * <p>
 * Long detailed description text for the specific class file.
 *
 * @author SSukhanov
 * @version 20.01.2018
 * @package org.buddy
 */
public class Bootstrap {

    private static final Logger logger = LoggerFactory.getLogger(Bootstrap.class);

    public static void main(String[] args) throws Exception {
        // load properties
        Properties properties = new Properties();
        properties.load(Bootstrap.class.getClassLoader().getResourceAsStream("app.properties"));

        initializeManagers(properties);
    }


    private static KeyManager[] getKeyManagers(Properties props) throws IOException, GeneralSecurityException {
        String alg = KeyManagerFactory.getDefaultAlgorithm();
        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(alg);

        int i = 1;
        List<X509KeyManager> x509KeyManagers = new ArrayList<>();
        while (true) {
            final String keyStoreProperty = props.getProperty("keystore." + i);
            if (keyStoreProperty != null) {
                FileInputStream fis = new FileInputStream(Bootstrap.class.getClassLoader().getResource(keyStoreProperty).getFile());
                logger.info("Loaded keystore");
                KeyStore keyStore = KeyStore.getInstance("jks");
                String keyStorePassword = props.getProperty("keystore.password." + i);
                keyStore.load(fis, keyStorePassword.toCharArray());
                fis.close();

                Enumeration enumeration = keyStore.aliases();
                while (enumeration.hasMoreElements()) {
                    String alias = (String) enumeration.nextElement();
                    System.out.println("alias name: " + alias);
                }

                keyManagerFactory.init(keyStore, keyStorePassword.toCharArray());
                X509KeyManager x509KeyManager = getX509KeyManager(alg, keyManagerFactory);
                x509KeyManagers.add(x509KeyManager);
            } else break;
            i++;
        }

        KeyManager[] km = {new MultiKeyStoreManager(x509KeyManagers.toArray(new X509KeyManager[x509KeyManagers.size()]))};
        logger.debug("Number of key managers registered:" + km.length);
        return km;
    }

    private static TrustManager[] getTrustManagers(Properties props) throws IOException, GeneralSecurityException {
        String alg = TrustManagerFactory.getDefaultAlgorithm();
        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(alg);

        int i = 1;
        List<X509TrustManager> x509TrustManagers = new ArrayList<>();
        while (true) {
            String trustStoreProperty = props.getProperty("truststore." + i);
            if (trustStoreProperty != null) {
                FileInputStream fis = null;
                if (trustStoreProperty.equals("cacerts")) {
                    trustStoreProperty = System.getProperty("java.home") + "/lib/security/cacerts".replace('/', File.separatorChar);
                    fis = new FileInputStream(trustStoreProperty);
                } else {
                    fis = new FileInputStream(Bootstrap.class.getClassLoader().getResource(trustStoreProperty).getFile());
                }

                logger.info("Loaded keystore");
                KeyStore trustStore = KeyStore.getInstance("jks");
                String trustStorePassword = props.getProperty("truststore.password." + i);
                trustStore.load(fis, trustStorePassword.toCharArray());
                fis.close();

                Enumeration enumeration = trustStore.aliases();
                while (enumeration.hasMoreElements()) {
                    String alias = (String) enumeration.nextElement();
                    System.out.println("alias name: " + alias);
                }

                trustManagerFactory.init(trustStore);
                X509TrustManager x509TrustManager = getX509TrustManager(alg, trustManagerFactory);
                x509TrustManagers.add(x509TrustManager);
            } else break;
            i++;
        }

        TrustManager[] km = {new MultiTrustStoreManager(x509TrustManagers.toArray(new X509TrustManager[x509TrustManagers.size()]))};
        logger.debug("Number of key managers registered:" + km.length);
        return km;
    }

    private static X509TrustManager getX509TrustManager(String algorithm, TrustManagerFactory kmFact) throws NoSuchAlgorithmException {
        TrustManager[] keyManagers = kmFact.getTrustManagers();

        if (keyManagers == null || keyManagers.length == 0) {
            throw new NoSuchAlgorithmException("The default algorithm :" + algorithm + " produced no key managers");
        }

        X509TrustManager x509TrustManager = null;

        for (TrustManager keyManager : keyManagers) {
            if (keyManager instanceof X509TrustManager) {
                x509TrustManager = (X509TrustManager) keyManager;
                break;
            }
        }

        if (x509TrustManager == null) {
            throw new NoSuchAlgorithmException("The default algorithm :" + algorithm + " did not produce a X509 Key manager");
        }
        return x509TrustManager;
    }

    private static X509KeyManager getX509KeyManager(String algorithm, KeyManagerFactory kmFact) throws NoSuchAlgorithmException {
        KeyManager[] keyManagers = kmFact.getKeyManagers();

        if (keyManagers == null || keyManagers.length == 0) {
            throw new NoSuchAlgorithmException("The default algorithm :" + algorithm + " produced no key managers");
        }

        X509KeyManager x509KeyManager = null;

        for (KeyManager keyManager : keyManagers) {
            if (keyManager instanceof X509KeyManager) {
                x509KeyManager = (X509KeyManager) keyManager;
                break;
            }
        }

        if (x509KeyManager == null) {
            throw new NoSuchAlgorithmException("The default algorithm :" + algorithm + " did not produce a X509 Key manager");
        }
        return x509KeyManager;
    }


    private static void initializeManagers(Properties props) throws IOException, GeneralSecurityException {
        SSLContext context = SSLContext.getInstance("SSL");
        context.init(getKeyManagers(props), getTrustManagers(props), null);
        SSLContext.setDefault(context);
    }
}
