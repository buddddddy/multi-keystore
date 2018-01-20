package org.buddy;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.X509KeyManager;
import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
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
public class MultiKeyStoreManager implements X509KeyManager {

    private static final Logger logger = LoggerFactory.getLogger(MultiKeyStoreManager.class);
    private final Collection<X509KeyManager> keyManagers;

    public MultiKeyStoreManager(X509KeyManager... keyManager) {
        this.keyManagers = new ArrayList<>();
        this.keyManagers.addAll(Arrays.asList(keyManager));
    }

    @Override
    public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
        for (X509KeyManager keyManager : keyManagers) {
            final String clientAlias = keyManager.chooseClientAlias(keyType, issuers, socket);
            if (clientAlias != null) {
                return clientAlias;
            }
        }
        return null;

    }

    @Override
    public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
        for (X509KeyManager keyManager : keyManagers) {
            final String serverAlias = keyManager.chooseServerAlias(keyType, issuers, socket);
            if (serverAlias != null) {
                return serverAlias;
            }
        }
        return null;
    }

    @Override
    public X509Certificate[] getCertificateChain(String alias) {
        for (X509KeyManager keyManager : keyManagers) {
            final X509Certificate[] certificateChain = keyManager.getCertificateChain(alias);
            if (certificateChain != null && certificateChain.length != 0) {
                return certificateChain;
            }
        }
        return null;
    }

    @Override
    public String[] getClientAliases(String keyType, Principal[] issuers) {
        List<String> clientAliases = new ArrayList<>();
        for (X509KeyManager keyManager : keyManagers) {
            clientAliases.addAll(Arrays.asList(keyManager.getClientAliases(keyType, issuers)));
        }
        return (String[]) clientAliases.toArray();
    }

    @Override
    public PrivateKey getPrivateKey(String alias) {
        for (X509KeyManager keyManager : keyManagers) {
            final PrivateKey privateKey = keyManager.getPrivateKey(alias);
            if (privateKey != null) {
                return privateKey;
            }
        }
        return null;
    }

    @Override
    public String[] getServerAliases(String keyType, Principal[] issuers) {
        List<String> serverAliases = new ArrayList<>();
        for (X509KeyManager keyManager : keyManagers) {
            serverAliases.addAll(Arrays.asList(keyManager.getServerAliases(keyType, issuers)));
        }
        return (String[]) serverAliases.toArray();
    }
}
