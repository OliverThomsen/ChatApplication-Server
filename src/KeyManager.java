import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

public class KeyManager {
    String username;
    KeyPair keyPair;
    X509Certificate certificate;

    public KeyManager(String username) throws Exception {
        this.username = username;
        this.keyPair = getKeyPair();
        this.certificate = CertificateAuthority.generateCertificate(username, "", "", "DK", keyPair);

        // Create directory for user to store keys
        Path path = Paths.get(username);
        Files.createDirectories(path);

        storeCertificate(certificate);
        accessCertificate(username+"KeyStore.jks", "password", "password", username);
    }

    public void storeCertificate(X509Certificate certificate) throws Exception {
        X509Certificate[] chain = {certificate};
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(null, null);
        keyStore.setKeyEntry(username, keyPair.getPrivate(), "password".toCharArray(), chain);

        FileOutputStream fos = new FileOutputStream(username + "/" + username + "KeyStore.jks");
        keyStore.store(fos, "password".toCharArray());
    }

    public static KeyPair getKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        return kpg.generateKeyPair();
    }

    public X509Certificate retrieveCertificate(String path) throws Exception {
        FileInputStream fr = new FileInputStream(path);
        CertificateFactory cf = CertificateFactory.getInstance("X509");
        return (X509Certificate) cf.generateCertificate(fr);
    }

    public void accessCertificate(String keyStoreName, String keyStorePass, String keyPass, String alias) throws Exception{
        // load information into a keystore
        KeyStore ks = java.security.KeyStore.getInstance( "JKS" );
        FileInputStream ksfis = new java.io.FileInputStream( username+"/"+keyStoreName );
        BufferedInputStream ksbufin = new java.io.BufferedInputStream( ksfis );
        ks.load( ksbufin, keyStorePass.toCharArray() );

        Certificate cert = ks.getCertificate( alias );
        ByteUtils.saveBytesToFile( username + "/" + alias + ".cer", cert.getEncoded() );
        ByteUtils.saveBytesToFile( username + "/" + alias + ".pubkey", cert.getPublicKey().getEncoded() );
        PrivateKey privateKey = (java.security.PrivateKey) ks.getKey( alias, keyPass.toCharArray() );
        ByteUtils.saveBytesToFile( username + "/" + alias + ".privKey", privateKey.getEncoded() );
        System.out.println( "### generated certificate information for -> " + alias );
        System.out.println( cert );

    }
}
