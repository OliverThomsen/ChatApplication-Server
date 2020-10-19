package chatapplication_server.components;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import static java.lang.Thread.sleep;

public class KeyManager {
    String username;
    KeyPair keyPair;
    X509Certificate certificate;

    public KeyManager(String username) throws Exception {
        File folderToDelete = new File(username);
        deleteFolder(folderToDelete);
        this.username = username;
        this.keyPair = generateKeyPair();
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

        File f = new File(username + "/" + username + "KeyStore.jks");
        while(!f.exists()) {
            System.out.println("Waiting for " + f.getName());
            sleep(1000);
        }

    }
//
//    public void storeSymmetricKey(Key symmetricKey) throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException {
//        KeyStore keyStore = KeyStore.getInstance("JKECS");
//        keyStore.load(null, null);
//        keyStore.setKeyEntry(username, keyPair.getPrivate(), "password".toCharArray(), chain);
//
//        FileOutputStream fos = new FileOutputStream(username + "/" + username + "KeyStore.jks");
//        keyStore.store(fos, "password".toCharArray());
//
//        File f = new File(username + "/" + username + "KeyStore.jks");
//        while(!f.exists()) {
//            System.out.println("Waiting for " + f.getName());
//            sleep(1000);
//        }
//    }

    public static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        return kpg.generateKeyPair();
    }

    public PublicKey getPublicKey() {
        return keyPair.getPublic();
    }

    public X509Certificate retrieveOwnCertificate() throws Exception {
        String path = username + "/" + username + "signedCA.cer";
        FileInputStream fr = new FileInputStream(path);
        CertificateFactory cf = CertificateFactory.getInstance("X509");
        return (X509Certificate) cf.generateCertificate(fr);
    }

    public void accessCertificate(String keyStoreName, String keyStorePass, String keyPass, String alias) throws Exception{
        // load information into a keystore
        KeyStore ks = KeyStore.getInstance( "JKS" );
        FileInputStream ksfis = new FileInputStream( username+"/"+keyStoreName );
        BufferedInputStream ksbufin = new BufferedInputStream( ksfis );
        ks.load( ksbufin, keyStorePass.toCharArray() );

        // Create empty keystore for symmetric keys
        KeyStore jceks = KeyStore.getInstance("JCEKS");
        char[] password = "password".toCharArray();
        jceks.load(null, password);
        FileOutputStream fos = new FileOutputStream(username+"/"+"SymKeyStore.jceks");
        jceks.store(fos, password);

        Certificate cert = ks.getCertificate( alias );
        ByteUtils.saveBytesToFile( username + "/" + alias + ".cer", cert.getEncoded() );
        ByteUtils.saveBytesToFile( username + "/" + alias + ".pubkey", cert.getPublicKey().getEncoded() );
        PrivateKey privateKey = (PrivateKey) ks.getKey( alias, keyPass.toCharArray() );
        ByteUtils.saveBytesToFile( username + "/" + alias + ".privKey", privateKey.getEncoded() );
        System.out.println( "### generated certificate information for -> " + alias );
        System.out.println( cert );

        File f = new File(username + "/" + username + ".cer");
        while(!f.exists()) {
            System.out.println("Waiting for " + f.getName());
            sleep(1000);
        }

    }

    public static void createPkcs10Request(String username) throws Exception {
        sleep(5000);
        String pathToUser = username + "/";
        String cmd = "keytool -certreq -alias " + username + " " + "-keystore " + pathToUser + username + "KeyStore.jks" + " -file " + pathToUser + username + ".csr" + " " + "-storepass" + " " + "password";
//        System.out.println(cmd);
        File f = new File(pathToUser + username + ".csr");
        System.out.println(pathToUser + username + ".csr");
        System.out.println(cmd);

        Runtime.getRuntime().exec(cmd);
        while(!f.exists()) {
            System.out.println("Waiting for " + f.getName());
            sleep(1000);
        }
    }
//
//    public static void verifyCertificate() {
//        CertificateAuthority.generateKeyPair()
//
//    }

    public static void importCACert(String username) throws IOException, InterruptedException {
        String pathToUser = username + "/";
        String cmd = "keytool -import -alias CA -file CA/caroot.cer -keystore " + pathToUser + username + "KeyStore.jks " + "-storepass password -noprompt";
        System.out.println(cmd);
        Runtime.getRuntime().exec(cmd);

        sleep(1000);
    }

//    public PublicKey extractCAPublickey() throws FileNotFoundException, CertificateException {
//        FileInputStream fr = new FileInputStream("CA/caroot.cer");
//        CertificateFactory cf = CertificateFactory.getInstance("X509");
//        X509Certificate c = (X509Certificate) cf.generateCertificate(fr);
//
//
//        //X509Certificate cert = loadCertificate(df);
//        System.out.println(c.getSigAlgName());//SHA1withRSA
//        PublicKey key=c.getPublicKey();
//        System.out.println("key: \n" + key.toString());
//        System.out.println(key.getAlgorithm());//java.lang.NullPointerException
//    }

    public static void importSignedCert(String username) throws IOException {
        String pathToUser = username + "/";
        String cmd = "keytool -import -alias " + username + " -file " + pathToUser + username + "signedCA.cer -keystore " + pathToUser + username + "KeyStore.jks " + "-storepass password -noprompt";
        System.out.println(cmd);
        Runtime.getRuntime().exec(cmd);
    }

    public static void deleteFolder(File folder) {
        File[] files = folder.listFiles();
        if(files!=null) { //some JVMs return null for empty dirs
            for(File f: files) {
                if(f.isDirectory()) {
                    deleteFolder(f);
                } else {
                    f.delete();
                }
            }
        }
        folder.delete();
    }

    public SecretKey generateRandomKey() {
        KeyGenerator keyGen = null;
        try {
            keyGen = KeyGenerator.getInstance("AES");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        keyGen.init(256);
        return keyGen.generateKey();
    }

    public Key getPrivateKey() {
        return keyPair.getPrivate();
    }
}
