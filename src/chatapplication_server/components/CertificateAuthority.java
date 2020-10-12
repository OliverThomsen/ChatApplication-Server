package chatapplication_server.components;

import sun.security.x509.*;

import java.io.File;
import java.io.FileOutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Date;

import static java.lang.Thread.sleep;

public class CertificateAuthority {

    public CertificateAuthority() {

    }

    public static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        return kpg.generateKeyPair();
    }

    public static X509Certificate generateCertificate(String commonName, String organizationUnit, String organizationName, String country, KeyPair keyPair) throws Exception {
        int validity = 365;
        String sigAlgName = "SHA256withRSA";
        PrivateKey privateKey = keyPair.getPrivate();

        X509CertInfo info = new X509CertInfo();

        Date from = new Date();
        Date to = new Date(from.getTime() + validity * 1000L * 24L * 60L * 60L);

        CertificateValidity interval = new CertificateValidity(from, to);
        BigInteger serialNumber = new BigInteger(64, new SecureRandom());
        X500Name owner = new X500Name(commonName, organizationUnit, organizationName, country);
        AlgorithmId sigAlgId = new AlgorithmId(AlgorithmId.md5WithRSAEncryption_oid);

        info.set(X509CertInfo.VALIDITY, interval);
        info.set(X509CertInfo.SERIAL_NUMBER, new CertificateSerialNumber(serialNumber));
        info.set(X509CertInfo.SUBJECT, owner);
        info.set(X509CertInfo.ISSUER, owner);
        info.set(X509CertInfo.KEY, new CertificateX509Key(keyPair.getPublic()));
        info.set(X509CertInfo.VERSION, new CertificateVersion(CertificateVersion.V3));
        info.set(X509CertInfo.ALGORITHM_ID, new CertificateAlgorithmId(sigAlgId));

        // TODO: use CA to sign certificate instead of self signing
        // Sign the cert to identify the algorithm that's used.
        X509CertImpl certificate = new X509CertImpl(info);
        certificate.sign(privateKey, sigAlgName);

        // Update the algorithm, and resign.
        sigAlgId = (AlgorithmId) certificate.get(X509CertImpl.SIG_ALG);
        info.set(CertificateAlgorithmId.NAME + "." + CertificateAlgorithmId.ALGORITHM, sigAlgId);
        certificate = new X509CertImpl(info);
        certificate.sign(privateKey, sigAlgName);

        // Write serial.txt file
        FileOutputStream fos = new FileOutputStream("serial.txt");
        fos.write(1234);
        fos.close();

        return certificate;
    }

    public static void signCSR(String username) throws Exception {
        sleep(5000);
        String pathtoUser = username + "/";
        String cmd = "openssl x509 -CA CA/caroot.cer -CAkey CA/cakey.pem -CAserial CA/serial.txt -req -in " + pathtoUser + username + ".csr" + " -out " + pathtoUser + username + "signedCA.cer" + " -days 365 -passin pass:password";
        System.out.println(cmd);
        Runtime.getRuntime().exec(cmd);

        File f = new File(pathtoUser + username + "signedCA.cer");
        while (!f.exists()) {
            System.out.println("Waiting for " + f.getName());
            sleep(1000);
        }
    }


}