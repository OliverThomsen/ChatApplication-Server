import java.security.cert.X509Certificate;

public class Test {
    public static void main(String[] args) throws Exception {
        KeyManager keyManager = new KeyManager("Oliver");
        KeyManager keyManagerBob = new KeyManager("Bob");

        X509Certificate caCer = keyManager.retrieveCertificate("CA/caroot.cer");
        System.out.println("CA public key: " + caCer.getPublicKey());

        KeyManager.createPkcs10Request("Bob");
        CertificateAuthority.signCSR("Bob");
        KeyManager.importCACert("Bob");
        KeyManager.importSignedCert("Bob");
    }
}
