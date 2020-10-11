/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */


import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.util.Enumeration;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.Certificate;

public class AccessCertificates {

  public static void main( String[] args ) throws Exception {
    Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    final String keyStoreName = "Bob/BobKeyStore.jks"; // keystore file should exisit in the program folder of the application
    final String keyStorePass = "password"; // password of keystore
    final String keyPass = "password";

    // load information into a keystore
    KeyStore ks = java.security.KeyStore.getInstance( "JKS" );
    FileInputStream ksfis = new java.io.FileInputStream( keyStoreName );
    BufferedInputStream ksbufin = new java.io.BufferedInputStream( ksfis );
    ks.load( ksbufin, keyStorePass.toCharArray() );

    // list aliases in the keystore
    java.io.FileOutputStream fos = null;
    for( Enumeration theAliases = ks.aliases(); theAliases.hasMoreElements(); ) {
      String alias = (String) theAliases.nextElement();
      System.out.println(alias);
      Certificate cert = ks.getCertificate( alias );
      ByteUtils.saveBytesToFile( alias + ".cer", cert.getEncoded() );
      ByteUtils.saveBytesToFile( alias + ".pubkey", cert.getPublicKey().getEncoded() );
      PrivateKey privateKey = (java.security.PrivateKey) ks.getKey( alias, keyPass.toCharArray() );
      ByteUtils.saveBytesToFile( alias + ".privKey", privateKey.getEncoded() );
      System.out.println( "### generated certificate information for -> " + alias );
      System.out.println( cert );
    }
  }
}
