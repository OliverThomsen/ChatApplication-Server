/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package chatapplication_server.components.ClientSocketEngine;

import SocketActionMessages.ChatMessage;
import chatapplication_server.ComponentManager;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import sun.misc.BASE64Decoder;
import sun.security.x509.X509CertImpl;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.security.cert.X509Certificate;
import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.Base64;

import static chatapplication_server.components.Encryption.getCipher;
import static chatapplication_server.components.Helper.*;
import static chatapplication_server.components.Helper.byteArrayToHex;
import static chatapplication_server.components.Keys.calculateHmac;
import static chatapplication_server.components.Keys.getClientKey;

/**
 *
 * @author atgianne
 */
public class ListenFromServer extends Thread 
{

    private SecretKeySpec clientKey;
    Cipher cipher;
    private final String userName;
    public ListenFromServer(Cipher cipher, SecretKeySpec clientKey, String userName) {
        this.cipher = cipher;
        this.clientKey = clientKey;
        this.userName = userName;
    }

    public boolean verify (String hashPart, String msgPart, SecretKeySpec serverKey) throws GeneralSecurityException {
        byte[] msgBytes = hexToByteArray(msgPart);
        byte[] newHash = calculateHmac(serverKey, msgBytes);
        byte[] oldHash = hexToByteArray(hashPart);
        return Arrays.equals(newHash, oldHash);
    }

    public void run()
    {
        boolean receivedServerSecKey = false;
        boolean receivedCertFromServer = false;
        KeyStore symkeystore = null;
        try {
            symkeystore = KeyStore.getInstance("JCEKS");
            symkeystore.load(null,null);
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        while(true) {
                ObjectInputStream sInput = ClientEngine.getInstance().getStreamReader();
                
                synchronized( sInput )
                {

                    Security.addProvider(new BouncyCastleProvider());
                    String msg;

                    try
                    {
                        // client receives the server certificate and validates it, if already received this is skipped
                        if (!receivedCertFromServer) {
                            X509CertImpl serverCertImpl = (X509CertImpl) sInput.readObject();
                            System.out.println(serverCertImpl.toString());
                            byte[] serverCertBytes = serverCertImpl.getEncoded();
                            X509Certificate clientCert = X509Certificate.getInstance(serverCertBytes);
                            clientCert.checkValidity();
                            receivedCertFromServer = true;
                        }
                        // client receives the symmetric key, decrypts it with its own private key and stores it in a symmetric key store
                        else if (!receivedServerSecKey) {
                            File keystoreFile = new File(userName + "/" + userName + "KeyStore.jks");

                            KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
                            try (InputStream in = new FileInputStream(keystoreFile)) {
                                keystore.load(in, "password".toCharArray());
                            }

                            PrivateKey clientPrivKey = (PrivateKey) keystore.getKey(userName, "password".toCharArray());
                            Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA1AndMGF1Padding");

                            System.out.println("Waiting for symmetric key");
                            String encryptedSecKeyString = sInput.readUTF();

                            System.out.println("Symmetric key received");
                            byte[] encryptedMsgBytes = hexToByteArray(encryptedSecKeyString);
                            cipher.init(Cipher.DECRYPT_MODE, clientPrivKey);
                            byte[] msgCipherKey = cipher.doFinal(encryptedMsgBytes);

                            System.out.println("symkey decrypted: " + msgCipherKey.toString());

                            String byteArrayToString = new String(msgCipherKey, StandardCharsets.UTF_8);
                            byte[] decodedKey = Base64.getDecoder().decode(byteArrayToString);

                            System.out.println("MsgCipherKey" + msgCipherKey);

                            System.out.println("msgcipherKey length " + decodedKey.length);
                            SecretKey secretKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
                            clientKey = (SecretKeySpec) secretKey;
                            System.out.println(new BigInteger(1, clientKey.getEncoded()).toString(16));

                            // Server keystore with symmetric keys
                            KeyStore.SecretKeyEntry secret = new KeyStore.SecretKeyEntry(secretKey);
                            KeyStore.ProtectionParameter password = new KeyStore.PasswordProtection("password".toCharArray());
                            symkeystore.setEntry("server", secret, password);

                            FileOutputStream in2 = new FileOutputStream(userName + "/" + "SymKeyStore.jceks");
                            symkeystore.store(in2, "password".toCharArray());
                            in2.close();

                            System.out.println(symkeystore.getKey("server","password".toCharArray()));

                            System.out.println("Client received secretKey" + secretKey.toString());
                            receivedServerSecKey = true;
                        } else {
                            /** Decrypt message with client key */
                            String msgHexEncrypted = (String) sInput.readObject();

                            String hashPart = msgHexEncrypted.substring(msgHexEncrypted.length() - 128);
                            String msgPart = msgHexEncrypted.substring(32, msgHexEncrypted.length() - 128);
                            String ivPart = msgHexEncrypted.substring(0, 32);
                            byte[] ivVectorByte = hexToByteArray(ivPart);
                            IvParameterSpec ivParameterSpec = new IvParameterSpec(ivVectorByte);
                            System.out.println("Username: " + userName);
                            if(verify(hashPart, msgPart, clientKey )) {

                                byte[] msgBytes = hexToByteArray(msgPart);
                                cipher.init(Cipher.DECRYPT_MODE, clientKey, ivParameterSpec);
                                byte[] msgCipher = cipher.doFinal(msgBytes);
                                msg = new String(msgCipher);
                            }
                            else {
                                throw new Exception("Message cannot be verified");
                            }
                            if(msg.contains( "#" ))
                            {
                                ClientSocketGUI.getInstance().appendPrivateChat(msg + "\n");
                            }
                            else
                            {
                                ClientSocketGUI.getInstance().append(msg + "\n");
                            }
                        }


                    }
                    catch(IOException e) 
                    {
                        ClientSocketGUI.getInstance().append( "Server has closed the connection: " + e.getMessage() +"\n" );
                        ComponentManager.getInstance().fatalException(e);
                    }
                    catch(ClassNotFoundException cfe) 
                    {
                        ClientSocketGUI.getInstance().append( "Server has closed the connection: " + cfe.getMessage() );
                        ComponentManager.getInstance().fatalException(cfe);
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
        }
    }
}
