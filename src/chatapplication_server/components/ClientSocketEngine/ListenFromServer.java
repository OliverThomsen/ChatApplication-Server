/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package chatapplication_server.components.ClientSocketEngine;

import SocketActionMessages.ChatMessage;
import chatapplication_server.ComponentManager;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;

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

    private final SecretKeySpec clientKey;
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

    public String appendHashAndIvToMsg(byte[] msgCipher, SecretKeySpec serverKey, IvParameterSpec IvVector) throws GeneralSecurityException {
        byte[] hash = calculateHmac(serverKey, msgCipher);
        byte[] ivTobytearray = IvVector.getIV();
        String msgCipherHash = byteArrayToHex(hash);
        String msgCipherHex = byteArrayToHex(msgCipher);
        String msgCipherIv = byteArrayToHex(ivTobytearray);
        return msgCipherIv+msgCipherHex+msgCipherHash;
    }

    /**
     * Generating a random IV vector
     */

    public IvParameterSpec generateIV () {
        byte[] iv = new byte[16];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        return ivParameterSpec;
    }

    public void run()
    {
        while(true) {
                ObjectInputStream sInput = ClientEngine.getInstance().getStreamReader();
                
                synchronized( sInput )
                {

                    Security.addProvider(new BouncyCastleProvider());
                    String msg;

                    try
                    {

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

//                        byte[] msgBytesEncrypted = hexToByteArray(msgHexEncrypted);
                       // byte[] msgBytes = cipher.doFinal(msgBytesEncrypted);




                      //  String msg = new String(msgBytes);


                        if(msg.contains( "#" ))
                        {
                            ClientSocketGUI.getInstance().appendPrivateChat(msg + "\n");
                        }
                        else
                        {
                            ClientSocketGUI.getInstance().append(msg + "\n");
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
