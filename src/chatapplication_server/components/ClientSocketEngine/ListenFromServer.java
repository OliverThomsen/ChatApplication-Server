/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package chatapplication_server.components.ClientSocketEngine;

import chatapplication_server.ComponentManager;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.security.Key;

import static chatapplication_server.components.Encryption.getCipher;
import static chatapplication_server.components.Helper.hexToByteArray;
import static chatapplication_server.components.Keys.getClientKey;

/**
 *
 * @author atgianne
 */
public class ListenFromServer extends Thread 
{

    Cipher cipher;
    public ListenFromServer(Cipher cipher) {
        this.cipher = cipher;
    }

    public void run()
    {
        while(true) {
                ObjectInputStream sInput = ClientEngine.getInstance().getStreamReader();
                
                synchronized( sInput )
                {
                    try
                    {

                        /** Decrypt message with client key */
                        String msgHexEncrypted = (String) sInput.readObject();
                        System.out.println(msgHexEncrypted);
                        byte[] msgBytesEncrypted = hexToByteArray(msgHexEncrypted);
                        byte[] msgBytes = cipher.doFinal(msgBytesEncrypted);
                        String msg = new String(msgBytes);


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
