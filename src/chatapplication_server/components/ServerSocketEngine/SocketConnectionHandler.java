/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package chatapplication_server.components.ServerSocketEngine;

import SocketActionMessages.ChatMessage;
import chatapplication_server.components.ConfigManager;
import chatapplication_server.components.Helper;
import chatapplication_server.components.KeyManager;
import chatapplication_server.components.Keys;
import chatapplication_server.statistics.ServerStatistics;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jcajce.provider.asymmetric.X509;
import sun.security.x509.X509CertImpl;

import java.io.*;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.net.*;
import java.security.Key;

import javax.security.cert.CertificateException;
import javax.security.cert.X509Certificate;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.Arrays;
import java.util.Vector;

import static chatapplication_server.components.Encryption.getCipher;
import static chatapplication_server.components.Helper.*;
import static chatapplication_server.components.Keys.*;
import static java.lang.Thread.sleep;

/**
 *
 * @author atgianne
 */
public class SocketConnectionHandler implements Runnable
{
    /** Did we receive a signal to shut down */
    protected boolean mustShutdown;

    /** Flag for indicating whether we are handling a socket or not */
    protected boolean isSocketOpen;

    /** The socket connection that we are handling */
    private Socket handleConnection;

    /** String identifier of this ConnectionHandler thread (since we have more than 1 in the ConnectionHandling pool) */
    private String handlerName;

    /** The username of the client that we are handling */
    private String userName;

    /** Client certificate
     *
     */
    private X509Certificate clientCert;


    /** The only type of message that we will receive */
    private ChatMessage cm;

    /** Instance of the ConfigManager component */
    ConfigManager configManager;

    /** Object for keeping track in the logging stream of the actions performed in this socket connection */
    ServerStatistics connectionStat;
    
    /** Socket Stream reader/writer that will be used throughout the whole connection... */
    private ObjectOutputStream socketWriter;
    private ObjectInputStream socketReader;
    
    /**
     * Creates a new instance of SocketConnectionHandler
     */
    public SocketConnectionHandler() 
    {        
        /** Get the running instance of the Configuration Manager component */
        configManager = ConfigManager.getInstance();
        
        /** Auxiliary object for printing purposes */
        connectionStat = new ServerStatistics();
                
        /** Initialize the mustShutdown flag... */
        mustShutdown = false;
        
        /** Initialize the isSocketOpen flag, the Handler and the sensor type identifiers... */
        isSocketOpen = false;
        handlerName = null;
        
        /** Initialize the socket connection */
        handleConnection = null;
        
        /** Initialize the socket connection stream reader/writer... */
        socketWriter = null;
        socketReader = null;
    }
    
    /**
     * Method for printing some information about the socket connection that this ConnectionHandler thread is
     * accommodating.
     */
    public void printSocketInfo()
    {
        /** Check to see if there is a connection... */
        if ( handleConnection != null )
        {
            /** If it is not closed... */
            if ( !handleConnection.isClosed() )
            {
                /** Print some auxiliary information... */
                SocketServerGUI.getInstance().appendEvent("\n----------[" + handlerName + "]:: Configuration properties of assigned socket connection----------\n" );
                SocketServerGUI.getInstance().appendEvent( "Remote Address:= " + handleConnection.getInetAddress().toString() + "\n" );
                SocketServerGUI.getInstance().appendEvent( "Remote Port:= " + handleConnection.getPort() + "\n" );
                SocketServerGUI.getInstance().appendEvent( "Client UserName:= " + userName + "\n" );
                SocketServerGUI.getInstance().appendEvent( "Local Socket Address:= " + handleConnection.getLocalSocketAddress().toString() + "\n" );
            }
        }
    }
    
     /**
     * Method for setting the socket connection that this SocketConnectionHandler thread object will handle.
     * We must also set the stream reader/writer of the assigned socket connection.
     * Finally, we must notify it to wake up;as it was in an idle state (in the ConnectionHandling pool) waiting for a
     * new connection to be assigned.
     * 
     * IMPORTANT NOTE It must run in a synchronized block
     * 
     * @param s A reference to the newly established socket connection that this SocketConnectionHandler will handle
     */
    synchronized void setSocketConnection( Socket s )
    {
        /** Set the isSocketOpen flag to true... */
        isSocketOpen = true;
        
        /** Assign the socket connection to this Connection Handler */
        handleConnection = s;
        
        /** Print to the logging stream that this SSLConnectionHandler is assigned to this socket connection... */
        SocketServerGUI.getInstance().appendEvent( "[SSEngine]:: " + handlerName + " assigned to socket (" + handleConnection.getRemoteSocketAddress() + ") (" + connectionStat.getCurrentDate() + ")\n" );

        /** If the socket's stream writer/reader are set up correctly...then notify the thread to start working */
        if ( setSocketStreamReaderWriter() )
        {
            /** Notify the local thread to wake up */
            notify();
        }
    }
    
    /**
     * Method for setting up the stream reader/writer of the assigned to us secure socket connection between the
     * chat clients and the server.
     *
     * @return TRUE If the set up was successful; FALSE otherwise
     */
    public boolean setSocketStreamReaderWriter()
    {
        Security.addProvider(new BouncyCastleProvider());
        try
        {
            /** Set up the stream reader/writer for this socket connection... */
            socketWriter = new ObjectOutputStream( handleConnection.getOutputStream() );
            socketReader = new ObjectInputStream( handleConnection.getInputStream() );
            
            /** Read the username */
            //TODO: decrypt
            userName = ( String )socketReader.readObject();
            SocketServerGUI.getInstance().appendEvent( userName + " just connected at port number: " + handleConnection.getPort() + "\n" );

            X509CertImpl clientCertImpl = (X509CertImpl) socketReader.readObject();
            System.out.println(clientCertImpl.toString());
            byte[] clientCertBytes = clientCertImpl.getEncoded();
            clientCert = X509Certificate.getInstance(clientCertBytes);
            clientCert.checkValidity();

            // Server keystore with certificates
            File keystoreFile = new File("Server/ServerKeyStore.jks");

            KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
            try (InputStream in = new FileInputStream(keystoreFile)) {
                keystore.load(in, "password".toCharArray());
            }

            PublicKey CAPubKey = keystore.getCertificate("ca").getPublicKey();
            PublicKey clientPubKey = clientCert.getPublicKey();
            clientCert.verify(CAPubKey);
            System.out.println(CAPubKey);

            // Server sends own certificate to client
            FileInputStream fr = new FileInputStream("Server/ServersignedCA.cer");
            CertificateFactory cf = CertificateFactory.getInstance("X509");
            java.security.cert.X509Certificate serverSignedCert = (java.security.cert.X509Certificate) cf.generateCertificate(fr);
            socketWriter.writeObject(serverSignedCert);


            // Generate symmetric key and add to keystore
            try
            {
                Runtime rt = Runtime.getRuntime();
                String[] cmdArray = new String[16];
                cmdArray[0] = "keytool";
                cmdArray[1] = "-genseckey";
                cmdArray[2] = "-alias";
                cmdArray[3] = "symmetric" + userName.toLowerCase();
                cmdArray[4] = "-keyalg";
                cmdArray[5] = "AES";
                cmdArray[6] = "-keysize";
                cmdArray[7] = "192";
                cmdArray[8] = "-keypass";
                cmdArray[9] = "password";
                cmdArray[10] = "-keystore";
                cmdArray[11] = "Server/SymKeyStore.jceks";
                cmdArray[12] = "-storepass";
                cmdArray[13] = "password";
                cmdArray[14] = "-storetype";
                cmdArray[15] = "jceks";
                Process proc = rt.exec(cmdArray);
                proc.waitFor();
                int exitVal = proc.exitValue();
                System.out.println("Process exitValue: " + exitVal);
            } catch (Throwable t)
            {
                t.printStackTrace();
            }

            // Server keystore with symmetric keys
            File symKeyStoreFile = new File("Server/SymKeyStore.jceks");
            SecretKey secKey;
            KeyStore symkeystore = KeyStore.getInstance("JCEKS");
            try (InputStream in = new FileInputStream(symKeyStoreFile)) {
                symkeystore.load(in, "password".toCharArray());
                secKey = (SecretKey) symkeystore.getKey("symmetric"+userName.toLowerCase(), "password".toCharArray());
            }

            Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA1AndMGF1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, clientPubKey);

            byte[] encryptedBytes = cipher.doFinal(new BigInteger(1, secKey.getEncoded()).toString(16).getBytes());

            System.out.println(new BigInteger(1, secKey.getEncoded()).toString(16));
            System.out.println(encryptedBytes.toString());
            System.out.println(Helper.byteArrayToHex(encryptedBytes));
//            socketWriter.writeObject(Helper.byteArrayToHex(encryptedBytes));
            socketWriter.writeUTF(Helper.byteArrayToHex(encryptedBytes));
//            socketWriter.writeObject(clientCert);
            socketWriter.flush();
//            socketWriter.writeBytes(Helper.byteArrayToHex(encryptedBytes));
//            socketWriter.writeObject(Helper.byteArrayToHex("polse".getBytes()));
            System.out.println("Symmetric key sent");

            return true;
        }
        catch ( StreamCorruptedException sce )
        {
            /** Keep track of the exception in the logging stream... */
            SocketServerGUI.getInstance().appendEvent( "[" + handlerName + "]:: Stream corrupted excp during stream reader/writer init -- " + sce.getMessage() + " (" + connectionStat.getCurrentDate() + ")\n" );
            
            /** Notify the SocketServerEngine that we are about to die in order to create a new SSLConnectionHandler in our place */
            SocketServerEngine.getInstance().addConnectionHandlerToPool( handlerName );

            /** Notify the SocketServerEngine to remove us from the occupance pool... */
            SocketServerEngine.getInstance().removeConnHandlerOccp( handlerName );
            
            /** Then shut down... */
            this.stop();

            return false;
        }
        catch ( ClassNotFoundException cnfe )
        {
            /** Keep track of this exception in the logging stream... */
            SocketServerGUI.getInstance().appendEvent( userName + " Exception reading streams:" + cnfe + "\n" );

            return false;
        }
        catch ( OptionalDataException ode )
        {
            /** Keep track of the exception in the logging stream... */
            SocketServerGUI.getInstance().appendEvent( "[" + handlerName + "]:: Optional data excp during stream reader/writer init -- " + ode.getMessage() + " (" + connectionStat.getCurrentDate() + ")\n" );
            
            /** Notify the SocketServerEngine that we are about to die in order to create a new SSLConnectionHandler in our place */
            SocketServerEngine.getInstance().addConnectionHandlerToPool( handlerName );

            /** Notify the SocketServerEngine to remove us from the occupance pool... */
            SocketServerEngine.getInstance().removeConnHandlerOccp( handlerName );
            
            /** Then shut down... */
            this.stop();

            return false;
        }
        catch ( IOException ioe )
        {
            /** Keep track of the exception in the logging stream... */
            SocketServerGUI.getInstance().appendEvent( "[" + handlerName + "]: IOException during stream read/writer init -- " + ioe.getMessage() + " (" + connectionStat.getCurrentDate() + ")\n" );
            
            /** Notify the SocketServerEngine that we are about to die in order to create a new SSLConnectionHandler in our place */
            SocketServerEngine.getInstance().addConnectionHandlerToPool( handlerName );

            /** Notify the SocketServerEngine to remove us from the occupance pool... */
            SocketServerEngine.getInstance().removeConnHandlerOccp( handlerName );
            
            /** Then shut down... */
            this.stop();

            return false;
        } catch (CertificateException e) {
            e.printStackTrace();
            return false;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }
    
     /**
     * Method for setting the identifier name of this ConnectionHandler thread.
     * Since we will have "ConnectionHandlers.Name" number of thread in the Connectionhandling pool, we must have
     * an identifier for for being able to distinguish them.
     *
     * @param s The String identifier to be given in this ConnectionHandler thread
     */
    public void setHandlerIdentifierName( String s )
    {
        handlerName = s;
    }
    
    /**
     * Method for getting the identifier name of this ConnectionHandler thread.
     *
     * @return The String identifier of this ConnectionHandler thread
     */
    public String getHandlerIdentifierName()
    {
        return handlerName;
    }
    
    /*
    * Method for getting the userName of the connected client handled by this thread.
    *
    * @return The String user Name of the connected client
    */
    public String getUserName()
    {
        return userName;
    }
    
    /**
     * Method for getting the Socket connection operated by this handler
     * 
     * @return The socket connection that is currently handled 
     */
    public Socket getHandleSocket()
    {
        return handleConnection;
    }
    
     /**
     * Java thread entry point...
     * This method contains the main functionality of the SocketConnectionHandler. When the worker handler is in
     * idle state, it just waits to be notified by the SocketServerEngine that a new socket connection has been
     * established and must be handled by this worker.
     * Once a socket connection is assigned to this ConnectionHandler, it waits until there is some data for 
     * reception.
     * Upon shut down, it returns to the Connectionhandling pool for future use by another socket connection.
     */
    public synchronized void run()
    {
        while ( !mustShutdown )
        {
            /** If we are in idle state, don't do anything;just wait to be notified */
            if ( handleConnection == null )
            {
                try
                {
                    wait();
                }
                catch ( InterruptedException e )
                {
                    /** IN NORMAL OPERATION THIS SHOULD NEVER HAPPEN... */
                    /** Print to logging stream that something went wrong */
                    SocketServerGUI.getInstance().appendEvent("[" + handlerName + "]:: ConnectionHandler in idle state died..." + e.getMessage() + " (" + connectionStat.getCurrentDate() + ")\n" );
                    
                    /** Notify the SocketServerEngine that we are about to die in order to create a new SSLConnectionHandler in our place */
                    SocketServerEngine.getInstance().addConnectionHandlerToPool( handlerName );

                    /** Notify the SocketServerEngine to remove us from the occupance pool... */
                    SocketServerEngine.getInstance().removeConnHandlerOccp( handlerName );

                    /** Then shut down... */
                    this.stop();
                    
                    /** Stop this SSLConnectionHandler worker */
                    return;
                }
            }
            
             /** 
             * If we are notified/assigned to handle a socket connection... 
             * Call the receiveContent method for waiting data/requests from the Alix client. The Connection Handler
             * thread will stay in this method during the lifetime of the assigned socket connection
             */
            if ( handleConnection != null )
            {
                receiveContent();
                
                /** If we finished the 'handling' of the assigned socket connection, add ourselves in the connectionHandling pool for future use */
                socketConnectionHandlerRelease();

                /** Also, inform the SocketServerEngine to remove us from the occupance pool... */
                SocketServerEngine.getInstance().removeConnHandlerOccp( this.handlerName );
            }
        }
    }

    /**
     * Verify the integrity of the message by comparing the sent hash with hashing the message with the same key
     */

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



    /**
     * Method for handling any data transmission/reception of the assigned socket connection. The SocketConnectionHandler retrieves
     * the stream sent by the client. Whenever,
     * the stream is empty (client doesn't send anything), the SocketConnectionHandler remains idle and goes back to business
     * only when necessary!!
     */
    public void receiveContent()
    {        
        while ( isSocketOpen )
        {    
            try
            {
                /** Wait until there is something in the stream to be read... */
                String msgHex = (String) socketReader.readObject();
                Security.addProvider(new BouncyCastleProvider());
                try {
//                    SecretKeySpec clientKey = getClientKey(configManager.getValue("Client.Username"));
                    // Server keystore with symmetric keys
                    File symKeyStoreFile = new File("Server/SymKeyStore.jceks");
                    SecretKey secKey;
                    KeyStore symkeystore = KeyStore.getInstance("JCEKS");
                    try (InputStream in = new FileInputStream(symKeyStoreFile)) {
                        symkeystore.load(in, "password".toCharArray());
                        secKey = (SecretKey) symkeystore.getKey("symmetric"+userName.toLowerCase(), "password".toCharArray());
                    }
                    SecretKeySpec clientKey = (SecretKeySpec) secKey;
                    System.out.println(new BigInteger(1, clientKey.getEncoded()).toString(16));
                    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                    String hashPart = msgHex.substring(msgHex.length() - 128);
                    String msgPart = msgHex.substring(32, msgHex.length() - 128);
                    String ivPart = msgHex.substring(0, 32);
                    System.out.println("Iv vector string: " + ivPart);
                    byte[] ivVectorByte = hexToByteArray(ivPart);
                    IvParameterSpec ivParameterSpec = new IvParameterSpec(ivVectorByte);
                    cipher.init(Cipher.DECRYPT_MODE, clientKey, ivParameterSpec);

                    if(verify(hashPart, msgPart, clientKey)) {

                        byte[] msgBytes = hexToByteArray(msgPart);
                        byte[] msgCipher = cipher.doFinal(msgBytes);
                        cm = (ChatMessage) convertFromBytes(msgCipher);
                    }
                    else {
                        throw new Exception("Message cannot be verified");
                    }

                } catch (NoSuchAlgorithmException e) {
                    e.printStackTrace();
                } catch (NoSuchPaddingException e) {
                    e.printStackTrace();
                } catch (BadPaddingException e) {
                    e.printStackTrace();
                } catch (IllegalBlockSizeException e) {
                    e.printStackTrace();
                } catch (InvalidKeyException e) {
                    e.printStackTrace();
                } catch (GeneralSecurityException e) {
                    e.printStackTrace();
                } catch (Exception e) {
                    e.printStackTrace();
                }

                String message = cm.getMessage();
                
//                 Switch on the type of message receive
                switch(cm.getType())
                {
                case ChatMessage.MESSAGE:
                        SocketServerEngine.getInstance().broadcast(userName + ": " + message);
                        break;
                case ChatMessage.LOGOUT:
                        SocketServerGUI.getInstance().appendEvent(userName + " disconnected with a LOGOUT message.\n");
                         /** If we finished the 'handling' of the assigned socket connection, add ourselves in the connectionHandling pool for future use */
                        socketConnectionHandlerRelease();

                        /** Also, inform the SocketServerEngine to remove us from the occupance pool... */
                        SocketServerEngine.getInstance().removeConnHandlerOccp( this.handlerName );
                        
                        isSocketOpen = false;
                        break;
                case ChatMessage.WHOISIN:
                    SocketServerEngine.getInstance().printEstablishedSocketInfo();
                    break;
                case ChatMessage.PRIVATEMESSAGE:
                    String temp[] = cm.getMessage().split(",");
                    int PortNo = Integer.valueOf(temp[0]);
                    String Chat = temp[1];

                    System.out.println("At Server :  " +PortNo +temp[1]);
                    SocketServerEngine.getInstance().writeMsgSpecificClient(PortNo, Chat);
                    break;              
		}
                
            }
            catch ( ClassNotFoundException cnfe )
            {
                /** Keep track of this exception in the logging stream... */
                SocketServerGUI.getInstance().appendEvent( userName + " Exception reading streams:" + cnfe.getMessage() + "\n" );
                isSocketOpen = false;
            }
            catch ( OptionalDataException ode )
            {
                /** Keep track of this exception in the logging stream... */
                SocketServerGUI.getInstance().appendEvent( userName + " Exception reading streams:" + ode.getMessage() + "\n" );
                isSocketOpen = false;
            }
            catch ( IOException e )
            {
                /** Keep track of this exception in the logging stream... */
                SocketServerGUI.getInstance().appendEvent( userName + " Exception reading streams:" + e.getMessage() + "\n" );
                
                /** Change the socket status... */
                isSocketOpen = false;
                e.printStackTrace();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }
    
    /*
     * Write a String to the Client output stream
     *
     * msg The string to be written to the client output stream
     */
    public boolean writeMsg( String msg )
    {
        // if Client is still connected send the message to it
        if( !isSocketOpen )
        {
            /** If we finished the 'handling' of the assigned socket connection, add ourselves in the connectionHandling pool for future use */
            socketConnectionHandlerRelease();

            /** Also, inform the SocketServerEngine to remove us from the occupance pool... */
            SocketServerEngine.getInstance().removeConnHandlerOccp( this.handlerName );

            return false;
        }
        // write the message to the stream
        try
        {
            //TODO: encrypt
/*            Key clientKey = getClientKey(userName);
            Cipher clientCipher = getCipher(Cipher.ENCRYPT_MODE, clientKey);
            byte[] msgEncrypted = clientCipher.doFinal(msg.getBytes());
            String msgEncryptedHex = byteArrayToHex(msgEncrypted);
            System.out.println(msgEncryptedHex);
            socketWriter.writeObject(msgEncryptedHex);*/

            System.out.println("sending to: " + configManager.getValue("Client.Username"));

            SecretKeySpec clientKey = getClientKey(configManager.getValue("Client.Username"));
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            IvParameterSpec ivParameterSpec = generateIV();
            cipher.init(Cipher.ENCRYPT_MODE, clientKey, ivParameterSpec);
            byte[] msgBytes = convertToBytes(msg);
            byte[] msgCipher = cipher.doFinal(msgBytes);
            socketWriter.writeObject(appendHashAndIvToMsg(msgCipher, clientKey, ivParameterSpec));

        }
        // if an error occurs, do not abort just inform the user
        catch( IOException e )
        {
            SocketServerGUI.getInstance().appendEvent("Error sending message to " + userName + "\n");
            SocketServerGUI.getInstance().appendEvent( e.toString() );
        } catch (Exception e) {
            e.printStackTrace();
        }
        return true;
    }

    /**
     * Method that is called whenever a ConnectionHandler thread finished the execution of an assigned socket 
     * connection. In that case, it must add itself in the Connectionhandling pool of the SocketServerEngine component
     * for future use and return to idle state waiting for new connections.
     */
    public void socketConnectionHandlerRelease()
    {
        /** First clear the reference to the previous connection... */
        handleConnection = null;

        /** Initialize the auxiliary identifier variables... */
        isSocketOpen = false;
        
        /** Print to the logging stream that this SSLConnectionHandler is returing in the ConnectionHandling pool... */
        SocketServerGUI.getInstance().appendEvent( "[" + handlerName + "]:: Finished SckHandling -- Back in the pool (" + connectionStat.getCurrentDate() + ")\n");
        
        /** Get the connectionHandling pool from the SSLEngineServer component to add ourselves */
        Vector connectionPool = SocketServerEngine.getInstance().getConnectionHandlingPool();

        synchronized ( connectionPool )
        {
            connectionPool.addElement( this );
        }
    }
    
     /**
     * Method for notifying this SocketConnectionHandler thread to stop its execution.
     */
    public void stop()
    {
        synchronized ( this )
        {
            /** First get out from execution mode the Connection Handler... */
            isSocketOpen = false;
            
            /** Signal the Connection Handler thread to stop its execution... */
            mustShutdown = true;
            
            /** Notify the ConnectionHandler thread in case it is in an idle state waiting... */
            notify();
        }
    }
}
