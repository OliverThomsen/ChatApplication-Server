/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package chatapplication_server.components.ClientSocketEngine;

import SocketActionMessages.ChatMessage;
import chatapplication_server.components.ConfigManager;
import chatapplication_server.components.KeyManager;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingConstants;
import javax.swing.WindowConstants;

import java.net.*;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;
import chatapplication_server.components.CertificateAuthority;

import static chatapplication_server.components.Helper.*;
import static chatapplication_server.components.Helper.hexToByteArray;
import static chatapplication_server.components.Keys.calculateHmac;

/**
 *
 * @author atgianne
 */
public class P2PClient extends JFrame implements ActionListener
{
    private String host;
    private String port;
    private String userName;
    private final JTextField tfServer;
    private final JTextField tfPort;
    private final JTextField tfsPort;
    private final JLabel label;
    private final JTextField tf;
    private final JTextArea ta;
    protected boolean keepGoing;
    JButton Send, stopStart;
    JButton connectStop;

    /** Client Socket and output stream... */
    Socket socket = null;
    ObjectOutputStream sOutput;

    private ListenFromClient clientServer;

    /** Flag indicating whether the Socket Server is running at one of the Clients... */
    boolean isRunning;

    /** Flag indicating whether another client is connected to the Socket Server... */
    boolean isConnected;

    /** Flag indicating if this client initiated the handshake*/
    private boolean isInitiator;

    private KeyManager keyManager;

    private Key symmetricKey;

    X509Certificate friendCert;
    private String firstMessage;


    P2PClient(KeyManager keyManager){
        super("P2P Client Chat");
        host=ConfigManager.getInstance().getValue( "Server.Address" );
        port=ConfigManager.getInstance().getValue( "Server.PortNumber" );
        userName = ConfigManager.getInstance().getValue( "Client.Username" );
        this.keyManager = keyManager;

        // The NorthPanel with:
        JPanel northPanel = new JPanel(new GridLayout(3,1));
        // the server name anmd the port number
        JPanel serverAndPort = new JPanel(new GridLayout(1,5, 1, 3));
        // the two JTextField with default value for server address and port number
        tfServer = new JTextField(host);
        tfPort = new JTextField("" + port);
        tfPort.setHorizontalAlignment(SwingConstants.RIGHT);

        tfsPort=new JTextField(5);
        tfsPort.setHorizontalAlignment(SwingConstants.RIGHT);
        stopStart=new JButton("Start");
        stopStart.addActionListener(this);

        serverAndPort.add(new JLabel("Receiver's Port No:  "));
        serverAndPort.add(tfPort);
        serverAndPort.add(new JLabel("Receiver's IP Add:  "));
        serverAndPort.add(tfServer);
        serverAndPort.add(new JLabel(""));
        // adds the Server an port field to the GUI
        northPanel.add(serverAndPort);

        // the Label and the TextField
        label = new JLabel("Enter message below", SwingConstants.LEFT);
        northPanel.add(label);
        tf = new JTextField();
        tf.setBackground(Color.WHITE);
        northPanel.add(tf);
        add(northPanel, BorderLayout.NORTH);

        // The CenterPanel which is the chat room
        ta = new JTextArea(" ", 80, 80);
        JPanel centerPanel = new JPanel(new GridLayout(1,1));
        centerPanel.add(new JScrollPane(ta));
        ta.setEditable(false);

//        ta2 = new JTextArea(80,80);
//        ta2.setEditable(false);
//        centerPanel.add(new JScrollPane(ta2));
        add(centerPanel, BorderLayout.CENTER);

        connectStop = new JButton( "Connect" );
        connectStop.addActionListener(this);

        Send = new JButton("Send");
        Send.addActionListener(this);
        Send.setVisible( false );
        JPanel southPanel = new JPanel();
        southPanel.add( connectStop );
        southPanel.add(Send);
        southPanel.add(stopStart);
        JLabel lbl=new JLabel("Sender's Port No:");
        southPanel.add(lbl);
        tfsPort.setText("0");
        southPanel.add(tfsPort);
        add(southPanel, BorderLayout.SOUTH);

        this.setDefaultCloseOperation(WindowConstants.DISPOSE_ON_CLOSE);

//        setDefaultCloseOperation(EXIT_ON_CLOSE);
        setSize(600, 600);
        setVisible(true);
        tf.requestFocus();

        isRunning = false;
        isConnected = false;
    }

    @Override
    public void actionPerformed(ActionEvent e) {
        Object o = e.getSource();

        if ( o == connectStop )
        {
            if ( connectStop.getText().equals( "Connect" ) && isConnected == false )
            {
                if ( tfPort.getText().equals( ConfigManager.getInstance().getValue( "Server.PortNumber" ) ) )
                {
                    display( "Cannot give the same port number as the Chat Application Server - Please give the port number of the peer client to communicate!\n" );
                    return;
                }

                /** Connect to the Socket Server instantiated by the other client... */
                this.connect();
            }
            else if ( connectStop.getText().equals( "Disconnect" ) && isConnected == true )
            {
                this.disconnect();
            }
        }
        else if ( o == Send )
        {
            /** Try to send the message to the other communicating party, if we have been connected... */
            if ( isConnected && symmetricKey != null )
            {
                try {
                    this.send(tf.getText());
                } catch(Exception exception) {
                    exception.printStackTrace();
                }
            }
            // Symmetric key not established. Initiate handshake by sharing own certificate
            else if (isConnected && symmetricKey == null) {
                try {
                    this.isInitiator = true;
                    X509Certificate myCertificate = keyManager.retrieveOwnCertificate();
                    this.send(myCertificate);
                    // Save message for later
                    this.firstMessage = tf.getText();
                } catch(Exception exception) {
                    exception.printStackTrace();
                }
            }
        }
        else if(o == stopStart)
        {
            if ( stopStart.getText().equals( "Start" ) && isRunning == false)
            {
                clientServer = new ListenFromClient(keyManager);
                clientServer.start();
                isRunning = true;
                stopStart.setText( "Stop" );
            }
            else if ( stopStart.getText().equals( "Stop" ) && isRunning == true )
            {
                clientServer.shutDown();
                clientServer.stop();
                isRunning = false;
                stopStart.setText( "Start" );
            }
        }
    }

    public String decrypt(String cipherText, Key key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IOException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        String iv = cipherText.substring(0,32);
        String msgCipher = cipherText.substring(32);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(hexToByteArray(iv));
        cipher.init(Cipher.DECRYPT_MODE, key, ivParameterSpec);
        byte[] plainText = cipher.doFinal(hexToByteArray(msgCipher));
        return new String(plainText);
    }

    public String encrypt(String message, Key key) throws InvalidAlgorithmParameterException, InvalidKeyException, IOException, BadPaddingException, IllegalBlockSizeException, NoSuchPaddingException, NoSuchAlgorithmException {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        IvParameterSpec ivParameterSpec = generateIV();
        cipher.init(Cipher.ENCRYPT_MODE, key, ivParameterSpec);
        byte[] msgBytes = convertToBytes(message);
        byte[] msgCipher = cipher.doFinal(msgBytes);
        byte[] iv = ivParameterSpec.getIV();
        return byteArrayToHex(iv) + byteArrayToHex(msgCipher);
    }

    public byte[] encryptRSA(byte[] cipherText, Key key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA1AndMGF1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(cipherText);
    }

    public byte[] decryptRSA(byte[] plainText, Key key) throws BadPaddingException, IllegalBlockSizeException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA1AndMGF1Padding");
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(plainText);
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

    public void display(String str) {
        ta.append(str + "\n");
        ta.setCaretPosition(ta.getText().length() - 1);
    }

    /**
     * Method that is invoked when a client wants to connect to the Socket Server spawn from another client in order to initiate their P2P communication.
     *
     * @return TRUE if the connection was successful; FALSE otherwise
     */
    public boolean connect()
    {
        /* Try to connect to the Socket Server... */
        try {
            if (isConnected == false)
            {
                socket = new Socket(tfServer.getText(), Integer.parseInt(tfPort.getText()));

                sOutput = new ObjectOutputStream(socket.getOutputStream());
                isConnected = true;
                Send.setVisible( true );
                connectStop.setText( "Disconnect" );

                return true;
            }
        }
        catch (IOException eIO) {
            display("The Socket Server from the other side has not been fired up!!\nException creating new Input/output Streams: " + eIO.getMessage() + "\n");
            isConnected = false;
            Send.setVisible( false );
            connectStop.setText( "Connect" );
            return false;
        }
        // if it failed not much I can so
        catch(Exception ec) {
            display("Error connecting to server:" + ec.getMessage() + "\n");
            isConnected = false;
            Send.setVisible( false );
            connectStop.setText( "Connect" );
            return false;
        }

        return true;
    }

    /**
     * Method that is invoked when we want do disconnect from a Socket Server (spawn by another client); this, basically, reflects the stopping of a P2P communication
     *
     * @return TRUE if the disconnect was successful; FALSE, otherwise
     */
    public boolean disconnect()
    {
        /** Disconnect from the Socket Server that we are connected... */
        try
        {
            if ( isConnected == true )
            {
                /** First, close the output stream... */
                sOutput.close();

                /** Then, close the socket... */
                socket.close();

                /** Re-initialize the parameters... */
                isConnected = false;
                Send.setVisible( false );
                connectStop.setText( "Connect" );

                return true;
            }
        }
        catch( IOException ioe )
        {
            display( "Error closing the socket and output stream: " + ioe.getMessage() + "\n" );

            /** Re-initialize the parameters... */
            isConnected = false;
            Send.setVisible( false );
            connectStop.setText( "Connect" );
            return false;
        }

        return true;
    }

    public boolean send(String msg)
    {
        try {
            String cipherText = encrypt(msg, symmetricKey);
            sOutput.writeObject(new ChatMessage(cipherText.length(), cipherText));
            display("You: " + msg);
        } catch (IOException ex) {
            display("The Client's Server Socket was closed!!\nException creating output stream: " + ex.getMessage());
            this.disconnect();
            return false;
        } catch (Exception e) {
            e.printStackTrace();
        }

        return true;
    }

    public boolean send(Object obj) {
        try {
            sOutput.writeObject(obj);
        } catch(Exception e) {
            e.printStackTrace();
            return false;
        }
        return true;
    }

    public void setSymmetricKey(SecretKey key) {
        this.symmetricKey = key;
    }

    private class ListenFromClient extends Thread
    {
        private final KeyManager keyManager;
        ServerSocket serverSocket;
        Socket socket;
        ObjectInputStream sInput = null;
        boolean clientConnect;

        public ListenFromClient(KeyManager keyManager)
        {
            this.keyManager = keyManager;
            try
            {
                // the socket used by the server
                serverSocket = new ServerSocket(Integer.parseInt(tfsPort.getText()));
                ta.append("Server is listening on port:"+tfsPort.getText() + "\n");
                ta.setCaretPosition(ta.getText().length() - 1);
                clientConnect = false;
                keepGoing = true;
            }
            catch ( IOException ioe )
            {
                System.out.println("[P2PClient]:: Error firing up Socket Server " + ioe.getMessage());
            }
        }

        @Override
        public void run()
        {
            // infinite loop to wait for messages
            while(keepGoing)
            {
                /** Wait only when there are no connections... */
                try
                {
                    if ( !clientConnect )
                    {
                        socket = serverSocket.accept();  	// accept connection
                        sInput = new ObjectInputStream(socket.getInputStream());
                        clientConnect = true;
                    }
                }
                catch (IOException ex)
                {
                    display("The Socket Server was closed: " + ex.getMessage());
                }

                // Clients have established symmetric key
                if(symmetricKey != null) {
                    try {
                        String cipherText = ((ChatMessage) sInput.readObject()).getMessage();
                        String msg = decrypt(cipherText, symmetricKey);
                        display(socket.getInetAddress()+": " + socket.getPort() + ": " + msg);
                        //sInput.close();
                        //socket.close();
                    }
                    catch (IOException ex)
                    {
                        display("Could not ready correctly the messages from the connected client: " + ex.getMessage());
                        clientConnect = false;
                    }
                    catch (ClassNotFoundException ex) {
                        Logger.getLogger(P2PClient.class.getName()).log(Level.SEVERE, null, ex);
                    }
                    catch (Exception exception) {
                        exception.printStackTrace();
                    }
                }

                // Clients do not have a symmetric key yet
                else {
                    try {
                        // Expect to receive certificate of friend
                        if (friendCert == null) {
                            friendCert = (X509Certificate) sInput.readObject();
                            System.out.println(friendCert);
                            friendCert.checkValidity();
                            friendCert.verify(CertificateAuthority.getCAPubKey());

                            // If user is initiator of handshake generate symmetric key and send to friend
                            if (isInitiator) {
                                SecretKey key = keyManager.generateRandomKey();
                                setSymmetricKey(key);
                                // Sign key with privateKey
//                                byte[] signedKey = encryptRSA(key.getEncoded(), keyManager.getPrivateKey());
                                // Encrypt symmetric key with pubKey of friends
                                byte[] encryptedSignedKey = encryptRSA(key.getEncoded(), friendCert.getPublicKey());
                                sOutput.writeObject(byteArrayToHex(encryptedSignedKey));
                                send(firstMessage);

                            }
                            // If the user is not the initiator send own certificate
                            else {
                                X509Certificate myCertificate = keyManager.retrieveOwnCertificate();
                                send(myCertificate);
                            }

                        }
                        // Expect to receive symmetric key
                        else {
                            String encryptedSignedKey = (String) sInput.readObject();
                            // Decrypt symmetric key with own private key
                            byte[] signedKey = decryptRSA(hexToByteArray(encryptedSignedKey), keyManager.getPrivateKey());
                            // Verify key with public key of friend
                            PublicKey publicKey = friendCert.getPublicKey();
//                            byte[] keyVerified = decryptRSA(hexToByteArray(encryptedSignedKey), publicKey);
                            SecretKey secretKey = new SecretKeySpec(signedKey, 0, signedKey.length, "AES");
                            setSymmetricKey(secretKey);
                        }


                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }

            }
        }

        public void shutDown()
        {
            try
            {
                keepGoing = false;
                if ( socket != null )
                {
                    sInput.close();
                    socket.close();
                }

                if (serverSocket != null)
                {
                    serverSocket.close();
                }
            }
            catch ( IOException ioe )
            {
                System.out.println("[P2PClient]:: Error closing Socket Server " + ioe.getMessage());
            }
        }
    }
}
