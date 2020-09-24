/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package chatapplication_server.components.ClientSocketEngine;

import SocketActionMessages.ChatMessage;
import chatapplication_server.components.ConfigManager;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
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
import java.security.spec.InvalidKeySpecException;
import java.util.logging.Level;
import java.util.logging.Logger;

import static chatapplication_server.components.GFG.findPrimitive;
import static chatapplication_server.components.GFG.power;
import static java.math.BigInteger.probablePrime;

/**
 *
 * @author atgianne
 */
public class P2PClient extends JFrame implements ActionListener
{
    private String host;
    private String port;
    private final JTextField tfServer;
    private final JTextField tfPort;
    private final JTextField tfsPort;
    private final JLabel label;
    private final JTextField tf;
    private final JTextArea ta;
    protected boolean keepGoing;
    JButton send, start;

    SecureRandom rnd = new SecureRandom();
    private double secretKey;
    int p;
    int g;
    int a;
    int b;
    int A;
    int B;

    P2PClient(){
        super("P2P Client Chat");
        host=ConfigManager.getInstance().getValue( "Server.Address" );
        port=ConfigManager.getInstance().getValue( "Server.PortNumber" );

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
        start=new JButton("Start");
        start.addActionListener(this);

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


        send = new JButton("Send");
        send.addActionListener(this);
        JPanel southPanel = new JPanel();
        southPanel.add(send);
        southPanel.add(start);
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
    }

    @Override
    public void actionPerformed(ActionEvent e) {
        Object o = e.getSource();
        if(o == send){
            if ( tfPort.getText().equals( ConfigManager.getInstance().getValue( "Server.PortNumber" ) ) )
            {
                display( "Cannot give the same port number as the Chat Application Server - Please give the port number of the peer client to communicate!\n" );
                return;
            }
            this.send(tf.getText());
        }
        if(o == start){
            new ListenFromClient().start();
        }
    }

    public void display(String str) {
        ta.append(str + "\n");
        ta.setCaretPosition(ta.getText().length() - 1);
    }

    private void beginDH() {
        p = probablePrime(16, new SecureRandom()).intValue();
        g = findPrimitive(p);

        System.out.println("Alice p:" + p);
        System.out.println("Alice g:" + g);
        send("I:" + p + "," + g);

        SecureRandom ranGen = new SecureRandom();
        b = ranGen.nextInt(99999) & Integer.MAX_VALUE;
        B = power(g, b, p); // calculation of A

        System.out.println("Alice B:" + B);

        send("B:" + B);
    }



    private void computeA(String msg) {
        int i = msg.indexOf(",");
        p = Integer.parseInt(msg.substring(0,i));
        g = Integer.parseInt(msg.substring(i+1));
        System.out.println("Bob p:" + p);
        System.out.println("Bob g:" + g);

        SecureRandom ranGen = new SecureRandom();
        a = ranGen.nextInt(99999) & Integer.MAX_VALUE;

        A = power(g, a, p); // calculation of A

        System.out.println("Bob A: " + A);

        send("A:" + A);
    }

    private void computeB() {
        SecureRandom ranGen = new SecureRandom();
        b = ranGen.nextInt(99999) & Integer.MAX_VALUE;
        B = power(g, b, p); // calculation of A

        System.out.println("Alice B:" + B);

        send("B:" + B);
    }

    private double computeKeyFromB(String msg) {
        B = Integer.parseInt(msg);
        System.out.println("Bob B: " + B);
        return power(B, a, p);
    }

    private double computeKeyFromA(String msg) {
        A = Integer.parseInt(msg);
        System.out.println("Alice A: " + A);
        return power(A,b, p);
    }


    public boolean send(String str){
        Socket socket;
        ObjectOutputStream sOutput;		// to write on the socket
        // try to connect to the server
        try {
            socket = new Socket(tfServer.getText(), Integer.parseInt(tfPort.getText()));
        }
        // if it failed not much I can so
        catch(Exception ec) {
            display("Error connectiong to server:" + ec.getMessage() + "\n");
            return false;
        }

        /* Creating both Data Stream */
        try
        {
//			sInput  = new ObjectInputStream(socket.getInputStream());
            sOutput = new ObjectOutputStream(socket.getOutputStream());
        }
        catch (IOException eIO) {
            display("Exception creating new Input/output Streams: " + eIO);
            return false;
        }

        try {
            sOutput.writeObject(new ChatMessage(str.length(), str));
            display("You: " + str);
            sOutput.close();
            socket.close();
            if (str.equals("Start DH")) {
                beginDH();
            }
        } catch (IOException ex) {
            display("Exception creating new Input/output Streams: " + ex);
        }

        return true;
    }

    private class ListenFromClient extends Thread{
        public ListenFromClient() {
            keepGoing=true;
        }

        @Override
        public void run() {
            try
            {
                // the socket used by the server
                ServerSocket serverSocket = new ServerSocket(Integer.parseInt(tfsPort.getText()));
                //display("Server is listening on port:"+tfsPort.getText());
                ta.append("Server is listening on port:"+tfsPort.getText() + "\n");
                ta.setCaretPosition(ta.getText().length() - 1);

                // infinite loop to wait for connections
                while(keepGoing)
                {
                    // format message saying we are waiting

                    Socket socket = serverSocket.accept();  	// accept connection

                    ObjectInputStream sInput=null;		// to write on the socket

                    /* Creating both Data Stream */
                    try
                    {
                        sInput = new ObjectInputStream(socket.getInputStream());
                    }
                    catch (IOException eIO) {
                        display("Exception creating new Input/output Streams: " + eIO);
                    }

                    try {
                        String msg = ((ChatMessage) sInput.readObject()).getMessage();
                        System.out.println("Msg:"+msg);
                        switch(msg.substring(0,2)) {
                            case "I:":
                                System.out.println("Client receives p and g");
                                computeA(msg.substring(2));
                                break;
                            case "A:":
                                System.out.println("Client receives A");
//                                computeB();
                                secretKey = computeKeyFromA(msg.substring(2));
                                System.out.println("Alice secret key: " + secretKey);
                                break;
                            case "B:":
                                System.out.println("Client receives A");
                                secretKey = computeKeyFromB(msg.substring(2));
                                System.out.println("Bob secret key:" + secretKey);
                                break;
                        }

                        display(socket.getInetAddress()+": " + socket.getPort() + ": " + msg);
                        sInput.close();
                        socket.close();
                    } catch (IOException ex) {
                        display("Exception creating new Input/output Streams: " + ex);
                    } catch (ClassNotFoundException ex) {
                        Logger.getLogger(P2PClient.class.getName()).log(Level.SEVERE, null, ex);
                    }
                }
            }
            // something went bad
            catch (IOException e) {
//            String msg = sdf.format(new Date()) + " Exception on new ServerSocket: " + e + "\n";
//			display(msg);
            }
        }
    }


}