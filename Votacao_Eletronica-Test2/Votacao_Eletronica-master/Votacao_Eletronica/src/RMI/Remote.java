/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package RMI;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.rmi.RemoteException;
import java.rmi.server.RemoteServer;
import java.rmi.server.ServerNotActiveException;
import java.rmi.server.UnicastRemoteObject;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
/**
 *
 * @author andre
 */
public class Remote extends UnicastRemoteObject implements RemoteInterface {
    List<Listener> listeners = new ArrayList<>();
    
     public void addListener(Listener node) {
        listeners.add(node);
    }

    String host; // nome do servidor
    String myAdress;

    public Remote(int port) throws RemoteException, UnknownHostException {
        super(port);
         myAdress = RMI.getRemoteName(port, remoteName);
        try {
            //atualizar o nome do servidor
            host = InetAddress.getLocalHost().getHostName();
        } catch (UnknownHostException e) {
            host = "unknow";
        }
    }
    
     public String getAdress() throws RemoteException {
        return myAdress;
    }
     
    public static final String remoteName = "EletroVoting";
    public static final int remotePort = 10_010;
    
    @Override
    public String getMessage() throws RemoteException {
        String client = "";
        try {
            //nome do cliente
            client = RemoteServer.getClientHost();
            System.out.println("Message to " + client);

        } catch (ServerNotActiveException ex) {
            Logger.getLogger(Remote.class.getName()).log(Level.SEVERE, null, ex);
        }
        //retornar uma mensagem
        return host + " say Hello to " + client;
    }
}

