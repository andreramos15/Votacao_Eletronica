/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package RMI;

import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.UnknownHostException;
import java.rmi.Naming;
import java.rmi.NotBoundException;
import java.rmi.Remote;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.server.UnicastRemoteObject;

/**
 *
 * @author andre
 */
public class RMI {

    /**
     * gets the RMI name of an remote object in the server
     *
     * @param port listen port
     * @param objectName name of object
     * @return remote RMI adress
     */
    public static String getRemoteName(int port, String objectName) throws UnknownHostException {
        //get adress of the localhost        
        return getRemoteName(InetAddress.getLocalHost().getHostAddress(), port, objectName);
    }

    /**
     * gets the RMI name of an remote object 
     *
     * @param host name of remote host
     * @param port listen port
     * @param objectName name of object
     * @return remote RMI adress
     */
    public static String getRemoteName(String host, int port, String objectName) {
        //RMI format of names
        return String.format("//%s:%d/%s", host, port, objectName);
    }

    /**
     * Makes a remote object available on the server
     *
     * @param remote remote object
     * @param port port to receive calls
     * @param objectName name of the object
     * @throws java.rmi.RemoteException
     * @throws java.net.UnknownHostException
     * @throws java.net.MalformedURLException
     */
    public static void startRemoteObject(Remote remote, int port, String objectName)
            throws RemoteException, UnknownHostException, MalformedURLException {
        //create port registry  
        LocateRegistry.createRegistry(port);
        //create address of remote object        
        String address = getRemoteName(port, objectName);
        //Rebind remote to the adress
        Naming.rebind(address, remote);
        System.out.println("remote Object " + address + " avaiable.");
    }

    /**
     * Gets a remote object
     *
     * @param host name of the host
     * @param port number of listen port
     * @param objectName name of the object
     * @return remote object
     * @throws java.rmi.NotBoundException
     * @throws java.net.MalformedURLException
     * @throws java.rmi.RemoteException
     */
    public static Remote getRemote(String host, int port, String objectName)
            throws NotBoundException, MalformedURLException, RemoteException {
        //gets remote refefence
        return Naming.lookup(getRemoteName(host, port, objectName));
    }

    /**
     * Removes a remote object from server
     *
     * @param remote object
     * @param port port to receive calls
     * @param objectName name of the object
     * @throws java.rmi.RemoteException
     * @throws java.net.UnknownHostException
     */
    public static void stopRemoteObject(Remote remote, int port, String objectName)
            throws RemoteException, UnknownHostException {
        //address of the remote object 
        String address = getRemoteName(port, objectName);
        //remove object
        UnicastRemoteObject.unexportObject(remote, true);
        System.out.println("remote Object :" + address + " NOT avaiable ");
    }

    //::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
    private static final long serialVersionUID = 201512152207L;
    //:::::::::::::::::::::::::::  Copyright(c) M@nso  2018  :::::::::::::::::::
    ///////////////////////////////////////////////////////////////////////////
}
