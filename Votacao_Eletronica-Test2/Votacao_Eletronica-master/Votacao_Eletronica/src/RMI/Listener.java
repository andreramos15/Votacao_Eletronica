/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package RMI;

import VE.core.Block;
import java.rmi.RemoteException;
import java.util.EventListener;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author andre
 */
public interface Listener extends EventListener {
    
public void onConnect(RemoteInterface node);

    public void onDisconnect(RemoteInterface node);

    public void onAbort(Block blk, RemoteInterface node);

    
    public static void notifyConnect(List<Listener> listeners, RemoteInterface node) {
        for (Listener listener : listeners) {
            listener.onConnect(node);
        }
    }

    public static void notifyDisconnect(List<Listener> listeners, RemoteInterface node) {
        for (Listener listener : listeners) {
            listener.onDisconnect(node);
        }
    }

    public static void notifyAbort(List<Listener> listeners, Block blk, RemoteInterface node) {

        try {
            blk.setMiner(node.getMessage());

        } catch (RemoteException ex) {
            Logger.getLogger(Listener.class.getName()).log(Level.SEVERE, null, ex);
        }
        for (Listener listener : listeners) {
            listener.onAbort(blk, node);
        }
    }
}
