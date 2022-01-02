package VE.core;

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */


import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author andre
 */
public class MinerarThr extends Thread {

    AtomicBoolean isDone;
    AtomicLong nounce;
    Block blk;

    public MinerarThr(AtomicBoolean isDone, AtomicLong nounce,Block block) {
        this.isDone = isDone;
        this.nounce = nounce;
        blk=block;
    }

    @Override
    public void run() {
        try {
            MessageDigest hasher = MessageDigest.getInstance("SHA-256");
            String prefix = String.format("%0"+blk.getSize()+"d",0);
            while (!isDone.get()) {
                long num = nounce.getAndIncrement();
                String msg = blk.getFact() + num;
                
                byte[] h= hasher.digest(msg.getBytes());
                String textH = Base64.getEncoder().encodeToString(h);
                if(textH.startsWith(prefix)){
                    nounce.set(num);
                    isDone.set(true);
                }
            
            }

        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(MinerarThr.class.getName()).log(Level.SEVERE, null, ex);
        }

    }
}
