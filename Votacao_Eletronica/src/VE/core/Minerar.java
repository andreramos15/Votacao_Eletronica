/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package VE.core;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

/**
 *
 * @author andre
 */
public class Minerar {

    public static void mine(Block b) throws NoSuchAlgorithmException, InterruptedException {
        /*// é feito para que termine com zeros*/
        
       

        AtomicBoolean isDone = new AtomicBoolean(false);
        AtomicLong nounce = new AtomicLong(0);
        int procs = Runtime.getRuntime().availableProcessors();
        MinerarThr[] miner = new MinerarThr[procs];

        for (int i = 0; i < miner.length; i++) {
            miner[i] = new MinerarThr(isDone, nounce, b);
            miner[i].start();

        }
        for (int i = 0; i < miner.length; i++) {
            miner[i].join();
        }
        b.setNounce(nounce.get());
        MessageDigest hasher = MessageDigest.getInstance("SHA-256");
        byte[] bh = hasher.digest((b.getFact() + b.getNounce()).getBytes());
        b.setHash(Base64.getEncoder().encodeToString(bh));

    }
}
