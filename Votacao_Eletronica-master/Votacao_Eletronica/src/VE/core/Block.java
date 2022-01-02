/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package VE.core;

import Security.Security;
import Security.SecurityUtils;
import java.io.IOException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Date;
import java.util.logging.Level;
import java.util.logging.Logger;
import jdk.jshell.execution.Util;

/**
 *
 * @author andre
 */
public class Block {

    String data; // block data
    long timestamp; // time o block validation
    String miner; // miner name
    protected String hash;// block hash ( previous + data + nonce)
    protected String previous;// link to previous
    protected long nounce;// solution of block 
    protected int dificulty; // number of  zeros


    // construtor de forma a construir os blocos

    public Block(String previous, String data, int dificulty) throws Exception {
        this.previous = previous;
        this.data = data;
        this.dificulty = dificulty;
        this.hash = "";
        this.nounce = 0;
        this.timestamp = 0;
        this.miner = "unknown";
    }
    public void setSolution(long solution, String miner){
        this.nounce = solution;
        this.hash = getHash(getMessage(), nounce);
        timestamp = new Date().getTime();
        this.miner = miner;
    }
    public void startMine() {
        this.nounce = 0;
        while(!getHash(getMessage(), nounce).startsWith("000")){
             this.nounce ++;
        }
        setSolution(this.nounce,"eu");
    }
    
    // este método é o que calcula os links
    public String calculateHash() throws NoSuchAlgorithmException {
        MessageDigest hasher = MessageDigest.getInstance("SHA-256");
        String msg = (previous + data.toString() + nounce);
        byte[] hbytes = hasher.digest(msg.getBytes());
        //return (previous + fact + nounce).hashCode();
        return Base64.getEncoder().encodeToString(hbytes);
    }

    // implementar o toString do bloco para que possa aparecer uma string
    public String toString() {
        return "Hash: " + previous + dificulty + data + hash + nounce + miner;
    }
    
    
    /**
     * message of the block
     *
     * @return
     */
    public String getMessage() {
        return previous + data + dificulty;
    }

   /**
     * validates the block
     *
     * @return
     */
    public boolean isValid() {
        return getHash(getMessage(), nounce).equals(hash);
    }
    
    public static String getHash(String msg, long nounce) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return Base64.getEncoder().encodeToString(digest.digest((msg + nounce).getBytes()));
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(Block.class.getName()).log(Level.SEVERE, null, ex);
        }
        return "ERROR";
    }

    void setHash(String encodeToString) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    long getFact() {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    String getSize() {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

}