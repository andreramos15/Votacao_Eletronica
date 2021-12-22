/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package VE.core;

import Security.Security;
import Security.SecurityUtils;
import Security.TextUtils;
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
    String hash;// block hash ( previous + data + nonce)
    String previous;// link to previous
    int nounce;// solution of block 


    // construtor de forma a construir os blocos

    public Block(String previous, String data) throws Exception {
        this.previous = previous;
        this.data = data;
        this.hash = "";
        this.nounce = 0;
        this.timestamp = 0;
        this.miner = "unknown";
    }
    
    @Override
    public String toString() {
        return "["+previous+"]" + data + "\n"+ "["+hash+"]" + nounce + miner;
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
    
       public String getPrevious() {
        return previous;
    }

    public void setPrevious(String previous) {
        this.previous = previous;
    }

    public String getData() {
        return data;
    }

    public void setData(String data) {
        this.data = data;
    }

    public int getNounce() {
        return nounce;
    }

    public void setNounce(int nounce) {
        this.nounce = nounce;
    }
    
    public String getHash() {
        return hash;
    }
    
    public void setHash(String myHash) {
        this.hash = myHash;
    }

    public void mine(int zeros) throws Exception{
        String prefix = String.format("%0"+zeros+"d",0);
        int number = 0;
        while (true) {
            number++;
            String message = previous + data + number;
            byte h[] = SecurityUtils.getHash(message.getBytes(), "SHA-256");
            String myHash = TextUtils.BytetoBase64(h);
             //verificar se esta correto
            if (myHash.startsWith(prefix)) {
                this.hash = myHash;
                this.nounce = number;
                break;
            }
        }
    }
}