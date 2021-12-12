  /*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package VE.core;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

/**
 *
 * @author andre
 */
public class Block {

    Voto fact;
    protected String hash;
    protected String previous;
    protected long nounce;
    protected int dificuldade;

    // construtor de forma a construir os blocos
    public Block(String previous, Voto data) throws Exception {
        this.previous = previous;
        this.fact = data;
        this.dificuldade = data.dificuldade; 
        Minerar.mine(this); // == this.hash;
    }

    
    // este método é o que calcula os links
    public String calculateHash() throws NoSuchAlgorithmException {
        MessageDigest hasher = MessageDigest.getInstance("SHA-256");
        String msg = (previous + fact.toString() + nounce);
        byte[] hbytes = hasher.digest(msg.getBytes());
        //return (previous + fact + nounce).hashCode();
        return Base64.getEncoder().encodeToString(hbytes);
    }

    // implementar o toString do bloco para que possa aparecer uma string
    @Override
    public String toString() {
        return String.format("%40s %10s(%6d) %20s %b ",
                previous, fact, nounce, hash, isValid());
    }

    // primeiro é preciso recalcular o hash para que depois se possa verificar se é valido ou não
    public boolean isValid() {
        return true;
    }

    public int getSize() {
        return dificuldade;
    }

    public String getFact() {
        return fact.toString();
    }

    public void setNounce(long nonce) {
        this.nounce = nonce;
    }

    public long getNounce() {
        return this.nounce;
    }

    public void setHash(String hash) {
        this.hash = hash;
    }

}
