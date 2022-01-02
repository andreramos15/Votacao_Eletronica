/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package VE.test;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

/**
 *
 * @author andre
 */
public class TestHash {
    public static void main(String[] args) throws NoSuchAlgorithmException {
        
        MessageDigest hasher = MessageDigest.getInstance("SHA-256");
        String txt = "teste";
        String key = "000";
        System.out.println(txt);
        int i = 0;
        
        while(true) {
           //calcular o hash da ms
           String msg = txt + i++;
           // vamos agarrar nesta msg e calcular o hash dela
           byte[] h = hasher.digest(msg.getBytes());
           String txtH = Base64.getEncoder().encodeToString(h);
           
            System.out.println(
            
                        (msg) + " \t " + txtH);
            
            if( txtH.startsWith(key))
                break;
        }
    }
}
