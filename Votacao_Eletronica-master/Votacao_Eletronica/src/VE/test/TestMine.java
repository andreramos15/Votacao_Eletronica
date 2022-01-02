/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package VE.test;

import VE.core.Block;

/**
 *
 * @author Velez
 */
public class TestMine {
    public static void main (String[] arg) throws Exception {
        Block b1 = new Block ("0000", "manuel votou no ps");
        b1.mine();
        System.out.println("b1" + b1.toString());
    }
}
