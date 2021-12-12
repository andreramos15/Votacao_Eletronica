/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package VE.core;

import java.util.ArrayList;

/**
 *
 * @author andre
 */
public class BlockChain {
    
    ArrayList<Block> BlockChain = new ArrayList<>() ;
    
    public void add(Voto data) throws Exception {
        String prev = getLastBlock();
        Block newBlock = new Block(prev, data);
        BlockChain.add(newBlock);
    }

    public String getLastBlock() {
        // se não houver lá nenhum, devolve 0
        if (BlockChain.isEmpty()) {
            return null;
        }
        // se não for vazio, vai buscar o último elemento 
        // e devolvo o hash
        return BlockChain.get(BlockChain.size() - 1).hash;
    }

    public void print() {
        for (Block block : BlockChain) {
            System.out.println(block.toString());
        }
    }


}
