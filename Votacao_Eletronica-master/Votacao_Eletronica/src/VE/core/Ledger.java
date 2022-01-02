/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package VE.core;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.PrintStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

/**
 *
 * @author Velez
 */
public class Ledger {

    /**
     * transactions in the ledger
     */
    List<Vote> history;

    /**
     * creates a ledger<br>
     *
     */
    public Ledger() {
        history = new ArrayList<>();
    }

    public List<Vote> getHistory(){
        return history;
    }
    
    @Override
    public String toString() {
        StringBuilder txt = new StringBuilder();
        for (Vote vote : history) {
            txt.append(vote.toString()).append("\n");
        }
        return txt.toString();
    }

    /**
     * adds one vote to the ledger
     *
     * @param vote vote
     */
    public void add(Vote vote) {
        history.add(vote);
    }

    /**
     * Save ledger to the file
     *
     * @param fileName name of the file
     * @throws FileNotFoundException
     */
    public void saveFile(String fileName) throws FileNotFoundException {
        PrintStream out = new PrintStream(new File(fileName));
        out.println(toString());
        out.close();
    }

    /**
     *
     * @param filName name of the file
     * @return Ledger ledger in the file
     * @throws FileNotFoundException
     */
    public static Ledger load(String filName) throws FileNotFoundException {
        Scanner file = new Scanner(new File(filName));
        Ledger voting = new Ledger();
        voting.history.clear();
        while (file.hasNext()) {
            //ler uma linha
            String line = file.nextLine();
            //partir a linha nos elementos
            String[] elem = line.split(" ");
            //fazer uma trasção com os elementos
            Vote t = new Vote(elem[0],elem[1]);
            //adicionar a transacao ao objeto
            voting.history.add(t);
        }
        return voting;

    }
}


