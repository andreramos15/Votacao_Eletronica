/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package VE.core;

import static java.lang.ProcessBuilder.Redirect.from;
import static java.lang.ProcessBuilder.Redirect.to;
import static javax.management.Query.value;

/**
 *
 * @author andre
 */
public class Voto {
    
   
    int numeroCC;
    String voto;
    int dificuldade;

    public Voto( int numeroCC, String voto, int dificuldade) {
       
        this.numeroCC = numeroCC;
        this.voto = voto;
        this.dificuldade = dificuldade;
    }

    public Voto(String line) throws VotoException {
        String elems[] = line.split(" ");
        setnumeroCC(Integer.valueOf(elems[1]));
        setvoto(elems[2]);
    }

    public Voto(String text, Integer valueOf) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

   

    

    public int getnumeroCC() {
        return numeroCC;
    }

    public final void setnumeroCC(int numeroCC) throws VotoException {
        //verify if the parameter is a string valid
        if (numeroCC > 8) {
            throw new VotoException("Illegal value ", numeroCC);
        }
        this.numeroCC = numeroCC;
    }

    public String getvoto() {
        return voto;
    }

    public final void setvoto(String voto) throws VotoException {
        //verify if the parameter is number valid
        this.voto = voto;
    }

    public int getDificuldade() {
        return dificuldade;
    }

    public void setDificuldade(int dificuldade) {
        this.dificuldade = dificuldade;
    }
    

    @Override
    public String toString() {
        return  numeroCC + " " + voto;
    }


   
      
    
}
