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
public class Vote {
    
   
    int numeroCC;
    String selectedP;
    int dificulty;

    public Vote( int numeroCC, String selectedP, int dificulty) {
       
        this.numeroCC = numeroCC;
        this.selectedP = selectedP;
        this.dificulty = dificulty;
    }

    public Vote(String line){
        String elems[] = line.split(" ");
        setnumeroCC(Integer.valueOf(elems[1]));
        setSelectedP(elems[2]);
    }

    public Vote(String text, Integer valueOf) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    public int getnumeroCC() {
        return numeroCC;
    }

    public final void setnumeroCC(int numeroCC) {
        this.numeroCC = numeroCC;
    }

    public String getvoto() {
        return selectedP;
    }

    public final void setSelectedP(String voto){
        //verify if the parameter is number valid
        this.selectedP = voto;
    }

    public int getDificulty() {
        return dificulty;
    }

    public void setDificulty(int dificulty) {
        this.dificulty = dificulty;
    }

    @Override
    public String toString() {
        return  numeroCC + " " + selectedP;
    }


}
