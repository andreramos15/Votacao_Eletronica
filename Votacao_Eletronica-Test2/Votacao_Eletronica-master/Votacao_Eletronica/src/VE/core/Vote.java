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
    
   
    String numeroCC;
    String selectedP;
    int dificulty;

    public Vote( String numeroCC, String selectedP) {
       this(numeroCC + " " + selectedP);
        
    }

    public Vote(String line){
        String elems[] = line.split(" ");
        setnumeroCC(elems[0]);
        setSelectedP(elems[1]);
    }


    public String getnumeroCC() {
        return numeroCC;
    }

    public final void setnumeroCC(String numeroCC) {
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
