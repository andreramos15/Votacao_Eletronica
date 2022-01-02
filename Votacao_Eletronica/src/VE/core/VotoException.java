
package VE.core;


public class VotoException extends Exception{
    
    public VotoException(String message,double value) {
        //put the value in the message 
        super(message + " value = " + value);    
    }
        
    
    public VotoException(String message) {
        super(message);    
    }

   
    private static final long serialVersionUID = 202109271625L;

}