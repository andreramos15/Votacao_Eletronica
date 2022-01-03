//::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::: 
//::                                                                         ::
//::     Antonio Manuel Rodrigues Manso                                      ::
//::                                                                         ::
//::     I N S T I T U T O    P O L I T E C N I C O   D E   T O M A R        ::
//::     Escola Superior de Tecnologia de Tomar                              ::
//::     e-mail: manso@ipt.pt                                                ::
//::     url   : http://orion.ipt.pt/~manso                                  ::
//::                                                                         ::
//::     This software was build with the purpose of investigate and         ::
//::     learning.                                                           ::
//::                                                                         ::
//::                                                               (c)2021   ::
//:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
//////////////////////////////////////////////////////////////////////////////
package Security;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * Created on 06/10/2021, 08:55:09
 *
 * @author IPT - computer
 * @version 1.0
 */
public class TextUtils {

    //::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::    
    //:::::::::::::::        T E X T   U T I L S             :::::::::::::::::::
    //::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::    
    public static String byteToString(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }

    public static String stringToBase64(String data) {
        return Base64.getEncoder().encodeToString(data.getBytes(StandardCharsets.UTF_8));
    }

    public static String base64ToString(String data) {
        return new String(Base64.getDecoder().decode(data), StandardCharsets.UTF_8);
    }
    public static String BytetoBase64(byte data[]) {
        return Base64.getEncoder().encodeToString(data);
    }

    public static byte[] base64ToByte(String data) {
        return Base64.getDecoder().decode(data);
    }

    //::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
    private static final long serialVersionUID = 202110060855L;
    //:::::::::::::::::::::::::::  Copyright(c) M@nso  2021  :::::::::::::::::::
    ///////////////////////////////////////////////////////////////////////////
}
