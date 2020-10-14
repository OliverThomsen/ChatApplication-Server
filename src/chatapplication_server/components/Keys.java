package chatapplication_server.components;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;

public class Keys
{
    public static byte[] sBytes = new byte[]{0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};


    public static final SecretKeySpec SERVER_KEY = new SecretKeySpec(sBytes, "AES");

    public static SecretKeySpec getClientKey(String username) {
        byte[] b = username.getBytes();
        byte[] bx = new byte[]{0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
        byte[] c = new byte[16];
        for (int i = 0; i<16; i++) {
            if (i < b.length) {
                c[i] = (byte) (b[i] + bx[i]);
            } else {
                c[i] = bx[i];
            }
        }
            return new SecretKeySpec(c, "AES");
        }

        /**
         Function for hashing the message
         */
        public static byte[] calculateHmac(SecretKey key, byte[] data)throws GeneralSecurityException {
            Mac hmac = Mac.getInstance("HMacSHA512", "BC");
            hmac.init(key);
            return hmac.doFinal(data);
        }



    }
