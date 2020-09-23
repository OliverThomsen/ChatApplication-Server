package chatapplication_server.components;

import javax.crypto.spec.SecretKeySpec;

public class Keys
{
    public static byte[] sBytes = new byte[]{0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};


    public static final SecretKeySpec SERVER_KEY = new SecretKeySpec(sBytes, "RawBytes");

    public static SecretKeySpec getClientKey(String username) {
        byte[] b = username.getBytes();
        return new SecretKeySpec(b, "RawBytes");
    }
}
