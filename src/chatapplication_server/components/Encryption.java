package chatapplication_server.components;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;

import static chatapplication_server.components.Helper.byteArrayToHex;
import static chatapplication_server.components.Keys.SERVER_KEY;

public class Encryption {
    public static Cipher getCipher(int mode, Key key) {
        Security.addProvider(new BouncyCastleProvider());
        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance("AES");
            if (mode == Cipher.DECRYPT_MODE) {
                byte[] sBytes = new byte[]{0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
                cipher.init(mode, SERVER_KEY, new IvParameterSpec(sBytes));
            } else {
                cipher.init(mode, SERVER_KEY);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return cipher;
    }
}
