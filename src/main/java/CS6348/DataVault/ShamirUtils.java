package CS6348.DataVault;

import com.codahale.shamir.Scheme;

import java.security.SecureRandom;
import java.util.Map;

public class ShamirUtils {

    private final Scheme scheme;

    /**
     * Constructor for Shamir's Secret Scheme.
     *
     * @param  n Split into n many secrets.
     * @param  t How many people need to come togther to recover the secret.
     */
    public ShamirUtils(int n, int t) {
        this.scheme = new Scheme(new SecureRandom(), n, t);
    }

    /**
     * Split the secret.
     *
     * @param  secret The secret you want to share.
     * @return A map that contains a secret number integer and points to a hex string secret.
     */
    public Map<Integer, byte[]> splitSecret(byte[] secret) {
        return this.scheme.split(secret);
    }

    /**
     * Recover the secret.
     *
     * @param  parts A map of secrets (integer -> string)
     * @return The original secret. Does not throw an exception if incorrect.
     */
    public byte[] recoverSecret(Map<Integer, byte[]> parts) {
        return this.scheme.join(parts);
    }

    /**
     * Utility that transforms a hex string into a byte array.
     *
     * @param  s A hex string.
     * @return The byte array of the hex string.
     */
    public static byte[] stringToBytes(String s) throws NumberFormatException {

        if(s.length() % 2 != 0 || !s.matches("^[A-Fa-f0-9]+$")) {
            throw new NumberFormatException("Invalid hexadecimal string.");
        }

        byte[] result = new byte[s.length() / 2];

        for(int x=0; x<s.length(); x+=2) {
            result[x / 2] = (byte) Integer.parseInt(s.substring(x, x+2), 16);
        }

        return result;

    }

    /**
     * Utility that transforms a byte array into a hex string.
     *
     * @param  bytes The byte array.
     * @return A hex string of the byte array.
     */
    public static String bytesToHexString(byte[] bytes) {
        StringBuilder builder = new StringBuilder();
        for (byte b : bytes) {
            builder.append(String.format("%02x", b));
        }
        return builder.toString();
    }

}
