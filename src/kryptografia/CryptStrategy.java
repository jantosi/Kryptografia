/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package kryptografia;

import sun.security.util.BigInt;

/**
 *
 * @author Kuba
 */
public interface CryptStrategy {
    
    public String decrypt(String ciphertext, String decryptKey);
    public String crypt(String plaintext, String cryptKey);
    public String getKeyTypeForCrypt();
    public String getKeyTypeForDecrypt();
}

