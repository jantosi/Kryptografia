/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package kryptografia;

/**
 *
 * @author Kuba
 */
class copyPlaintextCryptStrategy implements CryptStrategy {

    public copyPlaintextCryptStrategy() {
    }

    @Override
    public String decrypt(String ciphertext, String decryptKey) {
        return ciphertext;
    }

    @Override
    public String crypt(String plaintext, String cryptKey) {
        return plaintext;
    }

    @Override
    public String getKeyTypeForCrypt() {
        return "public";
    }

    @Override
    public String getKeyTypeForDecrypt() {
        return "private";
    }
    
}
