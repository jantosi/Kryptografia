/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package kryptografia;

/**
 *
 * @author Kuba
 */
public class CryptContext {
    private CryptStrategy strategy;
    
    public void setStrategy(CryptStrategy strategy)
    {
        this.strategy = strategy;
    }
    
    public String decrypt(String ciphertext, String decryptKey)
    {
        return strategy.decrypt(ciphertext, decryptKey);
    }
    
    public String crypt(String plaintext, String cryptKey)
    {
        return strategy.crypt(plaintext, cryptKey);
    }
    
    public String getKeyTypeForCrypt()
    {
        return strategy.getKeyTypeForCrypt();
    }
    public String getKeyTypeForDecrypt()
    {
        return strategy.getKeyTypeForDecrypt();
    }
}
