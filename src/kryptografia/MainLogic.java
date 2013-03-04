/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package kryptografia;

/**
 *
 * @author Kuba
 */
public class MainLogic {

    private CryptContext cctx;
    public String plainTextBuffer, cipherTextBuffer;

    public CryptContext getCctx() {
        return cctx;
    }
    
    public MainLogic() {
        cctx = new CryptContext();
        cctx.setStrategy(new copyPlaintextCryptStrategy()); //default strategy
    }
        
}
