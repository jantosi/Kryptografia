package kryptografia;

import java.math.BigInteger;
import java.util.Random;
import static kryptografia.ElGamalCryptStrategy.bigIntToString;

public class ElGamalCryptStrategy implements CryptStrategy {

    private BigInteger p, g, h, a, r, pom;
    private int bit = 512;
    private Random random = new Random();

    //generuje klucze
    //publiczne:  p, g, h 
    //prywatne: a
    public void init() {
        a = new BigInteger(bit - 2, new Random());
        p = BigInteger.probablePrime(bit, new Random());
        g = new BigInteger(bit - 2, new Random());
        h = g.modPow(a, p);
        System.out.println("klucze publiczne:\np=" + p + "\ng=" + g + "\nh=" + h);
        System.out.println("klucz prywatny:\na=" + a);


    }

    @Override
    public String decrypt(String ciphertext, String decryptKey) {

        String[] wiersze = ciphertext.split("\n");
        BigInteger[] bi_table = new BigInteger[wiersze.length];
        for (int i = 0; i < wiersze.length; i++) {
            bi_table[i] = new BigInteger(wiersze[i]);
        }

        BigInteger[] cipher = bi_table;
        String d = new String();
        for (int i = 0; i < cipher.length; i += 2) {
            //d=(( 1/(c1^a) mod p) * c2) mod p
            d += bigIntToString(cipher[i].multiply(cipher[i + 1].modPow(a, p).modInverse(p)).mod(p));
//            System.out.println("d" + i + "=" + d);
        }
        return d;

    }

    @Override
    public String crypt(String plaintext, String cryptKey) {
        //generuje klucze
        init();

        //r
        pom = p.subtract(BigInteger.ONE);
        r = BigInteger.probablePrime(bit, new Random());
        while (true) {
            if (r.gcd(pom).equals(BigInteger.ONE)) {
                break;
            } else {
                r = r.nextProbablePrime();
            }
        }

        int ileZnakow = (p.bitLength()) / 8;
        //reszta
        while (plaintext.length() % ileZnakow != 0) {
            //zwiekszenie ciagu znakow
            plaintext += ' ';
        }



        //szyfrogram jest 2x dluzszy od tekstu jawnego
        int part = plaintext.length() / ileZnakow;
        BigInteger[] cipher = new BigInteger[part * 2];
        for (int i = 0, j = 0; i < part; i++, j += 2) {
            String s = plaintext.substring(ileZnakow * i, ileZnakow * (i + 1));
            cipher[j] = stringToBigInt(s);

//            System.out.println("crypt " + i);
            //para liczb c1, c2 tworzy kryptogram

            //c1=g^r mod p
            cipher[j + 1] = g.modPow(r, p);
//            System.out.println("c1=" + cipher[j + 1]);

            //c2=(m*(h^r mod p))mod p
            cipher[j] = cipher[j].multiply(h.modPow(r, p)).mod(p);
//            System.out.println("c2=" + cipher[j]);
        }


        String str = new String();
        BigInteger[] bi_table = cipher;
        for (int i = 0; i < bi_table.length; i++) {
            str += bi_table[i] + "\n";
        }


        return str;
    }

    @Override
    public String getKeyTypeForCrypt() {
        return "";
    }

    @Override
    public String getKeyTypeForDecrypt() {
        return "";
    }

    //stringa to BigIntegera 
    public BigInteger stringToBigInt(String str) {
        byte[] tab = new byte[str.length()];
        for (int i = 0; i < tab.length; i++) {
            tab[i] = (byte) str.charAt(i);
        }
        return new BigInteger(1, tab);
    }

    //konwertuje BigIntegera na string
    public static String bigIntToString(BigInteger n) {
        byte[] tab = n.toByteArray();
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < tab.length; i++) {
            sb.append((char) tab[i]);
        }
        return sb.toString();
    }
}
