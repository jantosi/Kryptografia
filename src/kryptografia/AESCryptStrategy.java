/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package kryptografia;

/**
 *
 * @author Agnieszka
 */
public class AESCryptStrategy implements CryptStrategy {
    
    private int sbox[]= //tablica do podstawien w SubBytes()
    {
        //0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, //0
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, //1
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, //2
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, //3
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, //4
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, //5
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, //6
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, //7
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, //8
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, //9
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, //A
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, //B
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, //C
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, //D
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, //E
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16  //F
    };
    
    private int sboxDe[]= //sbox do deszyfrowania
    {
        //0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb, //0
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, //1
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e, //2
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25, //3
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92, //4
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84, //5
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06, //6
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, //7
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73, //8
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e, //9
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, //A
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4, //B
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f, //C
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, //D
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61, //E
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d  //F
    };

    private int Rcon[][]=  //przy tworzeniu klucza rozszerzonego
    {
        { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36},
        { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
        { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
        { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    };   
    
    private int wejscie[][]; //tablica na tekst jawny
    private int kluczRozszerzony[][]; // wpisywany jest tu klucz podanywany przez uzytkownika, edytowany w GenerowanieKlucza()
    private int szyfrogram[][]; 

    
    public int bitShift(int x) //przesuniecie bitowe
    {
        return ((x<<1) ^ (((x>>7) & 1) * 0x1b));
    }
    
    public int mnozenie(int y, int x) //w trakcie mnożenia macierzyy w MixColumn
    {
        return (((y & 1) * x) ^ ((y>>1 & 1) * bitShift(x)) ^ ((y>>2 & 1) * bitShift(bitShift(x))) ^ 
                ((y>>3 & 1) * bitShift(bitShift(bitShift(x)))) ^ ((y>>4 & 1) * bitShift(bitShift(bitShift(bitShift(x))))));  
    }
        
    public void SubBytes(boolean deszyfrowanie) //operacja podstawienia
    {
        for (int i = 0; i < 4; i++) 
        {
            for (int j = 0; j < 4; j++) 
            { 
                if (deszyfrowanie==false) szyfrogram[i][j] = sbox[szyfrogram[i][j]];  
                if (deszyfrowanie==true) szyfrogram[i][j] = sboxDe[szyfrogram[i][j]];  
            }
        }
    }
        
    public void ShiftRows(boolean deszysfrowanie) //obroty cykliczne w lewo(szysfrowanie) lub w prawo (deszysfrowanie)
    {
        for (int k = 0; k < 4; k++) 
        { 
            int tab []=new int[4];
            
            for (int i = 0; i < 4; i++) 
            {
                tab [i]=szyfrogram[k][i];
            }
            
            for (int i = 0; i < 4; i++) 
            {
                int ws;
                if(deszysfrowanie==true)
                {
                    ws=i-k;
                    if(ws<0) ws=ws+4;
                }
                else ws=i+k;               
                szyfrogram[k][i]=tab [ws%4];
            }
        }
    }
    
    public void MixColumns(boolean deszyfrowanie)
    {
         int szyfrogramTmp[][]=new int[4][4]; 
         
         for (int j = 0; j < 4; j++) 
         {
             if (deszyfrowanie==false)
             {    
                    szyfrogramTmp[0][j]=mnozenie(0x02, szyfrogram[0][j]) ^ mnozenie(0x03, szyfrogram[1][j]) 
                            ^ mnozenie(0x01, szyfrogram[2][j]) ^ mnozenie(0x01, szyfrogram[3][j]);
                    szyfrogramTmp[1][j]=mnozenie(0x01, szyfrogram[0][j]) ^ mnozenie(0x02, szyfrogram[1][j]) 
                            ^ mnozenie(0x03, szyfrogram[2][j]) ^ mnozenie(0x01, szyfrogram[3][j]);
                    szyfrogramTmp[2][j]=mnozenie(0x01, szyfrogram[0][j]) ^ mnozenie(0x01, szyfrogram[1][j]) 
                            ^ mnozenie(0x02, szyfrogram[2][j]) ^ mnozenie(0x03, szyfrogram[3][j]);
                    szyfrogramTmp[3][j]=mnozenie(0x03, szyfrogram[0][j]) ^ mnozenie(0x01, szyfrogram[1][j]) 
                            ^ mnozenie(0x01, szyfrogram[2][j]) ^ mnozenie(0x02, szyfrogram[3][j]);
             }
             
             if (deszyfrowanie==true)
             {    
                    szyfrogramTmp[0][j]=mnozenie(0x0e, szyfrogram[0][j]) ^ mnozenie(0x0b, szyfrogram[1][j]) 
                            ^ mnozenie(0x0d, szyfrogram[2][j]) ^ mnozenie(0x09, szyfrogram[3][j]);
                    szyfrogramTmp[1][j]=mnozenie(0x09, szyfrogram[0][j]) ^ mnozenie(0x0e, szyfrogram[1][j]) 
                            ^ mnozenie(0x0b, szyfrogram[2][j]) ^ mnozenie(0x0d, szyfrogram[3][j]);
                    szyfrogramTmp[2][j]=mnozenie(0x0d, szyfrogram[0][j]) ^ mnozenie(0x09, szyfrogram[1][j]) 
                            ^ mnozenie(0x0e, szyfrogram[2][j]) ^ mnozenie(0x0b, szyfrogram[3][j]);
                    szyfrogramTmp[3][j]=mnozenie(0x0b, szyfrogram[0][j]) ^ mnozenie(0x0d, szyfrogram[1][j]) 
                            ^ mnozenie(0x09, szyfrogram[2][j]) ^ mnozenie(0x0e, szyfrogram[3][j]);
             }
        }
          
        for (int i = 0; i < 4; i++) 
        {
            for (int j = 0; j < 4; j++) 
            {
                szyfrogramTmp[i][j]=szyfrogramTmp[i][j]%256; 
                szyfrogram[i][j]=szyfrogramTmp[i][j];
            }
        }
    }
    
    public void AddRoundKey() //transformacja dodawania klucza; wykorzystuje wygenerowany podlucz
    {
        for (int i = 0; i < 4; i++) 
        {
            for (int j = 0; j < 4; j++) 
            { 
                szyfrogram[i][j] =szyfrogram[i][j]^kluczRozszerzony[i][j];
            }
        }
    }
   
    public void wejscie()
    {
        szyfrogram=new int[4][4];     
        for (int i = 0; i < 4; i++) 
        {
            for (int j = 0; j < 4; j++) 
            { 
                szyfrogram[i][j] = wejscie[i][j];  
            }
        }   
    }
    
    public void kluczZero(String klucz)
    {
        kluczRozszerzony= new int[4][4];
        stringToInt(klucz, kluczRozszerzony);  
    }
    
    public void GenerowanieKlucza(int obrot) //generowanie klucza rozszerzonego z podstawowego
    {
        int kluczRozszerzonyTmp[][]=new int[4][4];

        for (int k = 0; k < 4; k++) 
        { 
            if (k==0)
            {
                for (int i = 0; i < 4; i++) 
                { 
                    int ws=i+1;
                    if(ws>3) ws=ws-4;
                    kluczRozszerzonyTmp[i][k]=sbox[ kluczRozszerzony[ws][3] ]^kluczRozszerzony[i][k]^ Rcon[i][obrot-1];
                }
            }
            else
            {
                for (int i = 0; i < 4; i++) 
                {
                    kluczRozszerzonyTmp[i][k]=kluczRozszerzony[i][k]^kluczRozszerzonyTmp[i][k-1];
                }
            }
        }
        
        for (int i = 0; i < 4; i++) 
        {
            for (int j = 0; j < 4; j++) 
            { 
                kluczRozszerzony[i][j] = kluczRozszerzonyTmp[i][j];  
            }
        }
    }
    
    public void WyswietlSzyfrogram() 
    {
        for (int i = 0; i < 4; i++) 
        {
            String linia= new String();
            for (int j = 0; j < 4; j++) 
            {
                linia=linia+szyfrogram[i][j]+'\t';
            }
            System.out.println(linia);
        }
    } 

    public String cryptRound(String blok, String cryptKey) 
    {
        wejscie=new int[4][4];
        stringToInt(blok, wejscie);
        wejscie();
        kluczZero(cryptKey);
        //WyswietlSzyfrogram();
        AddRoundKey();
        //WyswietlSzyfrogram();
        
        for (int i = 1; i < 10; i++) 
        { 
            SubBytes(false);
            //WyswietlSzyfrogram();
            ShiftRows(false);
            //WyswietlSzyfrogram();
            MixColumns(false);
            //WyswietlSzyfrogram();
            GenerowanieKlucza(i);
            AddRoundKey();
            //WyswietlSzyfrogram();
        }
        SubBytes(false);
        //WyswietlSzyfrogram();
        ShiftRows(false);
        //WyswietlSzyfrogram();
        GenerowanieKlucza(10);
         AddRoundKey();
        //WyswietlSzyfrogram();

        return intToString();
    }

    public String decryptRound(String blok, String decryptKey) 
    {
        wejscie=new int[4][4];
        stringToInt(blok, wejscie);
        wejscie();
        kluczZero(decryptKey);
        
        for (int i = 1; i < 11; i++) 
        { 
            GenerowanieKlucza(i);
        }
        AddRoundKey();
        //WyswietlSzyfrogram();

        for (int j = 10; j > 1; j--) 
        {        
            ShiftRows(true);
            //WyswietlSzyfrogram();
            SubBytes(true);
            //WyswietlSzyfrogram();

            kluczZero(decryptKey);
            for (int i = 1; i < j; i++) 
            { 
                GenerowanieKlucza(i);
            }
            AddRoundKey();
            //WyswietlSzyfrogram();
 
            MixColumns(true);
            //WyswietlSzyfrogram();
        }
  
        ShiftRows(true);
        //WyswietlSzyfrogram();
        SubBytes(true);
        //WyswietlSzyfrogram();

        kluczZero(decryptKey);
        //WyswietlKlucz();
        AddRoundKey();
        //WyswietlSzyfrogram();        
                   
        return intToString();
    }

    @Override
    public String decrypt(String ciphertext, String decryptKey) 
    {
        String wynik= new String();
        int dlugosc=ciphertext.length();
        int ilosc=dlugosc/16;
        if (dlugosc%16!=0) ilosc++;

        for (int i = 0; i < ilosc; i++) 
        {
            String blok= new String();
            for (int j = 0; j < 16; j++) 
            {
                if (i*16+j<dlugosc) blok=blok+ciphertext.charAt(i*16+j);
            }
            blok=decryptRound(blok, decryptKey);
            wynik=wynik+blok;
        }
        return wynik;
    }

    @Override
    public String crypt(String plaintext, String cryptKey) 
    {
        String wynik= new String();
        int dlugosc=plaintext.length();
        int ilosc=dlugosc/16;
        if (dlugosc%16!=0) ilosc++;
   
        for (int i = 0; i < ilosc; i++) 
        {
            String blok= new String();
            for (int j = 0; j < 16; j++) 
            {
                if (i*16+j<dlugosc) blok=blok+plaintext.charAt(i*16+j);
            }
            blok=cryptRound(blok, cryptKey);
            wynik=wynik+blok;
        }
        return wynik;
    }
    
    @Override
    public String getKeyTypeForCrypt() 
    {
        return "private";
    }

    @Override
    public String getKeyTypeForDecrypt() 
    {
        return "private";
    }
    
    public void stringToInt(String blok, int tab[][])     //zamiana tektu na Intiger
    {
        int i = 0;
        for (int j = 0; j < 4; j++) 
        {
            for (int k = 0; k < 4; k++) 
            {
                if(blok.length()!=i)
                {
                    tab[j][k]=blok.codePointAt(i);
                    //lub
                            //=(byte) plaintext.charAt(i);
                    i++;
                }
            }
        }
    }
    
    public String intToString()
    {
        StringBuffer bufor = new StringBuffer();

        for (int i = 0; i < 4; i++) 
        {
            for (int j = 0; j < 4; j++) 
            {
                bufor.append((char) szyfrogram[i][j]);
            }
        }
        return bufor.toString();
     }
    
}
