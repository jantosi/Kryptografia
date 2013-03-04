/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package kryptografia;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.JFileChooser;
import javax.swing.UIManager;

/**
 *
 * @author Kuba
 */
public class MainUI extends javax.swing.JFrame {
    private static MainLogic mainLogic;

    /**
     * Creates new form MainUI
     */
    public MainUI() {
        initComponents();
        /*hide unused components*/
        statusBarProgressBar.setVisible(false);
        statusBarProgressLabel.setVisible(false);
        
        mainLogic.plainTextBuffer = inputTextArea.getText();
        mainLogic.cipherTextBuffer = outputTextArea.getText();
    }

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        modeMenuRadioGroup = new javax.swing.ButtonGroup();
        jScrollPane1 = new javax.swing.JScrollPane();
        inputTextArea = new javax.swing.JTextArea();
        jScrollPane2 = new javax.swing.JScrollPane();
        outputTextArea = new javax.swing.JTextArea();
        statusBarPanel = new javax.swing.JPanel();
        statusBarLabel1 = new javax.swing.JLabel();
        statusBarProgressBar = new javax.swing.JProgressBar();
        statusBarProgressLabel = new javax.swing.JLabel();
        staticLabel1 = new javax.swing.JLabel();
        staticLabel2 = new javax.swing.JLabel();
        mainCryptActionButton = new javax.swing.JButton();
        privateKeyTextField = new javax.swing.JTextField();
        publicKeyTextField = new javax.swing.JTextField();
        privateKeyStaticLabel = new javax.swing.JLabel();
        privateKeyStaticLabel1 = new javax.swing.JLabel();
        mainDecryptActionButton = new javax.swing.JButton();
        jMenuBar1 = new javax.swing.JMenuBar();
        fileMenu = new javax.swing.JMenu();
        openFileToPlaintextMenuItem = new javax.swing.JMenuItem();
        openFileToCiphertextMenuItem = new javax.swing.JMenuItem();
        savePlainTextToFileMenuItem = new javax.swing.JMenuItem();
        saveCipherTextToFileMenuItem = new javax.swing.JMenuItem();
        appModeMenu = new javax.swing.JMenu();
        copyPlaintextModeMenuItem = new javax.swing.JRadioButtonMenuItem();
        AESCipherModeMenuItem = new javax.swing.JRadioButtonMenuItem();
        ElGamalCipherModeMenuItem = new javax.swing.JRadioButtonMenuItem();
        DSASignModeMenuItem = new javax.swing.JRadioButtonMenuItem();

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);
        setTitle("Kryptografia");
        setIconImages(null);

        inputTextArea.setColumns(20);
        inputTextArea.setFont(inputTextArea.getFont().deriveFont(inputTextArea.getFont().getSize()+4f));
        inputTextArea.setRows(5);
        inputTextArea.setText("Treść wejścia");
        inputTextArea.addCaretListener(new javax.swing.event.CaretListener() {
            public void caretUpdate(javax.swing.event.CaretEvent evt) {
                inputTextAreaCaretUpdate(evt);
            }
        });
        jScrollPane1.setViewportView(inputTextArea);

        outputTextArea.setColumns(20);
        outputTextArea.setFont(outputTextArea.getFont().deriveFont(outputTextArea.getFont().getSize()+4f));
        outputTextArea.setRows(5);
        outputTextArea.setText("Treść wyjścia");
        outputTextArea.addCaretListener(new javax.swing.event.CaretListener() {
            public void caretUpdate(javax.swing.event.CaretEvent evt) {
                outputTextAreaCaretUpdate(evt);
            }
        });
        jScrollPane2.setViewportView(outputTextArea);

        statusBarPanel.setBorder(javax.swing.BorderFactory.createEtchedBorder());

        statusBarLabel1.setText("Gotowy");

        statusBarProgressLabel.setHorizontalAlignment(javax.swing.SwingConstants.TRAILING);
        statusBarProgressLabel.setText("Opis postępu obecnej operacji");

        javax.swing.GroupLayout statusBarPanelLayout = new javax.swing.GroupLayout(statusBarPanel);
        statusBarPanel.setLayout(statusBarPanelLayout);
        statusBarPanelLayout.setHorizontalGroup(
            statusBarPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(statusBarPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(statusBarLabel1, javax.swing.GroupLayout.PREFERRED_SIZE, 546, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(statusBarProgressLabel, javax.swing.GroupLayout.DEFAULT_SIZE, 158, Short.MAX_VALUE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(statusBarProgressBar, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap())
        );
        statusBarPanelLayout.setVerticalGroup(
            statusBarPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(statusBarPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                .addComponent(statusBarLabel1)
                .addComponent(statusBarProgressLabel))
            .addComponent(statusBarProgressBar, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
        );

        staticLabel1.setText("Tekst jawny");

        staticLabel2.setText("Kryptogram");

        mainCryptActionButton.setText("Szyfruj");
        mainCryptActionButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                mainCryptActionButtonActionPerformed(evt);
            }
        });

        privateKeyTextField.setText("(klucz prywatny)");

        publicKeyTextField.setText("(klucz publiczny)");

        privateKeyStaticLabel.setText("Klucz prywatny");

        privateKeyStaticLabel1.setText("Klucz publiczny");

        mainDecryptActionButton.setText("Odszyfruj");
        mainDecryptActionButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                mainDecryptActionButtonActionPerformed(evt);
            }
        });

        fileMenu.setText("Plik");

        openFileToPlaintextMenuItem.setText("Otwórz plik z tekstem jawnym...");
        openFileToPlaintextMenuItem.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                openFileToPlaintextMenuItemActionPerformed(evt);
            }
        });
        fileMenu.add(openFileToPlaintextMenuItem);

        openFileToCiphertextMenuItem.setText("Otwórz plik z kryptogramem...");
        openFileToCiphertextMenuItem.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                openFileToCiphertextMenuItemActionPerformed(evt);
            }
        });
        fileMenu.add(openFileToCiphertextMenuItem);

        savePlainTextToFileMenuItem.setText("Zapisz tekst jawny...");
        savePlainTextToFileMenuItem.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                savePlainTextToFileMenuItemActionPerformed(evt);
            }
        });
        fileMenu.add(savePlainTextToFileMenuItem);

        saveCipherTextToFileMenuItem.setText("Zapisz kryptogram...");
        saveCipherTextToFileMenuItem.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                saveCipherTextToFileMenuItemActionPerformed(evt);
            }
        });
        fileMenu.add(saveCipherTextToFileMenuItem);

        jMenuBar1.add(fileMenu);

        appModeMenu.setText("Tryb działania");

        modeMenuRadioGroup.add(copyPlaintextModeMenuItem);
        copyPlaintextModeMenuItem.setSelected(true);
        copyPlaintextModeMenuItem.setText("Brak szyfrowania (kopiowanie wejścia na wyjście)");
        copyPlaintextModeMenuItem.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                copyPlaintextModeMenuItemActionPerformed(evt);
            }
        });
        appModeMenu.add(copyPlaintextModeMenuItem);

        modeMenuRadioGroup.add(AESCipherModeMenuItem);
        AESCipherModeMenuItem.setText("Szyfrowanie AES");
        AESCipherModeMenuItem.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                AESCipherModeMenuItemActionPerformed(evt);
            }
        });
        appModeMenu.add(AESCipherModeMenuItem);

        modeMenuRadioGroup.add(ElGamalCipherModeMenuItem);
        ElGamalCipherModeMenuItem.setText("Szyfrowanie ElGamal");
        ElGamalCipherModeMenuItem.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                ElGamalCipherModeMenuItemActionPerformed(evt);
            }
        });
        appModeMenu.add(ElGamalCipherModeMenuItem);

        modeMenuRadioGroup.add(DSASignModeMenuItem);
        DSASignModeMenuItem.setText("Podpis cyfrowy DSA");
        DSASignModeMenuItem.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                DSASignModeMenuItemActionPerformed(evt);
            }
        });
        appModeMenu.add(DSASignModeMenuItem);

        jMenuBar1.add(appModeMenu);

        setJMenuBar(jMenuBar1);

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(statusBarPanel, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jScrollPane2)
                    .addComponent(jScrollPane1)
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(privateKeyTextField, javax.swing.GroupLayout.PREFERRED_SIZE, 229, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(privateKeyStaticLabel))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(privateKeyStaticLabel1)
                            .addComponent(publicKeyTextField, javax.swing.GroupLayout.PREFERRED_SIZE, 229, javax.swing.GroupLayout.PREFERRED_SIZE))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                        .addComponent(mainCryptActionButton)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(mainDecryptActionButton))
                    .addGroup(layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(staticLabel1)
                            .addComponent(staticLabel2))
                        .addGap(0, 0, Short.MAX_VALUE)))
                .addContainerGap())
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(staticLabel1)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jScrollPane1, javax.swing.GroupLayout.PREFERRED_SIZE, 159, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addGap(18, 18, 18)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                            .addComponent(mainCryptActionButton, javax.swing.GroupLayout.PREFERRED_SIZE, 39, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(mainDecryptActionButton, javax.swing.GroupLayout.PREFERRED_SIZE, 39, javax.swing.GroupLayout.PREFERRED_SIZE))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 25, Short.MAX_VALUE))
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                            .addComponent(privateKeyStaticLabel)
                            .addComponent(privateKeyStaticLabel1))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                            .addComponent(privateKeyTextField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(publicKeyTextField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)))
                .addComponent(staticLabel2)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jScrollPane2, javax.swing.GroupLayout.PREFERRED_SIZE, 185, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 26, Short.MAX_VALUE)
                .addComponent(statusBarPanel, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void mainCryptActionButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_mainCryptActionButtonActionPerformed
        String key = getCryptKey();
            
        mainLogic.cipherTextBuffer = mainLogic.getCctx().crypt(mainLogic.plainTextBuffer, key);
        outputTextArea.setText(mainLogic.cipherTextBuffer);
    }//GEN-LAST:event_mainCryptActionButtonActionPerformed

    private void AESCipherModeMenuItemActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_AESCipherModeMenuItemActionPerformed
        mainLogic.getCctx().setStrategy(new AESCryptStrategy());
        statusBarLabel1.setText("Tryb szyfrowania: szyfrowanie AES");
    }//GEN-LAST:event_AESCipherModeMenuItemActionPerformed

    private void ElGamalCipherModeMenuItemActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_ElGamalCipherModeMenuItemActionPerformed
        mainLogic.getCctx().setStrategy(new ElGamalCryptStrategy());
        statusBarLabel1.setText("Tryb szyfrowania: Szyfrowanie ElGamal");
    }//GEN-LAST:event_ElGamalCipherModeMenuItemActionPerformed

    private void DSASignModeMenuItemActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_DSASignModeMenuItemActionPerformed
        mainLogic.getCctx().setStrategy(new DSASignStrategy());
        statusBarLabel1.setText("Tryb szyfrowania: podpis DSA");
    }//GEN-LAST:event_DSASignModeMenuItemActionPerformed

    private void openFileToPlaintextMenuItemActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_openFileToPlaintextMenuItemActionPerformed
       
        String readString = "";
        mainLogic.plainTextBuffer = "";
        JFileChooser fc = new JFileChooser();
        int returnVal = fc.showOpenDialog(fc);
        if (returnVal == JFileChooser.APPROVE_OPTION) {
            File file = fc.getSelectedFile();
            try (BufferedReader br = new BufferedReader(new FileReader(file.toString()))) {
                String sCurrentLine;
                inputTextArea.setText("");
                statusBarLabel1.setText("Wczytano plik " + file.toString());
                while ((sCurrentLine = br.readLine()) != null) {                  
                    readString += sCurrentLine;
                    mainLogic.plainTextBuffer += readString;
                    mainLogic.plainTextBuffer += "\n";  
                    readString="";
                }
                inputTextArea.append(mainLogic.plainTextBuffer);
            } catch (IOException e) {
                statusBarLabel1.setText("Nie udało się wczytać pliku " + file.toString());
            }
        }
               
            
    }//GEN-LAST:event_openFileToPlaintextMenuItemActionPerformed

    private void saveCipherTextToFileMenuItemActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_saveCipherTextToFileMenuItemActionPerformed
        JFileChooser fc = new JFileChooser();
        if(fc.showSaveDialog(this)==JFileChooser.APPROVE_OPTION)
        {
            File file = fc.getSelectedFile();
            String pathAndFilename = file.toString();

            try (BufferedWriter bw = new BufferedWriter(new FileWriter(file))) {
                bw.write(mainLogic.cipherTextBuffer);
            } catch (IOException ex) {
                statusBarLabel1.setText("Nie udało się zapisać pliku " + pathAndFilename);
                ex.printStackTrace();
            }

            
        }
        
    }//GEN-LAST:event_saveCipherTextToFileMenuItemActionPerformed

    private void copyPlaintextModeMenuItemActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_copyPlaintextModeMenuItemActionPerformed
        mainLogic.getCctx().setStrategy(new copyPlaintextCryptStrategy());
        statusBarLabel1.setText("Tryb szyfrowania: brak szyfrowania");
    }//GEN-LAST:event_copyPlaintextModeMenuItemActionPerformed

    private void mainDecryptActionButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_mainDecryptActionButtonActionPerformed
        String key = getDecryptKey();
        mainLogic.plainTextBuffer = mainLogic.getCctx().decrypt(mainLogic.cipherTextBuffer, key);
        inputTextArea.setText(mainLogic.plainTextBuffer);
    }//GEN-LAST:event_mainDecryptActionButtonActionPerformed

    private void inputTextAreaCaretUpdate(javax.swing.event.CaretEvent evt) {//GEN-FIRST:event_inputTextAreaCaretUpdate
        mainLogic.plainTextBuffer = inputTextArea.getText();
    }//GEN-LAST:event_inputTextAreaCaretUpdate

    private void outputTextAreaCaretUpdate(javax.swing.event.CaretEvent evt) {//GEN-FIRST:event_outputTextAreaCaretUpdate
        mainLogic.cipherTextBuffer = outputTextArea.getText();
    }//GEN-LAST:event_outputTextAreaCaretUpdate

    private void openFileToCiphertextMenuItemActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_openFileToCiphertextMenuItemActionPerformed
        String readString = "";
        mainLogic.cipherTextBuffer = "";
        JFileChooser fc = new JFileChooser();
        int returnVal = fc.showOpenDialog(fc);
        if (returnVal == JFileChooser.APPROVE_OPTION) {
            File file = fc.getSelectedFile();
            try (BufferedReader br = new BufferedReader(new FileReader(file.toString()))) {
                String sCurrentLine;
                outputTextArea.setText("");
                statusBarLabel1.setText("Wczytano plik " + file.toString());
                while ((sCurrentLine = br.readLine()) != null) {                  
                    readString += sCurrentLine;
                    mainLogic.cipherTextBuffer += readString;
                    mainLogic.cipherTextBuffer += "\n";  
                    readString="";
                }
                outputTextArea.append(mainLogic.cipherTextBuffer);
            } catch (IOException e) {
                statusBarLabel1.setText("Nie udało się wczytać pliku " + file.toString());
            }
        }
    }//GEN-LAST:event_openFileToCiphertextMenuItemActionPerformed

    private void savePlainTextToFileMenuItemActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_savePlainTextToFileMenuItemActionPerformed
        JFileChooser fc = new JFileChooser();
        if(fc.showSaveDialog(this)==JFileChooser.APPROVE_OPTION)
        {
            File file = fc.getSelectedFile();
            String pathAndFilename = file.toString();

            try (BufferedWriter bw = new BufferedWriter(new FileWriter(file))) {
                bw.write(mainLogic.plainTextBuffer);
            } catch (IOException ex) {
                statusBarLabel1.setText("Nie udało się zapisać pliku " + pathAndFilename);
                ex.printStackTrace();
            }

            
        }
    }//GEN-LAST:event_savePlainTextToFileMenuItemActionPerformed

    /**
     * @param args the command line arguments
     */
    public static void main(String args[]) {
        
        /* run business logic */
        mainLogic = new MainLogic();
        
        /* Set native look and feel */
        //<editor-fold defaultstate="collapsed" desc=" Look and feel setting code (optional) ">
        /* If Nimbus (introduced in Java SE 6) is not available, stay with the default look and feel.
         * For details see http://download.oracle.com/javase/tutorial/uiswing/lookandfeel/plaf.html 
         */
        try {
            UIManager.setLookAndFeel(
            UIManager.getSystemLookAndFeelClassName());
        } catch (ClassNotFoundException | InstantiationException | IllegalAccessException | javax.swing.UnsupportedLookAndFeelException ex) {
            java.util.logging.Logger.getLogger(MainUI.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }
        //</editor-fold>

        /* Create and display the form */
        java.awt.EventQueue.invokeLater(new Runnable() {
            public void run() {
                new MainUI().setVisible(true);
            }
        });
        
    }
    
    public String getCryptKey()
    {
        return getKeyForAction(mainLogic.getCctx().getKeyTypeForCrypt());
    }
    
    public String getDecryptKey()
    {
        return getKeyForAction(mainLogic.getCctx().getKeyTypeForDecrypt());
    }
    
    public String getKeyForAction(String keyTypeForAction)
    {
        String key;
        if("public".equals(keyTypeForAction))
        {
            key = publicKeyTextField.getText();
        }
        else 
        {
            key = privateKeyTextField.getText();
        }
        System.out.println("Key type: "+keyTypeForAction+" Key: "+key);
        return key;
    }
    
    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JRadioButtonMenuItem AESCipherModeMenuItem;
    private javax.swing.JRadioButtonMenuItem DSASignModeMenuItem;
    private javax.swing.JRadioButtonMenuItem ElGamalCipherModeMenuItem;
    private javax.swing.JMenu appModeMenu;
    private javax.swing.JRadioButtonMenuItem copyPlaintextModeMenuItem;
    private javax.swing.JMenu fileMenu;
    private javax.swing.JTextArea inputTextArea;
    private javax.swing.JMenuBar jMenuBar1;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JScrollPane jScrollPane2;
    private javax.swing.JButton mainCryptActionButton;
    private javax.swing.JButton mainDecryptActionButton;
    private javax.swing.ButtonGroup modeMenuRadioGroup;
    private javax.swing.JMenuItem openFileToCiphertextMenuItem;
    private javax.swing.JMenuItem openFileToPlaintextMenuItem;
    private javax.swing.JTextArea outputTextArea;
    private javax.swing.JLabel privateKeyStaticLabel;
    private javax.swing.JLabel privateKeyStaticLabel1;
    private javax.swing.JTextField privateKeyTextField;
    private javax.swing.JTextField publicKeyTextField;
    private javax.swing.JMenuItem saveCipherTextToFileMenuItem;
    private javax.swing.JMenuItem savePlainTextToFileMenuItem;
    private javax.swing.JLabel staticLabel1;
    private javax.swing.JLabel staticLabel2;
    private javax.swing.JLabel statusBarLabel1;
    private javax.swing.JPanel statusBarPanel;
    private javax.swing.JProgressBar statusBarProgressBar;
    private javax.swing.JLabel statusBarProgressLabel;
    // End of variables declaration//GEN-END:variables
}
