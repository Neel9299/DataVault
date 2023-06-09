/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/GUIForms/JFrame.java to edit this template
 */
package CS6348.DataVault;

import java.io.File;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.DefaultListModel;
import javax.swing.JOptionPane;

/**
 *
 * @author neelv
 */

public class ReadInfo_Main extends javax.swing.JFrame {

    /**
     * Creates new form ReadInfo_Main
     */
    private String Pass;
    private Map<String, String> fileMap;
    private Read_Update ru;
    FileListItem fileListItem;
    
    private Boolean isShared;
    private Map<Integer, String> secretSharingCodes;
    public ReadInfo_Main() {
        initComponents();
        this.Pass="";
    }
    
    public ReadInfo_Main(String Pass, Read_Update ru)
    {
        initComponents();
        this.Pass=Pass;
        this.ru = ru;
        this.isShared = false;
    }
    
    public ReadInfo_Main(Read_Update ru, Map<Integer, String> secretSharingCodes)
    {
        initComponents();
        this.secretSharingCodes = secretSharingCodes;
        this.isShared = true;
        this.ru = ru;
    }

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jLabel1 = new javax.swing.JLabel();
        jButton1 = new javax.swing.JButton();
        jButton2 = new javax.swing.JButton();
        jScrollPane1 = new javax.swing.JScrollPane();
        jList1 = new javax.swing.JList<>();
        jButton3 = new javax.swing.JButton();

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);

        jLabel1.setFont(new java.awt.Font("Arial Rounded MT Bold", 1, 24)); // NOI18N
        jLabel1.setText("DataVault");

        jButton1.setText("Read");
        jButton1.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton1ActionPerformed(evt);
            }
        });

        jButton2.setText("Back");
        jButton2.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton2ActionPerformed(evt);
            }
        });

        jScrollPane1.setViewportView(jList1);

        jButton3.setText("ListFiles");
        jButton3.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton3ActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addGap(119, 119, 119)
                        .addComponent(jLabel1, javax.swing.GroupLayout.PREFERRED_SIZE, 137, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addGroup(layout.createSequentialGroup()
                        .addGap(27, 27, 27)
                        .addComponent(jScrollPane1, javax.swing.GroupLayout.PREFERRED_SIZE, 332, javax.swing.GroupLayout.PREFERRED_SIZE)))
                .addContainerGap(41, Short.MAX_VALUE))
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                .addContainerGap(61, Short.MAX_VALUE)
                .addComponent(jButton3)
                .addGap(35, 35, 35)
                .addComponent(jButton1)
                .addGap(31, 31, 31)
                .addComponent(jButton2)
                .addGap(57, 57, 57))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGap(19, 19, 19)
                .addComponent(jLabel1)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addComponent(jScrollPane1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(18, 18, 18)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jButton1)
                    .addComponent(jButton2)
                    .addComponent(jButton3))
                .addGap(60, 60, 60))
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void jButton1ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton1ActionPerformed

        try {
            // TODO add your handling code here:
            if(!isShared){
                 String selectedFile = jList1.getSelectedValue();
                 if(selectedFile == null) {
                     throw new  Exception("Please Select a File !!");
                  } 
                 ReadInfo ri = new ReadInfo(Pass, fileMap.get(selectedFile), this);
                 //public Map<Integer, String> getSecretSharingCodes(String password, String fileID);
                 SensitiveDataVault sdv = new SensitiveDataVault();
                 //Map<Integer, String> map = sdv.getSecretSharingCodes(Pass,fileMap.get(selectedFile));
                 //map.forEach((key, value) -> System.out.println("Key: "+ key + ", Value: "+value));
                 ri.setVisible(true);
                 this.setVisible(false);
            }
            else
            {
                 String selectedFile = jList1.getSelectedValue();
                 if(selectedFile == null) {
                     throw new  Exception("Please Select a File !!");
                  } 
                 ReadInfo ri = new ReadInfo(fileMap.get(selectedFile),secretSharingCodes, this);
                //public Map<Integer, String> getSecretSharingCodes(String password, String fileID);
                 SensitiveDataVault sdv = new SensitiveDataVault();
                 //Map<Integer, String> map = sdv.getSecretSharingCodes(Pass,fileMap.get(selectedFile));
                 //map.forEach((key, value) -> System.out.println("Key: "+ key + ", Value: "+value));
                 ri.setVisible(true);
                 this.setVisible(false);
            }
        } catch (Exception ex) {
             JOptionPane.showMessageDialog(this,ex.getMessage(), "Error", JOptionPane.INFORMATION_MESSAGE);
        }
        
    }//GEN-LAST:event_jButton1ActionPerformed

    private void jButton3ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton3ActionPerformed
        // TODO add your handling code here:
        
        try {
            SensitiveDataVault sdv = new SensitiveDataVault();
            List<com.google.api.services.drive.model.File> files;
            if(!isShared)
                files = sdv.listNonSharedFiles();
            else 
                files = sdv.listSharedFiles();
            
            DefaultListModel<String> model = new DefaultListModel<>();
            fileMap = new HashMap<>();

            for (com.google.api.services.drive.model.File file : files) {
                String fileName = file.getName();
                String fileId = file.getId();
                fileMap.put(fileName, fileId);
                model.addElement(fileName);
    }
            jList1.setModel(model);
            } 
             catch (Exception ex) {
             JOptionPane.showMessageDialog(this,ex.getMessage(), "Error", JOptionPane.INFORMATION_MESSAGE);
        }
    }//GEN-LAST:event_jButton3ActionPerformed

    private void jButton2ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton2ActionPerformed
        // TODO add your handling code here:
        ru.setVisible(true);
        this.setVisible(false);
    }//GEN-LAST:event_jButton2ActionPerformed

    /**
     * @param args the command line arguments
     */
    public static void main(String args[]) {
        /* Set the Nimbus look and feel */
        //<editor-fold defaultstate="collapsed" desc=" Look and feel setting code (optional) ">
        /* If Nimbus (introduced in Java SE 6) is not available, stay with the default look and feel.
         * For details see http://download.oracle.com/javase/tutorial/uiswing/lookandfeel/plaf.html 
         */
        try {
            for (javax.swing.UIManager.LookAndFeelInfo info : javax.swing.UIManager.getInstalledLookAndFeels()) {
                if ("Nimbus".equals(info.getName())) {
                    javax.swing.UIManager.setLookAndFeel(info.getClassName());
                    break;
                }
            }
        } catch (ClassNotFoundException ex) {
            java.util.logging.Logger.getLogger(ReadInfo_Main.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (InstantiationException ex) {
            java.util.logging.Logger.getLogger(ReadInfo_Main.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (IllegalAccessException ex) {
            java.util.logging.Logger.getLogger(ReadInfo_Main.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (javax.swing.UnsupportedLookAndFeelException ex) {
            java.util.logging.Logger.getLogger(ReadInfo_Main.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }
        //</editor-fold>
        //</editor-fold>
        //</editor-fold>
        //</editor-fold>

        /* Create and display the form */
        java.awt.EventQueue.invokeLater(new Runnable() {
            public void run() {
                new ReadInfo_Main().setVisible(true);
            }
        });
    }

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton jButton1;
    private javax.swing.JButton jButton2;
    private javax.swing.JButton jButton3;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JList<String> jList1;
    private javax.swing.JScrollPane jScrollPane1;
    // End of variables declaration//GEN-END:variables
}
