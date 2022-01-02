/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package VE.GUI;


import VE.core.Block;
import VE.core.Voto;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.DefaultListModel;
import javax.swing.JOptionPane;

/**
 *
 * @author andre
 */
public class GUI extends javax.swing.JFrame{
    
    
    public GUI(){
        initComponents();
    }
  


    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        buttonGroup1 = new javax.swing.ButtonGroup();
        jScrollPane1 = new javax.swing.JScrollPane();
        lstLedger = new javax.swing.JTextArea();
        jPanel1 = new javax.swing.JPanel();
        jDesktopPane1 = new javax.swing.JDesktopPane();
        CC = new javax.swing.JLabel();
        txtNumCC = new javax.swing.JTextField();
        listaPartidos = new javax.swing.JLabel();
        Votar = new javax.swing.JButton();
        PS = new javax.swing.JRadioButton();
        PSD = new javax.swing.JRadioButton();
        CDS = new javax.swing.JRadioButton();
        PCP = new javax.swing.JRadioButton();
        BE = new javax.swing.JRadioButton();
        dificuldade = new javax.swing.JTextField();
        jLabel1 = new javax.swing.JLabel();
        Partido = new javax.swing.JTextField();

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);

        lstLedger.setColumns(20);
        lstLedger.setRows(5);
        lstLedger.setToolTipText("");
        lstLedger.setName(""); // NOI18N
        jScrollPane1.setViewportView(lstLedger);
        lstLedger.getAccessibleContext().setAccessibleName("");

        CC.setText("Número de CC");

        txtNumCC.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                txtNumCCActionPerformed(evt);
            }
        });

        listaPartidos.setText("Lista de Partidos");

        Votar.setText("Votar");
        Votar.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                VotarActionPerformed(evt);
            }
        });

        buttonGroup1.add(PS);
        PS.setText("PS");
        PS.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                PSActionPerformed(evt);
            }
        });

        buttonGroup1.add(PSD);
        PSD.setText("PSD");
        PSD.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                PSDActionPerformed(evt);
            }
        });

        buttonGroup1.add(CDS);
        CDS.setText("CDS-PP");
        CDS.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                CDSActionPerformed(evt);
            }
        });

        buttonGroup1.add(PCP);
        PCP.setText("PCP");
        PCP.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                PCPActionPerformed(evt);
            }
        });

        buttonGroup1.add(BE);
        BE.setText("BE");
        BE.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                BEActionPerformed(evt);
            }
        });

        jLabel1.setText("Dificuldade");

        jDesktopPane1.setLayer(CC, javax.swing.JLayeredPane.DEFAULT_LAYER);
        jDesktopPane1.setLayer(txtNumCC, javax.swing.JLayeredPane.DEFAULT_LAYER);
        jDesktopPane1.setLayer(listaPartidos, javax.swing.JLayeredPane.DEFAULT_LAYER);
        jDesktopPane1.setLayer(Votar, javax.swing.JLayeredPane.DEFAULT_LAYER);
        jDesktopPane1.setLayer(PS, javax.swing.JLayeredPane.DEFAULT_LAYER);
        jDesktopPane1.setLayer(PSD, javax.swing.JLayeredPane.DEFAULT_LAYER);
        jDesktopPane1.setLayer(CDS, javax.swing.JLayeredPane.DEFAULT_LAYER);
        jDesktopPane1.setLayer(PCP, javax.swing.JLayeredPane.DEFAULT_LAYER);
        jDesktopPane1.setLayer(BE, javax.swing.JLayeredPane.DEFAULT_LAYER);
        jDesktopPane1.setLayer(dificuldade, javax.swing.JLayeredPane.DEFAULT_LAYER);
        jDesktopPane1.setLayer(jLabel1, javax.swing.JLayeredPane.DEFAULT_LAYER);

        javax.swing.GroupLayout jDesktopPane1Layout = new javax.swing.GroupLayout(jDesktopPane1);
        jDesktopPane1.setLayout(jDesktopPane1Layout);
        jDesktopPane1Layout.setHorizontalGroup(
            jDesktopPane1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jDesktopPane1Layout.createSequentialGroup()
                .addComponent(listaPartidos)
                .addGap(0, 0, Short.MAX_VALUE))
            .addGroup(jDesktopPane1Layout.createSequentialGroup()
                .addGroup(jDesktopPane1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jDesktopPane1Layout.createSequentialGroup()
                        .addGap(104, 104, 104)
                        .addComponent(Votar, javax.swing.GroupLayout.PREFERRED_SIZE, 73, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addGroup(jDesktopPane1Layout.createSequentialGroup()
                        .addGap(24, 24, 24)
                        .addGroup(jDesktopPane1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(txtNumCC, javax.swing.GroupLayout.PREFERRED_SIZE, 79, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(CC))
                        .addGap(57, 57, 57)
                        .addGroup(jDesktopPane1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                            .addComponent(dificuldade)
                            .addComponent(jLabel1, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)))
                    .addGroup(jDesktopPane1Layout.createSequentialGroup()
                        .addContainerGap()
                        .addGroup(jDesktopPane1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(CDS, javax.swing.GroupLayout.PREFERRED_SIZE, 93, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(PCP, javax.swing.GroupLayout.PREFERRED_SIZE, 93, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(BE, javax.swing.GroupLayout.PREFERRED_SIZE, 93, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(PS, javax.swing.GroupLayout.PREFERRED_SIZE, 93, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(PSD, javax.swing.GroupLayout.PREFERRED_SIZE, 93, javax.swing.GroupLayout.PREFERRED_SIZE))))
                .addContainerGap(100, Short.MAX_VALUE))
        );
        jDesktopPane1Layout.setVerticalGroup(
            jDesktopPane1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jDesktopPane1Layout.createSequentialGroup()
                .addGroup(jDesktopPane1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(CC)
                    .addComponent(jLabel1, javax.swing.GroupLayout.PREFERRED_SIZE, 26, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(jDesktopPane1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(txtNumCC, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(dificuldade, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(27, 27, 27)
                .addComponent(listaPartidos)
                .addGap(18, 18, 18)
                .addComponent(PS)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(PSD)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(CDS)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(PCP)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(BE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 34, Short.MAX_VALUE)
                .addComponent(Votar)
                .addGap(151, 151, 151))
        );

        javax.swing.GroupLayout jPanel1Layout = new javax.swing.GroupLayout(jPanel1);
        jPanel1.setLayout(jPanel1Layout);
        jPanel1Layout.setHorizontalGroup(
            jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel1Layout.createSequentialGroup()
                .addContainerGap(47, Short.MAX_VALUE)
                .addComponent(jDesktopPane1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap())
        );
        jPanel1Layout.setVerticalGroup(
            jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel1Layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jDesktopPane1))
        );

        Partido.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                PartidoActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGap(33, 33, 33)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                    .addComponent(Partido, javax.swing.GroupLayout.PREFERRED_SIZE, 42, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jScrollPane1, javax.swing.GroupLayout.PREFERRED_SIZE, 208, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jPanel1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap(167, Short.MAX_VALUE))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGap(49, 49, 49)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                    .addComponent(jScrollPane1)
                    .addComponent(jPanel1, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(Partido, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap(34, Short.MAX_VALUE))
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void txtNumCCActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_txtNumCCActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_txtNumCCActionPerformed

    private void VotarActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_VotarActionPerformed
      try {
            Voto v = new Voto(
                //txtNomeEleitor.getText(),
                Integer.valueOf(txtNumCC.getText()),
                Partido.getText(), 
                Integer.valueOf(dificuldade.getText()));
           
           lstLedger.setText(v.toString());

        } catch (Exception ex) {
        }
    }//GEN-LAST:event_VotarActionPerformed

    private void PSActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_PSActionPerformed
          // TODO add your handling code here:
          Partido.setText("PS");
    }//GEN-LAST:event_PSActionPerformed

    private void CDSActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_CDSActionPerformed
        // TODO add your handling code here:
        Partido.setText("CDS");
    }//GEN-LAST:event_CDSActionPerformed

    private void PartidoActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_PartidoActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_PartidoActionPerformed

    private void PSDActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_PSDActionPerformed
        // TODO add your handling code here:
        Partido.setText("PSD");
    }//GEN-LAST:event_PSDActionPerformed

    private void PCPActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_PCPActionPerformed
        // TODO add your handling code here:
        Partido.setText("PCP");
    }//GEN-LAST:event_PCPActionPerformed

    private void BEActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_BEActionPerformed
        // TODO add your handling code here:
        Partido.setText("BE");
    }//GEN-LAST:event_BEActionPerformed

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
            java.util.logging.Logger.getLogger(GUI.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (InstantiationException ex) {
            java.util.logging.Logger.getLogger(GUI.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (IllegalAccessException ex) {
            java.util.logging.Logger.getLogger(GUI.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (javax.swing.UnsupportedLookAndFeelException ex) {
            java.util.logging.Logger.getLogger(GUI.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }
        //</editor-fold>

        /* Create and display the form */
        java.awt.EventQueue.invokeLater(new Runnable() {
            public void run() {
                new GUI().setVisible(true);
            }
        });
    }

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JRadioButton BE;
    private javax.swing.JLabel CC;
    private javax.swing.JRadioButton CDS;
    private javax.swing.JRadioButton PCP;
    private javax.swing.JRadioButton PS;
    private javax.swing.JRadioButton PSD;
    private javax.swing.JTextField Partido;
    private javax.swing.JButton Votar;
    private javax.swing.ButtonGroup buttonGroup1;
    private javax.swing.JTextField dificuldade;
    private javax.swing.JDesktopPane jDesktopPane1;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JPanel jPanel1;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JLabel listaPartidos;
    private javax.swing.JTextArea lstLedger;
    private javax.swing.JTextField txtNumCC;
    // End of variables declaration//GEN-END:variables
}
