package com.mycompany.client;

import java.awt.BorderLayout;

public class Janela extends javax.swing.JFrame {
    static TelaInicialCliente telaInicial;
    static TelaEntrada telaEntrada;
    static TelaLeilao telaLeilao;
    
    public Janela() {
        initComponents();
        telaInicial = new TelaInicialCliente();

        this.setLayout(new BorderLayout());
        this.add(telaInicial, BorderLayout.CENTER);
        this.pack();
        
        
    }
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(this);
        this.setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGap(0, 400, Short.MAX_VALUE)
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGap(0, 300, Short.MAX_VALUE)
        );
    }// </editor-fold>//GEN-END:initComponents


    // Variables declaration - do not modify//GEN-BEGIN:variables
    // End of variables declaration//GEN-END:variables
}
