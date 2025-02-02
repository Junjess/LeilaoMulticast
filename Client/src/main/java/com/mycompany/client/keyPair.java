
package com.mycompany.client;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.logging.Level;
import java.util.logging.Logger;


public class keyPair {
    private PrivateKey chavePrivada;
    private PublicKey chavePublica;

    
    public void gerarChaves(){
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(4096);  // Aumentando o tamanho da chave para 4096 bits
            KeyPair keyPair = keyGen.generateKeyPair();
            chavePrivada = keyPair.getPrivate();
            chavePublica = keyPair.getPublic();
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(keyPair.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    public PrivateKey getChavePrivada() {
        return chavePrivada;
    }

    public void setChavePrivada(PrivateKey chavePrivada) {
        this.chavePrivada = chavePrivada;
    }

    public PublicKey getChavePublica() {
        return chavePublica;
    }

    public void setChavePublica(PublicKey chavePublica) {
        this.chavePublica = chavePublica;
    }

    public keyPair() {
    }
    
    
}
