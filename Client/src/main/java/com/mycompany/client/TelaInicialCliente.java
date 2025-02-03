package com.mycompany.client;

import java.awt.BorderLayout;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.swing.JFrame;
import javax.swing.SwingUtilities;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.json.JSONTokener;

public class TelaInicialCliente extends javax.swing.JPanel {

    private keyPair keyPair;
    String PUBLIC_KEY_FILE = "publicKeys.json";

    public TelaInicialCliente() {
        initComponents();
        this.keyPair = new keyPair();
        keyPair.gerarChaves();
    }

    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jLabel1 = new javax.swing.JLabel();
        jLabel2 = new javax.swing.JLabel();
        cpf_tf = new javax.swing.JTextField();
        bt_entrar = new javax.swing.JButton();

        jLabel1.setFont(new java.awt.Font("Times New Roman", 1, 18)); // NOI18N
        jLabel1.setText("Bem-vindo ao Leilão");

        jLabel2.setFont(new java.awt.Font("Times New Roman", 0, 14)); // NOI18N
        jLabel2.setText("Digite o seu CPF para iniciar");

        cpf_tf.setText("888.888.888-88");
        cpf_tf.setToolTipText("CPF (000.000.000-00)");

        bt_entrar.setText("Entrar");
        bt_entrar.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseClicked(java.awt.event.MouseEvent evt) {
                bt_entrarMouseClicked(evt);
            }
        });

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(this);
        this.setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                        .addGroup(layout.createSequentialGroup()
                            .addContainerGap()
                            .addComponent(cpf_tf, javax.swing.GroupLayout.PREFERRED_SIZE, 166, javax.swing.GroupLayout.PREFERRED_SIZE))
                        .addGroup(javax.swing.GroupLayout.Alignment.LEADING, layout.createSequentialGroup()
                            .addGap(169, 169, 169)
                            .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                                .addComponent(jLabel2)
                                .addComponent(jLabel1))))
                    .addGroup(layout.createSequentialGroup()
                        .addGap(216, 216, 216)
                        .addComponent(bt_entrar)))
                .addContainerGap(192, Short.MAX_VALUE))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGap(53, 53, 53)
                .addComponent(jLabel1, javax.swing.GroupLayout.PREFERRED_SIZE, 34, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(18, 18, 18)
                .addComponent(jLabel2)
                .addGap(48, 48, 48)
                .addComponent(cpf_tf, javax.swing.GroupLayout.PREFERRED_SIZE, 48, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(40, 40, 40)
                .addComponent(bt_entrar)
                .addContainerGap(121, Short.MAX_VALUE))
        );
    }// </editor-fold>//GEN-END:initComponents

    public static String assinaturaCPF(String cpf, keyPair keyPair) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(keyPair.getChavePrivada());
        signature.update(cpf.getBytes());
        byte[] signedData = signature.sign();
        return Base64.getEncoder().encodeToString(signedData);
    }

    private void salvarChavePublica(String cpf) throws IOException {
        String publicKeyBase64 = Base64.getEncoder().encodeToString(keyPair.getChavePublica().getEncoded());

        // Criar o objeto JSON contendo a chave pública e o CPF
        JSONObject json = new JSONObject();
        json.put("chavePublica", publicKeyBase64);
        json.put("cpfCliente", cpf);

        String directoryPath = "C:\\Users\\rafae\\OneDrive\\Área de Trabalho\\TrabalhoSegurança\\Chaves";
        File directory = new File(directoryPath);

        // Verifica se o diretório existe e o cria se necessário
        if (!directory.exists()) {
            if (!directory.mkdirs()) {
                throw new IOException("Erro ao criar o diretório: " + directoryPath);
            }
        }

        // Caminho do arquivo
        File file = new File(directory, PUBLIC_KEY_FILE);

        JSONArray jsonArray;

        // Verifica se o arquivo já existe
        if (file.exists()) {
            // Lê o conteúdo atual do arquivo e determina se é um JSONObject ou JSONArray
            try ( FileReader fileReader = new FileReader(file)) {
                JSONTokener tokener = new JSONTokener(fileReader);
                Object parsedJson = tokener.nextValue();

                if (parsedJson instanceof JSONObject) {
                    // Converte o JSONObject para JSONArray
                    jsonArray = new JSONArray();
                    jsonArray.put(parsedJson);
                } else if (parsedJson instanceof JSONArray) {
                    // Utiliza o JSONArray existente
                    jsonArray = (JSONArray) parsedJson;
                } else {
                    throw new IOException("Formato inválido no arquivo JSON existente.");
                }
            } catch (IOException | JSONException e) {
                e.printStackTrace();
                throw new IOException("Erro ao ler o arquivo existente: " + e.getMessage());
            }
        } else {
            // Se o arquivo não existir, cria um novo JSONArray
            jsonArray = new JSONArray();
        }

        // Adiciona o novo objeto JSON ao array
        jsonArray.put(json);

        // Grava o JSONArray atualizado no arquivo
        try ( FileWriter fileWriter = new FileWriter(file)) {
            fileWriter.write(jsonArray.toString(4)); // 4 espaços para indentação no JSON
            System.out.println("Chave pública e CPF salvos em: " + file.getAbsolutePath());
        } catch (IOException e) {
            e.printStackTrace();
            throw new IOException("Erro ao salvar a chave pública e CPF: " + e.getMessage());
        }
    }

    private String descriptografar(PrivateKey chavePrivada, String message) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, keyPair.getChavePrivada());
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(message));
        return new String(decryptedBytes);
    }
    private void bt_entrarMouseClicked(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_bt_entrarMouseClicked
        try {
            // Salvar a chave pública em um arquivo
            salvarChavePublica(cpf_tf.getText());
            try ( Socket socket = new Socket("localhost", 50001)) {
                PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
                BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));

                String assinatura = assinaturaCPF(cpf_tf.getText(), keyPair);
                System.out.println("Assinatura: " + assinatura);
                // Enviar mensagem ao servidor
                JSONObject json = new JSONObject();
                json.put("assinatura", assinatura);
                json.put("cpf", cpf_tf.getText());

                String message = json.toString();
                out.println(message);

                String resposta = in.readLine();// Receber resposta do servidor
                JSONObject jsonResponse = new JSONObject(resposta);

                String entrada = jsonResponse.getString("entrada");
                String grupo = descriptografar(keyPair.getChavePrivada(), jsonResponse.getString("grupo"));
                int porta = Integer.valueOf(descriptografar(keyPair.getChavePrivada(), jsonResponse.getString("porta")));
                String aes = descriptografar(keyPair.getChavePrivada(), jsonResponse.getString("aes"));
                String assinaturaServer = descriptografar(keyPair.getChavePrivada(), jsonResponse.getString("assinatura"));

                if (entrada.equals("true") && assinaturaServer.equals("server")) {
                    Janela.telaLeilao = new TelaLeilao(grupo, porta, aes);
                    JFrame janela = (JFrame) SwingUtilities.getWindowAncestor(this);
                    janela.getContentPane().remove(this);
                    janela.add(Janela.telaLeilao, BorderLayout.CENTER);
                    janela.pack();
                } else {
                    System.out.println("NÃO ENTROU");
                    //tela de erro, entrada negada
                }

            } catch (IOException e) {
                e.printStackTrace();
            } catch (Exception ex) {
                Logger.getLogger(TelaInicialCliente.class.getName()).log(Level.SEVERE, null, ex);
            }
        } catch (IOException ex) {
            Logger.getLogger(TelaInicialCliente.class.getName()).log(Level.SEVERE, null, ex);
        }
    }//GEN-LAST:event_bt_entrarMouseClicked


    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton bt_entrar;
    private javax.swing.JTextField cpf_tf;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    // End of variables declaration//GEN-END:variables
}
