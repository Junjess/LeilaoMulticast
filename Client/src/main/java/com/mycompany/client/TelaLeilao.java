package com.mycompany.client;

import java.awt.BorderLayout;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.MulticastSocket;
import java.net.NetworkInterface;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.JFrame;
import javax.swing.SwingUtilities;
import org.json.JSONObject;

public class TelaLeilao extends javax.swing.JPanel {

    private String grupoMulticast;
    private int portaMulticast;
    private String aesKey;
    private String cpf;
    private InetAddress group;
    private MulticastSocket multicastSocket;

    public TelaLeilao(String grupo, int porta, String aes, String cpfCliente) throws IOException {
        initComponents();
        grupoMulticast = grupo;
        portaMulticast = porta;
        aesKey = aes;
        cpf = cpfCliente;
        group = InetAddress.getByName(grupoMulticast);
        multicastSocket = new MulticastSocket(portaMulticast);
        entrarNoGrupoMulticast();
        ta_todosLances.setEditable(false);
        tf_nomeItem.setEditable(false);
        tf_tempoRestante.setEditable(false);

    }

    public void entrarNoGrupoMulticast() {
        new Thread(() -> {
            try {
                NetworkInterface networkInterface = NetworkInterface.getByName("Wi-Fi");
                multicastSocket.joinGroup(new InetSocketAddress(group, portaMulticast), networkInterface);
                System.out.println("Cliente entrou no grupo multicast.");
                byte[] buffer = new byte[1024]; // Buffer para armazenar os dados recebidos
                String nomeItem = "";
                while (true) {
                    // Recebe o pacote de dados
                    DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
                    multicastSocket.receive(packet);
                    // Converte os dados recebidos (bytes) para uma string JSON
                    String jsonString = new String(packet.getData(), 0, packet.getLength());

                    // Converte a string JSON para um JSONObject
                    JSONObject json = new JSONObject(jsonString);
                    System.out.println("Mensagem recebida:" + json);
                    String item = "";
                    if (json.has("item")) {
                        item = descriptografarAES(json.getString("item"), stringParaSecretKey(aesKey));
                    }

                    if (!json.has("cliente")) {
                        if (!tf_nomeItem.equals(item)) {
                            if (json.has("tempoRestante")) {
                                // Se for tempo restante
                                String tempoRestante = String.valueOf(json.getLong("tempoRestante"));
                                SwingUtilities.invokeLater(() -> tf_tempoRestante.setText(tempoRestante));
                            } else if (json.getString("tipo").equals("atualizacao")) {
                                String mensagem = "Novo lance:  R$" + descriptografarAES(json.getString("valor"), stringParaSecretKey(aesKey));
                                SwingUtilities.invokeLater(() -> ta_todosLances.append("\n" + mensagem));
                            } else if (json.getString("tipo").equals("vencedor")) {
                                String anunciarVencedor = "Vencedor da rodada: " + descriptografarAES(json.getString("ganhador"), stringParaSecretKey(aesKey));
                                SwingUtilities.invokeLater(() -> ta_todosLances.setText(anunciarVencedor));
                            } else if (json.getString("tipo").equals("encerrado")) {
                                Janela.telaFinal = new TelaFinal();
                                JFrame janela = (JFrame) SwingUtilities.getWindowAncestor(this);
                                janela.getContentPane().remove(this);
                                janela.add(Janela.telaFinal, BorderLayout.CENTER);
                                janela.pack();
                            } else if (json.getString("tipo").equals("estadoAtual")) {
                                Thread.sleep(1000);
                                System.out.println("entrooooo no estado atual");
                                tf_nomeItem.setText(item);
                                String itemClienteNovo = "| Valor inicial: R$" + descriptografarAES(json.getString("valor inicial"), stringParaSecretKey(aesKey))
                                        + "\n | Lance mínimo R$" + descriptografarAES(json.getString("valor minimo"), stringParaSecretKey(aesKey))
                                        + "\n | Valor mínimo entre lances R$" + descriptografarAES(json.getString("valor minimo por lance"), stringParaSecretKey(aesKey));
                                System.out.println("antes de setar");
                                ta_todosLances.setText(itemClienteNovo);
                                System.out.println("depois");
                                
                            } else {
                                //Adiciona o nome do item no tf
                                tf_nomeItem.setText(item);

                                // Formata a exibição para o TextArea
                                String itemFormatado = "| Valor inicial: R$" + descriptografarAES(json.getString("valor inicial"), stringParaSecretKey(aesKey))
                                        + "\n | Lance mínimo R$" + descriptografarAES(json.getString("valor minimo"), stringParaSecretKey(aesKey))
                                        + "\n | Valor mínimo entre lances R$" + descriptografarAES(json.getString("valor minimo por lance"), stringParaSecretKey(aesKey));

                                // Atualiza o TextArea com a informação do item
                                SwingUtilities.invokeLater(() -> ta_todosLances.setText(itemFormatado));
                                nomeItem = item;
                            }
                        }

                    }

                }

            } catch (IOException e) {
                e.printStackTrace();
            } catch (Exception ex) {
                Logger.getLogger(TelaLeilao.class.getName()).log(Level.SEVERE, null, ex);
            }
        }).start();
    }

    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jLabel3 = new javax.swing.JLabel();
        jLabel4 = new javax.swing.JLabel();
        jLabel1 = new javax.swing.JLabel();
        jSeparator1 = new javax.swing.JSeparator();
        jScrollPane1 = new javax.swing.JScrollPane();
        ta_todosLances = new javax.swing.JTextArea();
        tf_lanceCliente = new javax.swing.JTextField();
        bt_enviarLance = new javax.swing.JButton();
        tf_tempoRestante = new javax.swing.JTextField();
        jLabel2 = new javax.swing.JLabel();
        jLabel5 = new javax.swing.JLabel();
        jLabel6 = new javax.swing.JLabel();
        tf_nomeItem = new javax.swing.JTextField();

        jLabel3.setText("jLabel3");

        jLabel4.setText("jLabel4");

        jLabel1.setFont(new java.awt.Font("Times New Roman", 1, 18)); // NOI18N
        jLabel1.setText("LEILÃO");

        ta_todosLances.setColumns(20);
        ta_todosLances.setRows(5);
        jScrollPane1.setViewportView(ta_todosLances);

        bt_enviarLance.setText("Enviar Lance");
        bt_enviarLance.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseClicked(java.awt.event.MouseEvent evt) {
                bt_enviarLanceMouseClicked(evt);
            }
        });

        jLabel2.setText("Tempo Restante:");

        jLabel5.setText("Digite seu lance:");

        jLabel6.setFont(new java.awt.Font("Times New Roman", 1, 14)); // NOI18N
        jLabel6.setText("Item disponível");

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(this);
        this.setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(jSeparator1)
            .addGroup(layout.createSequentialGroup()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addGap(235, 235, 235)
                        .addComponent(jLabel1))
                    .addGroup(layout.createSequentialGroup()
                        .addGap(40, 40, 40)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                            .addComponent(jScrollPane1, javax.swing.GroupLayout.PREFERRED_SIZE, 487, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addGroup(layout.createSequentialGroup()
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                    .addGroup(layout.createSequentialGroup()
                                        .addComponent(tf_lanceCliente, javax.swing.GroupLayout.PREFERRED_SIZE, 131, javax.swing.GroupLayout.PREFERRED_SIZE)
                                        .addGap(27, 27, 27)
                                        .addComponent(bt_enviarLance))
                                    .addComponent(jLabel5))
                                .addGap(74, 74, 74)
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                    .addComponent(jLabel2)
                                    .addComponent(tf_tempoRestante)))))
                    .addGroup(layout.createSequentialGroup()
                        .addGap(222, 222, 222)
                        .addComponent(jLabel6, javax.swing.GroupLayout.PREFERRED_SIZE, 110, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addGroup(layout.createSequentialGroup()
                        .addGap(199, 199, 199)
                        .addComponent(tf_nomeItem, javax.swing.GroupLayout.PREFERRED_SIZE, 146, javax.swing.GroupLayout.PREFERRED_SIZE)))
                .addContainerGap(39, Short.MAX_VALUE))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGap(26, 26, 26)
                .addComponent(jLabel1)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jSeparator1, javax.swing.GroupLayout.PREFERRED_SIZE, 10, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jLabel6)
                .addGap(9, 9, 9)
                .addComponent(tf_nomeItem, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(18, 18, 18)
                .addComponent(jScrollPane1, javax.swing.GroupLayout.PREFERRED_SIZE, 197, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel2)
                    .addComponent(jLabel5))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(tf_lanceCliente, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(bt_enviarLance)
                    .addComponent(tf_tempoRestante, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(27, 27, 27))
        );
    }// </editor-fold>//GEN-END:initComponents

    public void enviarLance(String item, double valorLance) throws Exception {
        JSONObject jsonLance = new JSONObject();
        jsonLance.put("tipo", "lance"); // Identificador da mensagem
        jsonLance.put("item", encriptarLance(item, stringParaSecretKey(aesKey)));
        jsonLance.put("valor", encriptarLance(String.valueOf(valorLance), stringParaSecretKey(aesKey)));
        jsonLance.put("cliente", encriptarLance(cpf, stringParaSecretKey(aesKey)));

        byte[] data = jsonLance.toString().getBytes();

        group = InetAddress.getByName(grupoMulticast);
        DatagramPacket packet = new DatagramPacket(data, data.length, group, portaMulticast);
        multicastSocket.send(packet);
        System.out.println("Lance enviado: " + jsonLance);
    }

    public static SecretKey stringParaSecretKey(String key) {
        byte[] decodedKey = Base64.getDecoder().decode(key);
        return new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
    }

    public static String encriptarLance(String message, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encryptedBytes = cipher.doFinal(message.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public static String descriptografarAES(String message, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(message));
        return new String(decryptedBytes);
    }

    private void bt_enviarLanceMouseClicked(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_bt_enviarLanceMouseClicked
        try {
            String item = tf_nomeItem.getText();

            int valorLance = Integer.parseInt(tf_lanceCliente.getText());
            enviarLance(item, valorLance);
            tf_lanceCliente.setText("");
        } catch (Exception ex) {
            Logger.getLogger(TelaLeilao.class.getName()).log(Level.SEVERE, null, ex);
        }

    }//GEN-LAST:event_bt_enviarLanceMouseClicked


    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton bt_enviarLance;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JLabel jLabel4;
    private javax.swing.JLabel jLabel5;
    private javax.swing.JLabel jLabel6;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JSeparator jSeparator1;
    private javax.swing.JTextArea ta_todosLances;
    private javax.swing.JTextField tf_lanceCliente;
    private javax.swing.JTextField tf_nomeItem;
    private javax.swing.JTextField tf_tempoRestante;
    // End of variables declaration//GEN-END:variables
}
