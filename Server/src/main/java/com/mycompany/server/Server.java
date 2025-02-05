package com.mycompany.server;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.*;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.json.JSONArray;
import org.json.JSONObject;
import org.json.JSONTokener;

public class Server {

    private static final int PORT = 50001;
    private static final String DIRECTORY_PATH = "C:\\Users\\rafae\\OneDrive\\Área de Trabalho\\TrabalhoSegurança\\Chaves";
    private MulticastSocket multicastSocket;
    private InetAddress address;
    private static final String MULTICAST_GROUP = "230.0.0.1"; // Endereço do grupo multicast
    private static final int MULTICAST_PORT = 5000; // Porta do grupo
    private List<Itens> itensLeilao;
    private ExecutorService executor = Executors.newCachedThreadPool();
    private boolean continuar = false;
    private static String chaveAES = "";
    private String ganhador = "";
    private static AtomicInteger conexoes = new AtomicInteger(0);
    private static boolean leilaoIniciado = false;
    private ServerSocket serverSocket;
    private Itens itemAtual = new Itens();
    JSONObject estadoAtual = new JSONObject();

    public static void main(String[] args) throws Exception {
        Server server = new Server();
        chaveAES = criarAES();
        server.iniciarServer();
    }

    public void iniciarServer() throws Exception {
        try {
            serverSocket = new ServerSocket(PORT);
            System.out.println("Servidor aguardando conexões na porta " + PORT + "...");
            adicionandoItens();

            new Thread(() -> {
                while (!serverSocket.isClosed()) {
                    try {
                        Socket clientSocket = serverSocket.accept();
                        System.out.println("Cliente conectado: " + clientSocket.getInetAddress());

                        new Thread(() -> tratarCliente(clientSocket)).start();
                    } catch (SocketException e) {
                        System.out.println("Servidor foi encerrado.");
                        break;
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }
            }).start();

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void tratarCliente(Socket clientSocket) {
        try {
            BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
            PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true);

            // Recebendo mensagem do cliente
            String message = in.readLine();
            JSONObject json = new JSONObject(message);
            String cpf = json.getString("cpf");
            String assinatura = json.getString("assinatura");

            System.out.println("Recebido do cliente: " + message);

            String chavePublica = verificarCliente(cpf);
            boolean entrar = verificarAssinatura(cpf, assinatura, stringParaPublicKey(chavePublica));

            JSONObject jsonResponse = new JSONObject();
            if (entrar) {
                jsonResponse.put("entrada", "true");
                jsonResponse.put("grupo", criptografarComChavePublica(chavePublica, MULTICAST_GROUP));
                jsonResponse.put("porta", criptografarComChavePublica(chavePublica, String.valueOf(MULTICAST_PORT)));
                jsonResponse.put("aes", criptografarComChavePublica(chavePublica, chaveAES));
                jsonResponse.put("assinatura", criptografarComChavePublica(chavePublica, "server"));

                if (leilaoIniciado) {
                    byte[] data = estadoAtual.toString().getBytes();
                    InetAddress group = InetAddress.getByName(MULTICAST_GROUP);
                    DatagramPacket packet = new DatagramPacket(data, data.length, group, MULTICAST_PORT);
                    multicastSocket.send(packet);
                }

                out.println(jsonResponse);
                conexoes.incrementAndGet();
            } else {
                jsonResponse.put("entrada", "false");
                out.println(jsonResponse);
            }
            clientSocket.close();

            // Iniciar leilão quando houver pelo menos 2 conexões
            if (conexoes.get() >= 2 && !leilaoIniciado) {
                synchronized (Server.class) {
                    if (!leilaoIniciado) {
                        leilaoIniciado = true;
                        iniciarLeilao();
                    }
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void iniciarLeilao() throws InterruptedException, IOException, Exception {
        criarMulticast();
        try {
            for (Itens item : itensLeilao) {
                Thread.sleep(3000);
                enviarItens(item);
                itemAtual = item;
                continuar = true;

                Future<?> future = executor.submit(() -> {
                    try {
                        processarLance();
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                });

                ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);
                final AtomicInteger tempoRestante = new AtomicInteger(15);

                Runnable tempo = () -> {
                    if (tempoRestante.get() > 0) {
                        enviarTempo(tempoRestante.get());
                        tempoRestante.decrementAndGet();
                    } else {
                        continuar = false;
                        scheduler.shutdown();
                    }
                };

                scheduler.scheduleAtFixedRate(tempo, 0, 1, TimeUnit.SECONDS);

                while (continuar) {
                    Thread.sleep(100);
                }
                JSONObject jsonVencedor = new JSONObject();
                jsonVencedor.put("tipo", "vencedor");
                jsonVencedor.put("ganhador", encriptarAES(ganhador, stringParaSecretKey(chaveAES)));

                byte[] data = jsonVencedor.toString().getBytes();
                InetAddress group = InetAddress.getByName(MULTICAST_GROUP);
                DatagramPacket packet = new DatagramPacket(data, data.length, group, MULTICAST_PORT);
                multicastSocket.send(packet);
            }
            Thread.sleep(3000);
            JSONObject jsonEncerrado = new JSONObject();
            jsonEncerrado.put("tipo", "encerrado");
            byte[] data = jsonEncerrado.toString().getBytes();
            InetAddress group = InetAddress.getByName(MULTICAST_GROUP);
            DatagramPacket packet = new DatagramPacket(data, data.length, group, MULTICAST_PORT);
            multicastSocket.send(packet);
            multicastSocket.close();
        } catch (IOException ex) {

        }
    }

    public static String encriptarAES(String message, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encryptedBytes = cipher.doFinal(message.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public static SecretKey stringParaSecretKey(String key) {
        byte[] decodedKey = Base64.getDecoder().decode(key);
        return new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
    }

    public String verificarCliente(String cpf) throws IOException {
        File file = new File(DIRECTORY_PATH, "publicKeys.json");

        if (!file.exists()) {
            throw new IOException("Arquivo não encontrado: " + file.getAbsolutePath());
        }

        try ( FileReader reader = new FileReader(file)) {
            JSONTokener tokener = new JSONTokener(reader);
            JSONArray jsonArray = new JSONArray(tokener);

            System.out.println("cpf: " + cpf);
            // Normaliza o CPF recebido (remove pontos, traços, espaços)
            String cpfNormalizado = cpf.replaceAll("\\D", "");

            System.out.println("CPF recebido normalizado: " + cpfNormalizado);

            for (int i = 0; i < jsonArray.length(); i++) {
                JSONObject jsonObject = jsonArray.getJSONObject(i);

                String cpfCadastrado = jsonObject.optString("cpfCliente", null);
                if (cpfCadastrado != null) {
                    // Normaliza o CPF do JSON antes de comparar
                    String cpfCadastradoNormalizado = cpfCadastrado.replaceAll("\\D", "");

                    System.out.println("Verificando CPF no JSON: " + cpfCadastradoNormalizado);

                    if (cpfCadastradoNormalizado.equals(cpfNormalizado)) {
                        System.out.println("CPF encontrado! Retornando chave pública...");
                        return jsonObject.optString("chavePublica", null);
                    }
                }
            }

            throw new IOException("CPF não encontrado no arquivo.");
        } catch (IOException e) {
            e.printStackTrace();
            throw new IOException("Erro ao ler o arquivo: " + e.getMessage());
        }

    }

    public boolean verificarAssinatura(String cpf, String assinatura, PublicKey chavePublica) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(chavePublica);
        signature.update(cpf.getBytes());
        byte[] signedData = Base64.getDecoder().decode(assinatura);
        return signature.verify(signedData);
    }

    public static PublicKey stringParaPublicKey(String keyBase64) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(keyBase64);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        return keyFactory.generatePublic(keySpec);
    }

    public void criarMulticast() throws IOException {
        try {
            multicastSocket = new MulticastSocket(MULTICAST_PORT);
            address = InetAddress.getByName(MULTICAST_GROUP);
            multicastSocket.joinGroup(address);
        } catch (IOException E) {

        }
    }

    public String criptografarComChavePublica(String chavePublica, String message) throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        PublicKey key = stringParaPublicKey(chavePublica);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encryptedBytes = cipher.doFinal(message.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public static String criarAES() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256); // Define o tamanho da chave (256 bits)
        SecretKey secretKey = keyGen.generateKey();
        return Base64.getEncoder().encodeToString(secretKey.getEncoded());
    }

    public void adicionandoItens() {
        itensLeilao = new ArrayList<>();
        itensLeilao.add(new Itens("Motoca Rosa", 300, 350, 50, "item"));
        itensLeilao.add(new Itens("Boneca Barbie", 200, 200, 75, "item"));
        itensLeilao.add(new Itens("Carrinho HotWheels", 400, 420, 60, "item"));
    }

    public void enviarItens(Itens item) throws IOException, InterruptedException, Exception {
        try {
            adicionandoItens();
            JSONObject jsonItens = item.toJSON(); // Convertendo para JSON
            jsonItens.put("item", encriptarAES(item.getNomeItem(), stringParaSecretKey(chaveAES)));
            jsonItens.put("valor inicial", encriptarAES(String.valueOf(item.getValorInicial()), stringParaSecretKey(chaveAES)));
            jsonItens.put("valor minimo", encriptarAES(String.valueOf(item.getValorMinimo()), stringParaSecretKey(chaveAES)));
            jsonItens.put("valor minimo por lance", encriptarAES(String.valueOf(item.getValorMinimoLance()), stringParaSecretKey(chaveAES)));
            jsonItens.put("tipo", "item");

            estadoAtual.put("item", encriptarAES(item.getNomeItem(), stringParaSecretKey(chaveAES)));
            estadoAtual.put("valor inicial", encriptarAES(String.valueOf(item.getValorInicial()), stringParaSecretKey(chaveAES)));
            estadoAtual.put("valor minimo", encriptarAES(String.valueOf(item.getValorMinimo()), stringParaSecretKey(chaveAES)));
            estadoAtual.put("valor minimo por lance", encriptarAES(String.valueOf(item.getValorMinimoLance()), stringParaSecretKey(chaveAES)));
            estadoAtual.put("tipo", "estadoAtual");

            byte[] data = jsonItens.toString().getBytes();

            // Envia o JSON via multicast
            InetAddress group = InetAddress.getByName(MULTICAST_GROUP);
            DatagramPacket packet = new DatagramPacket(data, data.length, group, MULTICAST_PORT);
            multicastSocket.send(packet);
            System.out.println("Item enviado: " + jsonItens);
        } catch (IOException e) {
            System.err.println("Error sending info: " + e.getMessage());
        }

    }

    public void enviarTempo(int tempo) {
        JSONObject jsonTempoRestante = new JSONObject();
        jsonTempoRestante.put("tipo", "tempo");
        jsonTempoRestante.put("tempoRestante", tempo);

        // Envia o tempo restante via multicast
        byte[] data = jsonTempoRestante.toString().getBytes();
        try ( DatagramSocket socket = new DatagramSocket()) {
            InetAddress group = InetAddress.getByName(MULTICAST_GROUP);
            DatagramPacket packet = new DatagramPacket(data, data.length, group, MULTICAST_PORT); // Ajuste a porta conforme necessário
            socket.send(packet);

            System.out.println("Tempo restante enviado: " + tempo + " segundos");

            if (tempo == 1) {
                continuar = true;
            }
        } catch (Exception e) {
        }

    }

    private void processarLance() {
        while (continuar) {
            try {
                byte[] buffer = new byte[2048];
                DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
                multicastSocket.receive(packet); // Recebe o pacote do cliente
                String jsonString = new String(packet.getData(), 0, packet.getLength());
                JSONObject json = new JSONObject(jsonString);
                //Descriptografa com AES
                if (!json.getString("tipo").equals("item") && !json.getString("tipo").equals("tempo") && !json.getString("tipo").equals("atualizacao")) {
                    String item = descriptografarAES(json.getString("item"), stringParaSecretKey(chaveAES));
                    double valor = Double.parseDouble(descriptografarAES(json.getString("valor"), stringParaSecretKey(chaveAES)));
                    String cliente = descriptografarAES(json.getString("cliente"), stringParaSecretKey(chaveAES));
                    double valorLance = valor;

                    for (int i = 0; i < itensLeilao.size(); i++) {
                        if (itensLeilao.get(i).getNomeItem().equals(item)) {
                            if (valorLance >= itensLeilao.get(i).getValorMinimo() && valorLance >= (itensLeilao.get(i).getValorMinimoLance() + itensLeilao.get(i).getValorMinimo())) {
                                enviarAtualizacao(item, valorLance);
                                itensLeilao.get(i).setValorMinimo(valorLance);
                                ganhador = cliente;
                                break;
                            }
                        } else if (itensLeilao.get(i).getNomeItem().equals(item)) {
                            if (valorLance >= itensLeilao.get(i).getValorMinimo() && valorLance >= (itensLeilao.get(i).getValorMinimoLance() + itensLeilao.get(i).getValorMinimo())) {
                                enviarAtualizacao(item, valorLance);
                                itensLeilao.get(i).setValorMinimo(valorLance);
                                ganhador = cliente;
                                break;
                            }
                        } else if (itensLeilao.get(i).getNomeItem().equals(item)) {
                            if (valorLance >= itensLeilao.get(i).getValorMinimo() && valorLance >= (itensLeilao.get(i).getValorMinimoLance() + itensLeilao.get(i).getValorMinimo())) {
                                enviarAtualizacao(item, valorLance);
                                itensLeilao.get(i).setValorMinimo(valorLance);
                                ganhador = cliente;
                                break;
                            }
                        }
                    }
                }

            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    private void enviarAtualizacao(String item, double valor) throws Exception {
        JSONObject jsonAtualizacao = new JSONObject();
        jsonAtualizacao.put("tipo", "atualizacao");
        jsonAtualizacao.put("item", encriptarAES(item, stringParaSecretKey(chaveAES)));
        jsonAtualizacao.put("valor", encriptarAES(String.valueOf(valor), stringParaSecretKey(chaveAES)));

        byte[] data = jsonAtualizacao.toString().getBytes();
        InetAddress group = InetAddress.getByName(MULTICAST_GROUP);
        DatagramPacket packet = new DatagramPacket(data, data.length, group, MULTICAST_PORT);
        multicastSocket.send(packet);
        System.out.println("Atualização enviada");
    }

    public static String descriptografarAES(String message, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(message));
        return new String(decryptedBytes);
    }
}
