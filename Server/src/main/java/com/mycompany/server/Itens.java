package com.mycompany.server;

import org.json.JSONObject;

public class Itens {

    private String tipo;
    private String nomeItem;
    private int valorInicial;
    private double valorMinimo;
    private int valorMinimoLance;
    
    public String getNomeItem() {
        return nomeItem;
    }

    public void setNomeItem(String nomeItem) {
        this.nomeItem = nomeItem;
    }

    public String getTipo() {
        return tipo;
    }

    public void setTipo(String tipo) {
        this.tipo = tipo;
    }

    public int getValorInicial() {
        return valorInicial;
    }

    public void setValorInicial(int valorInicial) {
        this.valorInicial = valorInicial;
    }

    public double getValorMinimo() {
        return valorMinimo;
    }

    public void setValorMinimo(double valorMinimo) {
        this.valorMinimo = valorMinimo;
    }

    public int getValorMinimoLance() {
        return valorMinimoLance;
    }

    public void setValorMinimoLance(int valorMinimoLance) {
        this.valorMinimoLance = valorMinimoLance;
    }

    public Itens(String nomeItem, int valorInicial, double valorMinimo, int valorMinimoLance, String tipo) {
        this.nomeItem = nomeItem;
        this.valorInicial = valorInicial;
        this.valorMinimo = valorMinimo;
        this.valorMinimoLance = valorMinimoLance;
        this.tipo= tipo;
    }

    // Método que converte o objeto Item para JSONObject
    public JSONObject toJSON() {
        JSONObject json = new JSONObject();
        json.put("item", nomeItem);
        json.put("valor inicial", valorInicial);
        json.put("valor minimo", valorMinimo);
        json.put("valor minimo por lance", valorMinimoLance);
        json.put("tipo", tipo);
        return json;
    }
}
