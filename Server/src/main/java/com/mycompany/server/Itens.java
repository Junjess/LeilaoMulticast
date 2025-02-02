
package com.mycompany.server;

import org.json.JSONObject;

public class Itens {
    private String nomeItem;
    private int valorInicial;
    private int valorMinimo;
    private int valorMinimoLance;

    public String getNomeItem() {
        return nomeItem;
    }

    public void setNomeItem(String nomeItem) {
        this.nomeItem = nomeItem;
    }

    public int getValorInicial() {
        return valorInicial;
    }

    public void setValorInicial(int valorInicial) {
        this.valorInicial = valorInicial;
    }

    public int getValorMinimo() {
        return valorMinimo;
    }

    public void setValorMinimo(int valorMinimo) {
        this.valorMinimo = valorMinimo;
    }

    public int getValorMinimoLance() {
        return valorMinimoLance;
    }

    public void setValorMinimoLance(int valorMinimoLance) {
        this.valorMinimoLance = valorMinimoLance;
    }

    public Itens(String nomeItem, int valorInicial, int valorMinimo, int valorMinimoLance) {
        this.nomeItem = nomeItem;
        this.valorInicial = valorInicial;
        this.valorMinimo = valorMinimo;
        this.valorMinimoLance = valorMinimoLance;
    }
    
     // Método que converte o objeto Item para JSONObject
    public JSONObject toJSON() {
        JSONObject json = new JSONObject();
        json.put("nome", nomeItem);
        json.put("valor inicial", valorInicial);
        json.put("valor minimo", valorMinimo);
        json.put("valor minimo por lance", valorMinimoLance);
        return json;
    }
}
