package com.apreta.plugin;

import org.apache.cordova.*;
import org.json.JSONArray;
import org.json.JSONException;

public class Blowfish extends CordovaPlugin {
    private BlowfishECB coder = null;

    public Blowfish() {
    }


    @Override
    public boolean execute(String action, JSONArray data, CallbackContext callbackContext) throws JSONException {

        switch (action) {
            case "encrypt": {
                JSONArray jsData = data.getJSONArray(0);
                JSONArray out = this.encrypt(jsData);
                callbackContext.success(out);
                return true;
            }
            case "decrypt": {
                JSONArray jsData = data.getJSONArray(0);
                JSONArray out = this.decrypt(jsData);
                callbackContext.success(out);
                return true;
            }
            case "setKey": {
                JSONArray jsData = data.getJSONArray(0);
                this.setKey(jsData);
                callbackContext.success();
                return true;
            }
        }
        return false;
    }

    public JSONArray encrypt(JSONArray in) throws JSONException {

        byte[] originalBytes = new byte[in.length()];
        for (int i=0; i<in.length(); i++) {
            int data = in.optInt(i); 
            originalBytes[i] = (byte)(data > 127 ? data - 256 : data);
        }

        byte[] encryptedBytes = new byte[originalBytes.length];

        coder.encrypt(originalBytes, 0, encryptedBytes, 0, in.length());

        JSONArray out = new JSONArray();
        for (int i=0; i<encryptedBytes.length; i++) {
            byte data = encryptedBytes[i];
            out.put((int)(data < 0 ? 256 + data : data));
        }

        return out;
    }

    public JSONArray decrypt(JSONArray in) throws JSONException {

        byte[] encryptedBytes = new byte[in.length()];
        for (int i=0; i<in.length(); i++) {
            int data = in.optInt(i); 
            encryptedBytes[i] = (byte)(data > 127 ? data - 256 : data);
        }

        byte[] originalBytes = new byte[encryptedBytes.length];

        coder.decrypt(encryptedBytes, 0, originalBytes, 0, in.length());

        JSONArray out = new JSONArray();
        for (int i=0; i<originalBytes.length; i++) {
            byte data = originalBytes[i];
            out.put((int)(data < 0 ? 256 + data : data));
        }

        return out;
    }

    public void setKey(JSONArray in) {
        byte[] keyBytes = new byte[in.length()];
        for (int i=0; i<in.length(); i++) {
            int data = in.optInt(i); 
            keyBytes[i] = (byte)(data > 127 ? data - 256 : data);
        }
        coder = new BlowfishECB(keyBytes, 0, keyBytes.length);
    }
}
