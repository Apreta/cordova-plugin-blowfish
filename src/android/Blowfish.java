package com.apreta.plugin;

import org.apache.cordova.*;
import org.json.JSONArray;
import org.json.JSONException;
import java.util.zip.Inflater;
import java.util.zip.Deflater;
import java.util.zip.DataFormatException;
import java.util.ArrayList;

public class Blowfish extends CordovaPlugin {


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
                try {
                    JSONArray out = this.decrypt(jsData);
                    callbackContext.success(out);
                } catch (DataFormatException ex) {
                    callbackContext.error("Decryption error");
                }
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

        JSONArray out = new JSONArray();
        for (int i=0; i<encryptedBytes.length; i++) {
            byte data = encryptedBytes[i];
            out.put((int)(data < 0 ? 256 + data : data));
        }

        return out;
    }

    public JSONArray decrypt(JSONArray in) throws DataFormatException, JSONException {

        byte[] compressedBytes = new byte[in.length()];
        for (int i=0; i<in.length(); i++) {
            int data = in.optInt(i); 
            compressedBytes[i] = (byte)(data > 127 ? data - 256 : data);
        }

        byte[] decompressedBytes = new byte[compressedBytes.length];

        JSONArray out = new JSONArray();
        for (int i=0; i<decompressedBytes.length; i++) {
            byte data = decompressedBytes[i];
            out.put((int)(data < 0 ? 256 + data : data));
        }

        return out;
    }

    public void setKey(JSONArray in) {
    }
}
