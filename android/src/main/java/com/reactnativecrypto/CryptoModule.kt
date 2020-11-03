package com.reactnativecrypto

import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.ReactContextBaseJavaModule
import com.facebook.react.bridge.ReactMethod
import com.facebook.react.bridge.Promise

import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec

class CryptoModule(reactContext: ReactApplicationContext) : ReactContextBaseJavaModule(reactContext) {

    override fun getName(): String {
        return "Crypto"
    }

    // Example method
    // See https://facebook.github.io/react-native/docs/native-modules-android
    @ReactMethod
    fun multiply(a: Int, b: Int, promise: Promise) {

      promise.resolve(a * b)

    }

    @ReactMethod
    fun test(promise : Promise) {
      val cipher : Cipher = Cipher.getInstance("AES");
      val encryptionKeyString : String =  "thisisa128bitkey";
	    val originalMessage : String = "This is a secret message";
	    val encryptionKeyBytes : ByteArray = encryptionKeyString.toByteArray();

      val secretKey = SecretKeySpec(encryptionKeyBytes,"AES");

      cipher.init(Cipher.ENCRYPT_MODE, secretKey);
      val encryptedMessageBytes : ByteArray = cipher.doFinal(originalMessage.toByteArray());

      cipher.init(Cipher.DECRYPT_MODE, secretKey);
	    val decryptedMessageBytes : ByteArray = cipher.doFinal(encryptedMessageBytes);

      promise.resolve(String(decryptedMessageBytes));
    }
}
