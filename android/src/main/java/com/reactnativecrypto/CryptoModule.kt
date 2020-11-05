package com.reactnativecrypto


import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.ReactContextBaseJavaModule
import com.facebook.react.bridge.ReactMethod
import com.facebook.react.bridge.Promise

import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec
import java.security.KeyPairGenerator
import java.security.KeyPair
import java.security.PublicKey
import java.security.KeyStore
import java.util.Base64

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

    @ReactMethod
    fun generateRSAKeyPair(promise : Promise) {

      val keyGenerator : KeyPairGenerator = KeyPairGenerator.getInstance("RSA");
      keyGenerator.initialize(2048);

      val keys : KeyPair = keyGenerator.generateKeyPair();

      val public : PublicKey = keys.getPublic();
      val publicBytes : ByteArray = public.getEncoded();
      val publicBASE64 : ByteArray = Base64.getEncoder().encode(publicBytes);




      promise.resolve(String(publicBASE64));
    }

    @ReactMethod
    fun SaveKeyToKeystore(alias : String, key : String, promise : Promise) {
      val ks : KeyStore = KeyStore.getInstance("AndroidKeyStore").apply {
        load(null)
      }
    }
}
