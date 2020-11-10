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
import java.security.PrivateKey
import java.security.KeyStore
import java.util.Base64
import android.security.keystore.KeyProperties
import java.security.KeyFactory
import java.security.spec.X509EncodedKeySpec
import java.security.GeneralSecurityException

import android.security.keystore.KeyGenParameterSpec
import javax.crypto.spec.OAEPParameterSpec
import java.security.spec.MGF1ParameterSpec
import javax.crypto.spec.PSource

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
    fun generateRSAKeyPair(alias : String, promise : Promise) {

      /* val keyGenerator : KeyPairGenerator = KeyPairGenerator.getInstance("RSA");
      keyGenerator.initialize(2048);

      val keys : KeyPair = keyGenerator.generateKeyPair();

      val public : PublicKey = keys.getPublic();
      val publicBytes : ByteArray = public.getEncoded();
      val publicBASE64 : ByteArray = Base64.getEncoder().encode(publicBytes);

      promise.resolve(String(publicBASE64)); */
      val keyPairGenerator : KeyPairGenerator =
      KeyPairGenerator.getInstance(
        KeyProperties.KEY_ALGORITHM_RSA,
        "AndroidKeyStore"
      );

      keyPairGenerator.initialize(KeyGenParameterSpec.Builder(
        alias,
        KeyProperties.PURPOSE_DECRYPT)
        .setBlockModes(KeyProperties.BLOCK_MODE_ECB)
        .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
        .build()
      )

      val keyPair : KeyPair = keyPairGenerator.generateKeyPair();
      promise.resolve(null);
    }

    @ReactMethod
    fun deleteRSAKeyPair(alias : String, promise : Promise) {
      val keyStore = KeyStore.getInstance("AndroidKeyStore")
      keyStore.load(null)
      keyStore.deleteEntry(alias)
      promise.resolve(null);
    }

    @ReactMethod
    fun loadKeyFromKeystore(alias : String, promise : Promise) {
      val keyStore : KeyStore = KeyStore.getInstance("AndroidKeyStore");
      keyStore.load(null);
      //val privateKey : PrivateKey = keyStore.getKey(alias, null) as PrivateKey;
      val publicKey = keyStore.getCertificate(alias)?.publicKey;
      if(publicKey === null) {
        return promise.resolve("Public Key Not Found")
      }

      val publicBytes : ByteArray = publicKey.getEncoded();
      val publicBASE64 : ByteArray = Base64.getEncoder().encode(publicBytes);

      promise.resolve(String(publicBASE64))
    }

    @ReactMethod
    fun encryptString(
      alias : String,
      encryptionType : String,
      stringToEncrypt : String,
      promise : Promise) {
        val keyStore : KeyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);


        val publicKey : PublicKey = keyStore.getCertificate(alias).getPublicKey();
        val cipher : Cipher = Cipher.getInstance(encryptionType);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        val stringAsBytes : ByteArray = stringToEncrypt.toByteArray();
        val encryptedBytes : ByteArray = cipher.doFinal(stringAsBytes);
        val encryptedStringBASE64 : ByteArray = Base64.getEncoder().encode(encryptedBytes);

        promise.resolve(String(encryptedStringBASE64));
      }

    @ReactMethod
    fun decryptString(
      alias : String,
      encryptionType : String,
      stringToDecrypt : String,
      promise : Promise) {
        val keyStore : KeyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);
        val privateKey = keyStore.getKey(alias, null) as PrivateKey;
        val cipher : Cipher = Cipher.getInstance(encryptionType);
        val mg1 = MGF1ParameterSpec("SHA-1");
        val cipherSpec = OAEPParameterSpec(
          "SHA-256",
          "MGF1",
          mg1,
          PSource.PSpecified.DEFAULT
        )
        cipher.init(Cipher.DECRYPT_MODE, privateKey,cipherSpec);

        val encryptedStringAsBytes : ByteArray = Base64.getDecoder().decode(stringToDecrypt);
        try {
          val decryptedString = cipher.doFinal(encryptedStringAsBytes)
        }
        catch(e : GeneralSecurityException) {
          return promise.resolve(e)
        }

        promise.resolve(stringToDecrypt);
      }
}
