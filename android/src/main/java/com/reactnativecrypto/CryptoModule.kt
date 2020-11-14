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
import android.util.Base64
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
    fun deleteKeyPair(alias : String, promise : Promise) {
      val keyStore = KeyStore.getInstance("AndroidKeyStore")
      keyStore.load(null)
      try {
        keyStore.deleteEntry(alias)
      }
      catch(e : GeneralSecurityException) {
        return promise.resolve(e);
      }
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
      val publicBASE64 = Base64.encodeToString(publicBytes,Base64.DEFAULT);

      promise.resolve(publicBASE64)
    }

    @ReactMethod
    fun encryptString(
      alias : String,
      encryptionType : String,
      stringToEncrypt : String,
      promise : Promise) {
        //retrieve key from keystore
        val keyStore : KeyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);
        val publicKey : PublicKey? = keyStore.getCertificate(alias)?.getPublicKey();
        if(publicKey === null) {
          return promise.resolve("Public Key does not exist")
        }

        //init cipher with RSA/ECB/OAEPWithSHA-256AndMGF1Padding scheme
        val cipher : Cipher = Cipher.getInstance(encryptionType);
        val cipherSpec = OAEPParameterSpec(
          "SHA-256",
          "MGF1",
          MGF1ParameterSpec.SHA1,
          PSource.PSpecified.DEFAULT
        )
        cipher.init(Cipher.ENCRYPT_MODE, publicKey, cipherSpec);

        //cast string to bytes
        val stringAsBytes : ByteArray = stringToEncrypt.toByteArray();
        val encryptedBytes : ByteArray
        try {
          //encrypt string
          encryptedBytes = cipher.doFinal(stringAsBytes);
          //encode encrypted string to base64 for javascript and pass upwards
          val encryptedStringBASE64 = Base64.encodeToString(encryptedBytes,Base64.DEFAULT);
          return promise.resolve(encryptedStringBASE64);
        }
        catch(e : GeneralSecurityException) {
          return promise.resolve(e)
        }

      }

    @ReactMethod
    fun decryptString(
      alias : String,
      encryptionType : String,
      stringToDecrypt : String,
      promise : Promise) {
        //retrieve key from keystore
        val keyStore : KeyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);
        val privateKey = keyStore.getKey(alias, null) as PrivateKey?;

        if(privateKey === null) {
          return promise.resolve("Private key does not exist")
        }

        //init cipher according to RSA/ECB/OAEPWithSHA-256AndMGF1Padding scheme
        val cipher : Cipher = Cipher.getInstance(encryptionType);
        val cipherSpec = OAEPParameterSpec(
          "SHA-256",
          "MGF1",
          MGF1ParameterSpec.SHA1,
          PSource.PSpecified.DEFAULT
        )
        cipher.init(Cipher.DECRYPT_MODE, privateKey,cipherSpec);

        //decode base64 string passed in from javscript
        val encryptedStringAsBytes = Base64.decode(stringToDecrypt,Base64.DEFAULT);
        //try to decrypt bytes and resolve promise accordingly
        try {
          val decryptedString = cipher.doFinal(encryptedStringAsBytes);
          return promise.resolve(String(decryptedString))
        }
        catch(e : GeneralSecurityException) {
          return promise.resolve(e)
        }
      }
}
