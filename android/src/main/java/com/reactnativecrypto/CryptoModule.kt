package com.reactnativecrypto

import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.ReactContextBaseJavaModule
import com.facebook.react.bridge.ReactMethod
import com.facebook.react.bridge.Promise

import javax.crypto.Cipher

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
      promise.resolve("test Kotlin Function")
    }
}
