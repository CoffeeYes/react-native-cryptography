import * as React from 'react';
import { StyleSheet, View, Text } from 'react-native';
import Crypto, { CryptoViewManager } from 'react-native-crypto';

export default function App() {
  const [result, setResult] = React.useState<number | undefined>();
  const [publicKey,setPublicKey] = React.useState<string | undefined>();
  const [testText, setTestText] = React.useState<string | undefined>();

  React.useEffect(() => {
    Crypto.multiply(3, 7).then(setResult);
    Crypto.test().then(setResult);
    Crypto.generateRSAKeyPair("test").then(() => {
      Crypto.loadKeyFromKeystore("test").then(key => {
        setPublicKey(key)
      })
    });
    encryptAndDecryptTest("this is a test string").then(text => setTestText(text))
  }, []);

  const encryptAndDecryptTest = async text => {
    const encryptedString = await Crypto.encryptString(
      "test",
      "RSA/ECB/OAEPWithSHA-256AndMGF1Padding",
      text);
    const decryptedString = await Crypto.decryptString(
      "test",
      "RSA/ECB/OAEPWithSHA-256AndMGF1Padding",
      encryptedString);
    return decryptedString;
  }

  return (
    <View style={styles.container}>
      <Text>Result: test {result}</Text>
      <Text>Public Key : {publicKey}</Text>
      <Text>Test Asym Encrypt : {testText}</Text>
      <CryptoViewManager color="#32a852" style={styles.box} />
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    alignItems: 'center',
    justifyContent: 'center',
  },
  box: {
    width: 60,
    height: 60,
    marginVertical: 20,
  },
});
