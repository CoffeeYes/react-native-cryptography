import * as React from 'react';
import { StyleSheet, View, Text } from 'react-native';
import Crypto, { CryptoViewManager } from 'react-native-crypto';

export default function App() {
  const [result, setResult] = React.useState<number | undefined>();
  const [publicKey,setPublicKey] = React.useState<string | undefined>();
  const [testText, setTestText] = React.useState<string | undefined>();

  React.useEffect(() => {
    // Crypto.generateRSAKeyPair("test");
    encryptAndDecryptTest("this is a test string").then(text => setTestText(text))
  }, []);

  const encryptAndDecryptTest = async text => {
    const encryptedString = await Crypto.encryptString(
      "test",
      Crypto.cipherTypes.RSA_OEAP_SHA256_MGF1,
      text);
    const decryptedString = await Crypto.decryptString(
      "test",
      Crypto.cipherTypes.RSA_OEAP_SHA256_MGF1,
      encryptedString);
    return decryptedString;
  }

  return (
    <View style={styles.container}>
      <Text>Test Asym Encrypt : {testText}</Text>
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
