import * as React from 'react';
import { StyleSheet, View, Text } from 'react-native';
import Crypto, { CryptoViewManager } from 'react-native-crypto';

export default function App() {
  const [result, setResult] = React.useState<number | undefined>();

  React.useEffect(() => {
    Crypto.multiply(3, 7).then(setResult);
    Crypto.test().then(setResult);
  }, []);

  return (
    <View style={styles.container}>
      <Text>Result: test {result}</Text>
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
