import { NativeModules, requireNativeComponent, ViewStyle } from 'react-native';

type CryptoType = {
  multiply(a: number, b: number): Promise<number>;
  test(): Promise<string>;
  generateRSAKeyPair(): Promise<string>;
  SaveKeyToKeystore(key : string) : Promise<string>;
};

type CryptoProps = {
  color: string;
  style: ViewStyle;
};

const { Crypto } = NativeModules;

export const CryptoViewManager = requireNativeComponent<CryptoProps>(
  'CryptoView'
);

export default Crypto as CryptoType;
