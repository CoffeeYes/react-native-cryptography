import { NativeModules, requireNativeComponent, ViewStyle } from 'react-native';

type CryptoType = {
  multiply(a: number, b: number): Promise<number>;
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