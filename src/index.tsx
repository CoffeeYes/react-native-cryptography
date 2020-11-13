import { NativeModules, requireNativeComponent, ViewStyle } from 'react-native';

type CryptoType = {
  multiply(a: number, b: number): Promise<number>;
  test(): Promise<string>;
  generateRSAKeyPair(alias : string): Promise<void>;
  deleteRSAKeyPair(alias : string) : Promise<void>;
  loadKeyFromKeystore(alias : string) : Promise<string>;
  encryptString(alias : string, encryptionType : string, stringToEncrypt : string) : Promise<string>;
  decryptString(alias : string, encryptionType : string, stringToDecrypt : string) : Promise<string>;
};

const { Crypto } = NativeModules;

export default Crypto as CryptoType;
