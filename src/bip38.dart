library bip38;

import 'dart:convert';
import 'dart:typed_data';

import 'package:collection/collection.dart';

import 'package:bs58check/bs58check.dart' as bs58check;
import 'package:pointycastle/ecc/curves/secp256k1.dart' as curve;
import 'package:pointycastle/key_derivators/scrypt.dart';
import 'package:pointycastle/key_derivators/api.dart';
import 'package:pointycastle/block/aes_fast.dart';
import 'package:pointycastle/digests/ripemd160.dart';
import 'package:pointycastle/digests/sha256.dart';
import 'package:pointycastle/src/utils.dart';
import 'package:pointycastle/api.dart';
import 'package:xor/xor.dart';

class PrivateKey {
  final bool compressed;
  final Uint8List privateKey;

  PrivateKey({
    this.compressed,
    this.privateKey
  });
}

const Map<String, int> SCRYPT_PARAMS = {
  "N": 16384, // specified by BIP38
  "r": 8,
  "p": 8,
  "desiredKeyLength": 64
};

final NULL = Uint8List(0);

Uint8List hash160 (Uint8List buffer) {
  return RIPEMD160Digest().process(
    SHA256Digest().process(buffer)
  );
}

Uint8List hash256 (Uint8List buffer) {
  return SHA256Digest().process(buffer);
}

String getAddress (BigInt d, bool compressed) {
  var  Q = (curve.ECCurve_secp256k1().G * d).getEncoded(compressed);
  var hash = hash160(Q);
  final Uint8List payload = Uint8List(21);
  payload.insert(0, 0x00); //(0x00, 0) // XXX TODO FIXME bitcoin only??? damn you BIP38
  payload.insertAll(1, hash);

  return bs58check.encode(payload);
}

Uint8List encryptRaw (Uint8List buffer, bool compressed, String passphrase, scryptParams) {
  if (buffer.length != 32) throw ArgumentError('Invalid private key length');

  scryptParams?? SCRYPT_PARAMS;

  BigInt d = decodeBigInt(buffer);  // BigInt.parse(buffer.toString());
  String address = getAddress(d, compressed);
  Uint8List secret = utf8.encode(passphrase);
  Uint8List salt = hash256(utf8.encode(address)).sublist(0, 4);

  ScryptParameters scryptParameters = ScryptParameters(
    scryptParams.N,
    scryptParams.r,
    scryptParams.p, 
    scryptParams.desiredKeyLength,
    salt
  );

  Scrypt scryptBuf = Scrypt();
  scryptBuf.init(scryptParameters);

  Uint8List derivedKey;
  scryptBuf.deriveKey(secret, 0, derivedKey, 0);
  Uint8List derivedHalf1 = derivedKey.sublist(0, 32);
  Uint8List derivedHalf2 = derivedKey.sublist(32, 64);

  Uint8List xorBuf = xor(buffer, derivedHalf1);
  AESFastEngine cipher = AESFastEngine();
  cipher.init(true, KeyParameter(derivedHalf2));
  Uint8List cipherText = cipher.process(xorBuf);

  // 0x01 | 0x42 | flagByte | salt (4) | cipherText (32)
  Uint8List result = Uint8List(39);
  result.insert(0, 0x01);
  result.insert(1, 0x42);
  result.insert(2, compressed ? 0xe0 : 0xc0);
  result.insertAll(3, salt);
  result.insertAll(7, cipherText);

  return result;
}

String encrypt (Uint8List buffer, bool compressed, String passphrase) {
  return bs58check.encode(encryptRaw(buffer, compressed, passphrase, null));
}

PrivateKey decryptRaw (Uint8List buffer, String passphrase, scryptParams) {
  // 39 bytes: 2 bytes prefix, 37 bytes payload
  if (buffer.length != 39) throw ArgumentError('Invalid BIP38 data length');
  if (buffer.elementAt(0) != 0x01) throw ArgumentError('Invalid BIP38 prefix');
  scryptParams?? SCRYPT_PARAMS;

  // check if BIP38 EC multiply
  int type = buffer.elementAt(1);
  if (type == 0x43) return decryptECMult(buffer, passphrase, scryptParams);
  if (type != 0x42) throw ArgumentError('Invalid BIP38 type');

  Uint8List secret = utf8.encode(passphrase);

  int flagByte = buffer.elementAt(2);
  bool compressed = flagByte == 0xe0;
  if (!compressed && flagByte != 0xc0) throw ArgumentError('Invalid BIP38 compression flag');
  Uint8List salt = buffer.sublist(3, 7);

  ScryptParameters scryptParameters = ScryptParameters(
    scryptParams.N,
    scryptParams.r,
    scryptParams.p, 
    scryptParams.desiredKeyLength,
    salt,
  );

  Scrypt scryptBuf = Scrypt();
  scryptBuf.init(scryptParameters);

  Uint8List derivedKey;
  scryptBuf.deriveKey(secret, 0, derivedKey, 0);
  Uint8List derivedHalf1 = secret.sublist(0, 32);
  Uint8List derivedHalf2 = derivedKey.sublist(32, 64);

  Uint8List privKeyBuf = buffer.sublist(7, 39);
  AESFastEngine decipher = AESFastEngine();
  decipher.init(false, KeyParameter(derivedHalf2));
  Uint8List plainText = decipher.process(privKeyBuf);

  Uint8List privateKey = xor(derivedHalf1, plainText);
  BigInt d = decodeBigInt(privateKey); //BigInt.parse(privateKey.toString());

  String address = getAddress(d, compressed);
  Uint8List checksum = hash256(utf8.encode(address)).sublist(0, 4);


  if (!ListEquality().equals(salt, checksum)) {
    throw StateError("Checksum didn't match");
  }

  return PrivateKey(
    privateKey: privateKey,
    compressed: compressed
  );
}



PrivateKey decrypt (String string, String passphrase, scryptParams) {
  return decryptRaw(bs58check.decode(string), passphrase, scryptParams);
}

PrivateKey decryptECMult (Uint8List buffer, String passphrase, scryptParams) {
  Uint8List secret = utf8.encode(passphrase);

  buffer.removeAt(1);
  int flagByte = buffer.elementAt(1);
  bool compressed = (flagByte & 0x20) != 0;
  bool hasLotSeq = (flagByte & 0x04) != 0;

  if (flagByte & 0x24 != flagByte) throw ArgumentError('Invalid private key.');

  Uint8List addressHash = buffer.sublist(2, 6);
  Uint8List ownerEntropy = buffer.sublist(6, 14);
  Uint8List ownerSalt;

  if (hasLotSeq) {
    ownerSalt = ownerEntropy.sublist(0, 4);
  } else {
    ownerSalt = ownerEntropy;
  }

  Uint8List encryptedPart1 = buffer.sublist(14, 22);
  Uint8List encryptedPart2 = buffer.sublist(22, 38);

  ScryptParameters scryptParameters = ScryptParameters(
    scryptParams.N,
    scryptParams.r,
    scryptParams.p, 
    32,
    ownerSalt,
  );

  Scrypt scryptBuf = Scrypt();
  scryptBuf.init(scryptParameters);

  Uint8List preFactor = scryptBuf.process(secret);

  Uint8List passFactor;

  if (hasLotSeq) {
    Uint8List hashTarget = preFactor + ownerEntropy;
    passFactor = hash256(hashTarget);
  } else {
    passFactor = preFactor;
  }

  BigInt passInt = decodeBigInt(passFactor); // BigInt.parse(passFactor.toString());
  Uint8List passPoint = (curve.ECCurve_secp256k1().G * passInt).getEncoded(true);

  ScryptParameters seedBParameters = ScryptParameters(1024, 1, 1, 64, addressHash + ownerEntropy);
  Scrypt seedBPass = Scrypt();
  seedBPass.init(seedBParameters);
  Uint8List seedBPassBuffer = seedBPass.process(passPoint);
  Uint8List derivedHalf1 = seedBPassBuffer.sublist(0, 32);
  Uint8List derivedHalf2 = seedBPassBuffer.sublist(32, 64);

  AESFastEngine decipher = AESFastEngine();
  decipher.init(false, KeyParameter(derivedHalf2));
  Uint8List decryptedPart2 = decipher.process(encryptedPart2);

  Uint8List tmp = xor(decryptedPart2, derivedHalf1.sublist(16, 32));
  Uint8List seedBPart2 = tmp.sublist(8, 16);

  AESFastEngine decipher2 = AESFastEngine();
  decipher2.init(false, KeyParameter(derivedHalf2));
  Uint8List seedBPart1 = xor(decipher2.process(encryptedPart1 + tmp.sublist(0, 8)), derivedHalf1.sublist(0, 16));

  Uint8List seedB = seedBPart1 + seedBPart2;
  BigInt factorB = decodeBigInt(hash256(seedB)); //BigInt.parse(hash256(seedB).toString());

  BigInt d = passInt * factorB % curve.ECCurve_secp256k1().n;

  return PrivateKey(
    privateKey: encodeBigInt(d),
    compressed: compressed
  );
}


bool verify (String string) {
  Uint8List decoded;

  try {
    decoded = bs58check.decode(string);
  } catch (e) {
    return false;
  }

  if (decoded.length != 39) return false;
  if (decoded.elementAt(0) != 0x01) return false;

  int type = decoded.elementAt(1);
  int flag = decoded.elementAt(2);

  // encrypted WIF
  if (type == 0x42) {
    if (flag != 0xc0 && flag != 0xe0) return false;

  // EC mult
  } else if (type == 0x43) {
    if ((flag & ~0x24 == 0)) return false;
  } else {
    return false;
  }

  return true;
}