import 'dart:io';
import 'dart:convert';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:meta/meta.dart';
import "package:hex/hex.dart";

import 'package:bip32/src/utils/wif.dart' as wif;
import 'package:bs58check/bs58check.dart';
import 'package:bitcoin_flutter/bitcoin_flutter.dart';

import '../src/bip38.dart' as bip38;


void main() {
  var fixtures = jsonDecode(File('test/fixtures.json').readAsStringSync());
  var validTests = fixtures["valid"].map((object) => ValidTest(
    passphrase: object["passphrase"],
    bip38: object["bip38"],
    wif: object["wif"],
    address: object["address"],
    description: object["description"],
    decryptOnly: object["decryptOnly"],
    code: object["code"],
    confirm: object["confirm"],
    lot: object["lot"],
    seq: object["seq"]
  ));
  var invalid = fixtures["invalid"];

  group('decrypt', () {
      validTests.forEach((validTest) {
        test('should decrypt ${validTest.description}', () {
          bip38.PrivateKey actual = bip38.decrypt(validTest.bip38, validTest.passphrase, null);

          expect(actual, wif.encode(wif.WIF(
            version: 0x80, privateKey: actual.privateKey, compressed: actual.compressed
          )));
        });
      });


    test("Invalid", () {

    });
  });

  group('encrypt', () {
    test("Valid", () {

    });

    test("Invalid", () {
      
    });
  });

  group('verify', () {
    test("Valid", () {});

    test("Inalid", () {});
  });
}

class ValidTest {
  final String passphrase;
  final String bip38;
  final String wif;
  final String address;
  final String description;

  bool decryptOnly;
  String code;
  String confirm;
  int lot;
  int seq;

  ValidTest({
    @required this.passphrase,
    @required this.bip38,
    @required this.wif,
    @required this.address,
    @required this.description,
    this.decryptOnly,
    this.code,
    this.confirm,
    this.lot,
    this.seq
  });
}

class InvalidTest {
  List decrypt;
  List encrypt;
}

class InvalidVerify {
  final String description;
  final String exception;
  final String base58;

  InvalidVerify({
    this.description,
    this.exception,
    this.base58
  });
}