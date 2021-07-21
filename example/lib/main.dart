import 'dart:convert';

import 'package:flutter/material.dart';
import 'dart:async';

import 'package:flutter/services.dart';
import 'package:flutter_pkcs12/flutter_pkcs12.dart';

void main() => runApp(MyApp());

class MyApp extends StatefulWidget {
  @override
  _MyAppState createState() => _MyAppState();
}

class _MyAppState extends State<MyApp> {
  List<int> _p12Bytes;
  List _signatureHashes = ["PKCS-SHA1", "PKCS-SHA256", "PKCS-SHA512"];

  List<DropdownMenuItem<SignatureHashType>> _dropDownMenuItems;
  SignatureHashType _selectedHashType;

  TextEditingController _dataToSignController = new TextEditingController();

  SignWithP12Result _signature;
  CertificateResult _publicKey;

  @override
  void initState() {
    super.initState();
    _dataToSignController.text = "Hello world";
    _dropDownMenuItems = getDropDownMenuItems();
    _selectedHashType = _dropDownMenuItems[0].value;
  }

// here we are creating the list needed for the DropDownButton
  List<DropdownMenuItem<SignatureHashType>> getDropDownMenuItems() {
    List<DropdownMenuItem<SignatureHashType>> items = [];
    for (var i = 0; i < _signatureHashes.length; i++) {
      items.add(new DropdownMenuItem<SignatureHashType>(
          value: SignatureHashType.values[i],
          child: new Text(_signatureHashes[i])));
    }
    return items;
  }

  @override
  void didChangeDependencies() async {
    super.didChangeDependencies();
    _p12Bytes = await loadKeystoreAsset();
  }

  Future<List<int>> loadKeystoreAsset() async {
    return (await rootBundle.load('assets/keystore.p12')).buffer.asUint8List();
  }

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      home: Scaffold(
        appBar: AppBar(
          title: const Text('Flutter PKCS12'),
        ),
        body: ListView(
          children: <Widget>[
            Padding(
              padding: const EdgeInsets.only(top: 20),
              child: TextFormField(
                controller: _dataToSignController,
                decoration: InputDecoration(
                  border: OutlineInputBorder(
                    borderRadius: BorderRadius.circular(3.0),
                  ),
                  labelText: "Text to sign",
                ),
              ),
            ),
            Padding(
              padding: const EdgeInsets.only(top: 15, bottom: 5, left: 10),
              child: Row(
                children: <Widget>[
                  Text("Signature hash:"),
                  Padding(
                    padding: const EdgeInsets.only(left: 10),
                    child: DropdownButton(
                      value: _selectedHashType,
                      items: _dropDownMenuItems,
                      onChanged: (item) {
                        setState(() {
                          _selectedHashType = item;
                        });
                      },
                    ),
                  ),
                ],
              ),
            ),
            Padding(
              padding: const EdgeInsets.only(top: 10),
              child: ElevatedButton(
                child: Text("Sign data"),
                onPressed: () async {
                  var signature = await FlutterPkcs12().signDataWithP12(
                    data: utf8.encode(_dataToSignController.text),
                    p12Bytes: _p12Bytes,
                    password: "test",
                    signatureHashType: _selectedHashType,
                  );
                  setState(() {
                    _signature = signature;
                  });
                },
              ),
            ),
            Padding(
              padding: const EdgeInsets.only(top: 10),
              child: Text(
                  "Signature is ${_signature != null ? _signature.signature : ""}"),
            ),
            Padding(
              padding: const EdgeInsets.only(top: 30),
              child: ElevatedButton(
                child: Text("Read public key"),
                onPressed: () async {
                  final cert = await FlutterPkcs12()
                      .readPublicKey(p12Bytes: _p12Bytes, password: "test");
                  setState(() {
                    _publicKey = cert;
                  });
                },
              ),
            ),
            Padding(
              padding: const EdgeInsets.only(top: 10),
              child: Text(
                  "Public key is ${_publicKey != null ? _publicKey.b64 : ""}"),
            ),
          ],
        ),
      ),
    );
  }
}
