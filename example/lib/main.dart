import 'dart:typed_data';

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

  TextEditingController _dataToSignController = new TextEditingController();

  SignWithP12Result _signature;
  CertificateResult _publicKey;

  @override
  void initState() {
    super.initState();
    _dataToSignController.text = "Hello world";
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
              padding: const EdgeInsets.only(top: 10),
              child: RaisedButton(
                child: Text("Sign data"),
                onPressed: () async {
                  var signature = await FlutterPkcs12().signDataWithP12(
                    data: Uint8List.fromList(
                        _dataToSignController.text.codeUnits),
                    p12Bytes: _p12Bytes,
                    password: "test",
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
              child: RaisedButton(
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
