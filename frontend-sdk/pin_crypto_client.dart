import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:pointycastle/export.dart' as pc;
import 'package:asn1lib/asn1lib.dart';

/// ============================================================================
/// PCI-PIN E2E Client SDK para Flutter (iOS / Android / Web)
/// ============================================================================
/// Implementa el Punto 2 del Brief Técnico en Dart/Flutter:
/// 1. Entorno Seguro de Captura: Widget/Configuración de TextField que bloquea
///    teclados predictivos, autocompletado, copiar/pegar y menú contextual.
/// 2. Generación de PIN Block: ISO 9564 Formato 4 (16 bytes) en Uint8List
///    vinculado criptográficamente a los 12 dígitos de la cuenta (PAN).
/// 3. Cifrado E2E: RSA-OAEP con SHA-256 y MGF1(SHA-256) compatible con el
///    Utimaco PaymentServer HSM (v6.6.0.0) usando PointyCastle.
/// 4. Volatilidad de Datos: sobrescritura inmediata en RAM (`fillRange(0, len, 0)`)
///    de cualquier `Uint8List` con dígitos del PIN o bloques en claro en `finally`.
///
/// Dependencias requeridas en el `pubspec.yaml` de tu app Flutter:
/// ```yaml
/// dependencies:
///   pointycastle: ^3.9.1
///   asn1lib: ^1.5.3
/// ```
class PinCryptoFlutterClient {
  PinCryptoFlutterClient._();

  /// 1. GENERACIÓN DE PIN BLOCK (ISO 9564 Formato 4 - 16 bytes)
  /// Construye el bloque en un `Uint8List(16)` mutable sin crear `String` con el PIN,
  /// permitiendo sobrescribir la memoria RAM con ceros tras el cifrado RSA-OAEP.
  ///
  /// Estructura (32 nibbles = 16 bytes):
  /// - Byte 0: `0x44` (Control field '4' Formato 4 + Longitud '4')
  /// - Bytes 1..2: 4 dígitos del PIN en BCD (ej. `[7, 3, 9, 2]` -> `0x73, 0x92`)
  /// - Bytes 3..7: Padding fijo `0xAA` (`AAAAAAAAAA` según ISO 9564-1 Formato 4)
  /// - Bytes 8..9: Prefijo `0x00, 0x00` (`0000`)
  /// - Bytes 10..15: 12 dígitos de cuenta ISO en BCD
  static Uint8List buildIso9564Format4PinBlockBytes(
    Uint8List pinDigits,
    String panOrAccountId,
  ) {
    if (pinDigits.length != 4) {
      throw ArgumentError('El PIN debe tener exactamente 4 dígitos.');
    }
    for (int i = 0; i < 4; i++) {
      if (pinDigits[i] > 9) {
        throw ArgumentError('Cada dígito del PIN debe estar entre 0 y 9.');
      }
    }

    final String normalizedAccount12 = extractIso12AccountDigits(panOrAccountId);
    final Uint8List block = Uint8List(16);

    // Byte 0: '4' (Format 4) y '4' (PIN length 4) -> 0x44
    block[0] = 0x44;

    // Byte 1..2: 4 dígitos del PIN en BCD
    block[1] = ((pinDigits[0] & 0x0F) << 4) | (pinDigits[1] & 0x0F);
    block[2] = ((pinDigits[2] & 0x0F) << 4) | (pinDigits[3] & 0x0F);

    // Bytes 3..7: 10 nibbles 'A' -> 5 bytes 0xAA
    block[3] = 0xAA;
    block[4] = 0xAA;
    block[5] = 0xAA;
    block[6] = 0xAA;
    block[7] = 0xAA;

    // Bytes 8..9: '0000' -> 0x00, 0x00
    block[8] = 0x00;
    block[9] = 0x00;

    // Bytes 10..15: 12 dígitos de cuenta ISO en BCD
    for (int i = 0; i < 6; i++) {
      final int highNibble = normalizedAccount12.codeUnitAt(i * 2) - 48;
      final int lowNibble = normalizedAccount12.codeUnitAt(i * 2 + 1) - 48;
      block[10 + i] = ((highNibble & 0x0F) << 4) | (lowNibble & 0x0F);
    }

    return block;
  }

  /// Extrae los 12 dígitos más a la derecha excluyendo el dígito verificador final (ISO 9564).
  static String extractIso12AccountDigits(String panOrUserId) {
    final String digits = panOrUserId.replaceAll(RegExp(r'\D'), '');
    if (digits.length >= 13) {
      return digits.substring(digits.length - 13, digits.length - 1);
    }
    return digits.padLeft(12, '0');
  }

  /// 2. CIFRADO E2E RSA-OAEP (SHA-256 + MGF1-SHA-256) + VOLATILIDAD DE DATOS
  /// Cifra el PIN Block ISO 9564 Formato 4 con la llave pública RSA-2048 del HSM
  /// y limpia inmediatamente (`fillRange(0, length, 0)`) tanto `pinDigits` como el
  /// bloque en claro en un bloque `finally`.
  static String encryptPinBlockE2E({
    required Uint8List pinDigits,
    required String panOrAccountId,
    required String hsmPublicKeyPem,
  }) {
    Uint8List? clearPinBlock;
    try {
      final pc.RSAPublicKey publicKey = parsePublicKeyFromPem(hsmPublicKeyPem);
      clearPinBlock = buildIso9564Format4PinBlockBytes(pinDigits, panOrAccountId);

      final Uint8List encryptedBytes = _rsaOaepSha256Encrypt(
        clearPinBlock,
        publicKey,
      );
      return base64Encode(encryptedBytes);
    } finally {
      // VOLATILIDAD DE DATOS (PCI-PIN): sobrescritura inmediata con ceros en RAM
      zeroize(pinDigits);
      if (clearPinBlock != null) {
        zeroize(clearPinBlock);
      }
    }
  }

  /// Prepara el Map JSON listo para enviar a `POST /api/v1/account/change-pin`
  /// garantizando que ambos arreglos de PIN (`currentPinDigits` y `newPinDigits`)
  /// queden en cero en memoria RAM inmediatamente después de cifrar.
  static Map<String, dynamic> prepareChangePinRequestPayload({
    required String userId,
    required String panOrAccountNumber,
    required Uint8List currentPinDigits,
    required Uint8List newPinDigits,
    required String publicKeyPem,
    String? storedPinBlockUnderLmk,
  }) {
    try {
      final String encryptedCurrentPin = encryptPinBlockE2E(
        pinDigits: currentPinDigits,
        panOrAccountId: panOrAccountNumber,
        hsmPublicKeyPem: publicKeyPem,
      );

      final String encryptedNewPin = encryptPinBlockE2E(
        pinDigits: newPinDigits,
        panOrAccountId: panOrAccountNumber,
        hsmPublicKeyPem: publicKeyPem,
      );

      return <String, dynamic>{
        'userId': userId,
        'panOrAccountNumber': panOrAccountNumber,
        'encryptedCurrentPin': encryptedCurrentPin,
        'encryptedNewPin': encryptedNewPin,
        if (storedPinBlockUnderLmk != null)
          'storedPinBlockUnderLmk': storedPinBlockUnderLmk,
      };
    } finally {
      zeroize(currentPinDigits);
      zeroize(newPinDigits);
    }
  }

  /// Prepara el Map JSON listo para enviar a `POST /api/v1/account/verify-pin`
  /// garantizando que el arreglo de PIN (`pinDigits`) quede en cero en memoria RAM
  /// inmediatamente después de cifrar.
  static Map<String, dynamic> prepareVerifyPinRequestPayload({
    required String userId,
    required String panOrAccountNumber,
    required Uint8List pinDigits,
    required String publicKeyPem,
    String? storedPinBlockUnderLmk,
  }) {
    try {
      final String encryptedPin = encryptPinBlockE2E(
        pinDigits: pinDigits,
        panOrAccountId: panOrAccountNumber,
        hsmPublicKeyPem: publicKeyPem,
      );

      return <String, dynamic>{
        'userId': userId,
        'panOrAccountNumber': panOrAccountNumber,
        'encryptedPin': encryptedPin,
        if (storedPinBlockUnderLmk != null)
          'storedPinBlockUnderLmk': storedPinBlockUnderLmk,
      };
    } finally {
      zeroize(pinDigits);
    }
  }

  /// Implementación RFC 8017 de RSAES-OAEP-ENCRYPT con SHA-256 tanto para el
  /// Hash del Label como para MGF1(SHA-256), compatible 100% con JCE/PKCS#11:
  /// `RSA/ECB/OAEPWithSHA-256AndMGF1Padding`.
  static Uint8List _rsaOaepSha256Encrypt(
    Uint8List message,
    pc.RSAPublicKey publicKey,
  ) {
    final pc.Digest sha256 = pc.Digest('SHA-256');
    final int hLen = sha256.digestSize; // 32 bytes
    final int k = (publicKey.modulus!.bitLength + 7) ~/ 8; // 256 bytes (RSA-2048)

    if (message.length > k - 2 * hLen - 2) {
      throw ArgumentError('Mensaje demasiado largo para RSA-OAEP-256');
    }

    // lHash = SHA-256("") para PSource.PSpecified.DEFAULT
    final Uint8List lHash = Uint8List(hLen);
    sha256.reset();
    sha256.doFinal(lHash, 0);

    // DB = lHash || PS (ceros) || 0x01 || M
    final int dbLen = k - hLen - 1;
    final Uint8List db = Uint8List(dbLen);
    final Uint8List seed = Uint8List(hLen);
    final Uint8List dbMask = Uint8List(dbLen);
    final Uint8List maskedDb = Uint8List(dbLen);
    final Uint8List seedMask = Uint8List(hLen);
    final Uint8List maskedSeed = Uint8List(hLen);
    final Uint8List em = Uint8List(k);

    try {
      db.setRange(0, hLen, lHash);
      final int psLen = dbLen - hLen - 1 - message.length;
      db[hLen + psLen] = 0x01;
      db.setRange(hLen + psLen + 1, dbLen, message);

      // Generar seed criptográficamente seguro
      final Random secureRandom = Random.secure();
      for (int i = 0; i < hLen; i++) {
        seed[i] = secureRandom.nextInt(256);
      }

      // dbMask = MGF1-SHA256(seed, dbLen)
      _mgf1Sha256(seed, dbLen, dbMask);
      for (int i = 0; i < dbLen; i++) {
        maskedDb[i] = db[i] ^ dbMask[i];
      }

      // seedMask = MGF1-SHA256(maskedDB, hLen)
      _mgf1Sha256(maskedDb, hLen, seedMask);
      for (int i = 0; i < hLen; i++) {
        maskedSeed[i] = seed[i] ^ seedMask[i];
      }

      // EM = 0x00 || maskedSeed || maskedDB
      em[0] = 0x00;
      em.setRange(1, 1 + hLen, maskedSeed);
      em.setRange(1 + hLen, k, maskedDb);

      final pc.AsymmetricBlockCipher rsaEngine = pc.RSAEngine()
        ..init(true, pc.PublicKeyParameter<pc.RSAPublicKey>(publicKey));

      return rsaEngine.process(em);
    } finally {
      // Limpieza de todos los buffers intermedios del padding OAEP
      zeroize(db);
      zeroize(seed);
      zeroize(dbMask);
      zeroize(maskedDb);
      zeroize(seedMask);
      zeroize(maskedSeed);
      zeroize(em);
    }
  }

  static void _mgf1Sha256(Uint8List seed, int maskLen, Uint8List outMask) {
    final pc.Digest sha256 = pc.Digest('SHA-256');
    final int hLen = sha256.digestSize;
    final Uint8List counterBytes = Uint8List(4);
    final Uint8List hashBuf = Uint8List(hLen);

    int generated = 0;
    int counter = 0;
    while (generated < maskLen) {
      counterBytes[0] = (counter >> 24) & 0xFF;
      counterBytes[1] = (counter >> 16) & 0xFF;
      counterBytes[2] = (counter >> 8) & 0xFF;
      counterBytes[3] = counter & 0xFF;

      sha256.reset();
      sha256.update(seed, 0, seed.length);
      sha256.update(counterBytes, 0, 4);
      sha256.doFinal(hashBuf, 0);

      final int toCopy = min(hLen, maskLen - generated);
      outMask.setRange(generated, generated + toCopy, hashBuf);
      generated += toCopy;
      counter++;
    }
    zeroize(hashBuf);
  }

  /// Parsea la llave pública X.509 SubjectPublicKeyInfo (PEM) devuelta por
  /// `GET /api/v1/security/pin-key`.
  static pc.RSAPublicKey parsePublicKeyFromPem(String pemString) {
    final String cleanBase64 = pemString
        .replaceAll('-----BEGIN PUBLIC KEY-----', '')
        .replaceAll('-----END PUBLIC KEY-----', '')
        .replaceAll(RegExp(r'\s+'), '');

    final Uint8List derBytes = base64Decode(cleanBase64);
    final ASN1Parser topLevelParser = ASN1Parser(derBytes);
    final ASN1Sequence topLevelSeq =
        topLevelParser.nextObject() as ASN1Sequence;

    final ASN1BitString publicKeyBitString =
        topLevelSeq.elements[1] as ASN1BitString;
    final ASN1Parser publicKeyParser =
        ASN1Parser(publicKeyBitString.contentBytes());
    final ASN1Sequence pkSeq = publicKeyParser.nextObject() as ASN1Sequence;

    final ASN1Integer modulus = pkSeq.elements[0] as ASN1Integer;
    final ASN1Integer exponent = pkSeq.elements[1] as ASN1Integer;

    return pc.RSAPublicKey(
      modulus.valueAsBigInteger,
      exponent.valueAsBigInteger,
    );
  }

  /// Sobrescribe inmediatamente con ceros todos los bytes de un buffer en RAM.
  static void zeroize(Uint8List buffer) {
    buffer.fillRange(0, buffer.length, 0);
  }
}

/// ============================================================================
/// WIDGET FLUTTER DE CAPTURA SEGURA DE PIN (PCI-PIN Compliant)
/// ============================================================================
/// - Desactiva sugerencias del sistema operativo (`enableSuggestions: false`)
/// - Desactiva autocorrección (`autocorrect: false`)
/// - Desactiva el menú contextual de copiar/pegar (`contextMenuBuilder: empty`)
/// - Desactiva el aprendizaje personalizado del teclado (`enableIMEPersonalizedLearning: false`)
/// - Oculta los caracteres (`obscureText: true`)
class SecurePinTextField extends StatelessWidget {
  final TextEditingController controller;
  final String labelText;
  final ValueChanged<String>? onCompleted;

  const SecurePinTextField({
    super.key,
    required this.controller,
    required this.labelText,
    this.onCompleted,
  });

  @override
  Widget build(BuildContext context) {
    return TextField(
      controller: controller,
      obscureText: true,
      obscuringCharacter: '•',
      keyboardType: TextInputType.number,
      maxLength: 4,
      autocorrect: false,
      enableSuggestions: false,
      enableInteractiveSelection: false, // Bloquea selección y portapapeles
      enableIMEPersonalizedLearning: false, // Bloquea historial de teclado en Android
      autofillHints: const <String>[], // Desactiva autocompletado de iOS/Android
      contextMenuBuilder: (BuildContext context, EditableTextState state) {
        return const SizedBox.shrink(); // Desactiva menú Copiar/Pegar
      },
      inputFormatters: <TextInputFormatter>[
        FilteringTextInputFormatter.digitsOnly,
        LengthLimitingTextInputFormatter(4),
      ],
      decoration: InputDecoration(
        labelText: labelText,
        counterText: '',
        border: const OutlineInputBorder(),
      ),
      onChanged: (String value) {
        if (value.length == 4 && onCompleted != null) {
          onCompleted!(value);
        }
      },
    );
  }
}

