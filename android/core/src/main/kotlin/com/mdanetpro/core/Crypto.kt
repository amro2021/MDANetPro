package com.mdanetpro.core

import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.NoSuchAlgorithmException
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.Signature
import java.security.spec.MGF1ParameterSpec
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.PSSParameterSpec
import java.security.spec.X509EncodedKeySpec
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Crypto matching the Python app (pycryptodome defaults):
 *  - RSA-2048 keys; public keys as SubjectPublicKeyInfo PEM in pycryptodome's layout
 *  - signatures: RSA-PSS, SHA-256, MGF1(SHA-256), salt 32 bytes
 *  - key wrapping: RSA-OAEP with SHA-1 / MGF1(SHA-1)
 *  - payload: AES-256-GCM, 12-byte nonce, 16-byte tag sent separately
 */
object Crypto {
    private val random = SecureRandom()

    class Identity(val privateKey: PrivateKey, val publicKey: PublicKey) {
        val publicPem: String = publicKeyToPem(publicKey)
        val privatePem: String get() = pem("PRIVATE KEY", privateKey.encoded)
    }

    fun generateIdentity(): Identity {
        val gen = KeyPairGenerator.getInstance("RSA")
        gen.initialize(2048, random)
        val pair = gen.generateKeyPair()
        return Identity(pair.private, pair.public)
    }

    fun loadIdentity(privatePem: String, publicPem: String): Identity =
        Identity(privateKeyFromPem(privatePem), publicKeyFromPem(publicPem))

    private fun pem(type: String, der: ByteArray): String {
        val body = Base64.getEncoder().encodeToString(der).chunked(64).joinToString("\n")
        return "-----BEGIN $type-----\n$body\n-----END $type-----"
    }

    fun publicKeyToPem(key: PublicKey): String = pem("PUBLIC KEY", key.encoded)

    private fun pemBody(pem: String): ByteArray {
        val body = pem.lines().filter { !it.startsWith("-----") }.joinToString("").filterNot { it.isWhitespace() }
        return Base64.getDecoder().decode(body)
    }

    fun publicKeyFromPem(pem: String): PublicKey =
        KeyFactory.getInstance("RSA").generatePublic(X509EncodedKeySpec(pemBody(pem)))

    fun privateKeyFromPem(pem: String): PrivateKey =
        KeyFactory.getInstance("RSA").generatePrivate(PKCS8EncodedKeySpec(pemBody(pem)))

    // ---- signatures ---------------------------------------------------------------------
    private fun pssSignature(): Signature {
        return try {
            Signature.getInstance("SHA256withRSA/PSS") // Android (Conscrypt): MGF1-SHA256, salt 32
        } catch (_: NoSuchAlgorithmException) {
            Signature.getInstance("RSASSA-PSS").apply {  // desktop JDK
                setParameter(PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1))
            }
        }
    }

    fun sign(privateKey: PrivateKey, data: ByteArray): ByteArray {
        val sig = pssSignature()
        sig.initSign(privateKey)
        sig.update(data)
        return sig.sign()
    }

    fun verify(publicKey: PublicKey, data: ByteArray, signature: ByteArray): Boolean = try {
        val sig = pssSignature()
        sig.initVerify(publicKey)
        sig.update(data)
        sig.verify(signature)
    } catch (_: Exception) {
        false
    }

    fun verifyPem(publicPem: String, data: ByteArray, signatureB64: String): Boolean = try {
        verify(publicKeyFromPem(publicPem), data, b64d(signatureB64))
    } catch (_: Exception) {
        false
    }

    // ---- encryption ---------------------------------------------------------------------
    fun oaepEncrypt(publicKey: PublicKey, data: ByteArray): ByteArray =
        Cipher.getInstance("RSA/ECB/OAEPWithSHA-1AndMGF1Padding").run {
            init(Cipher.ENCRYPT_MODE, publicKey)
            doFinal(data)
        }

    fun oaepDecrypt(privateKey: PrivateKey, data: ByteArray): ByteArray =
        Cipher.getInstance("RSA/ECB/OAEPWithSHA-1AndMGF1Padding").run {
            init(Cipher.DECRYPT_MODE, privateKey)
            doFinal(data)
        }

    class Sealed(val nonce: ByteArray, val ciphertext: ByteArray, val tag: ByteArray)

    fun aesGcmEncrypt(key: ByteArray, plain: ByteArray): Sealed {
        val nonce = randomBytes(12)
        val out = Cipher.getInstance("AES/GCM/NoPadding").run {
            init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
            doFinal(plain)
        }
        return Sealed(nonce, out.copyOfRange(0, out.size - 16), out.copyOfRange(out.size - 16, out.size))
    }

    fun aesGcmDecrypt(key: ByteArray, nonce: ByteArray, ciphertext: ByteArray, tag: ByteArray): ByteArray =
        Cipher.getInstance("AES/GCM/NoPadding").run {
            init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
            doFinal(ciphertext + tag)
        }

    // ---- misc ---------------------------------------------------------------------------
    fun randomBytes(n: Int) = ByteArray(n).also { random.nextBytes(it) }

    fun sha256(data: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(data)

    fun sha256Hex(data: ByteArray): String = sha256(data).joinToString("") { "%02x".format(it) }

    fun b64(data: ByteArray): String = Base64.getEncoder().encodeToString(data)

    fun b64d(text: String): ByteArray = Base64.getDecoder().decode(text.trim())

    fun hex(n: Int) = randomBytes(n).joinToString("") { "%02x".format(it) }
}
