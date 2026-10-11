package org.suut.javacard.pki.curve25519test;

import javacard.framework.*;
import javacardx.apdu.*;
import javacardx.crypto.*;
import javacard.security.*;
import java.lang.*;

import org.suut.javacard.pki.curve25519.Curve25519KeyBuilder;
import org.suut.javacard.pki.curve25519.Curve25519KeyAgreement;
import org.suut.javacard.pki.curve25519.Curve25519Signature;
import org.suut.javacard.pki.curve25519.Curve25519PublicKey;
import org.suut.javacard.pki.curve25519.Curve25519PrivateKey;

class Curve25519Test extends Applet {
    private Curve25519PublicKey publicKey;
    private Curve25519PrivateKey privateKey;
    private Curve25519PublicKey x25519PublicKey;
    private Curve25519PublicKey x25519RemotePublicKey;
    private Curve25519PrivateKey x25519PrivateKey;

    private Curve25519Signature signature;
    private Curve25519KeyAgreement keyAgreement;

    private byte[] sigBuff = null;
    private byte[] secretBuff = null;

    public static void install(byte[] array, short offset, byte length) throws ISOException {
        // check the install parameters

        byte Li = array[offset];
        byte Lc = array[(short)(offset+Li+1)];
        byte La = array[(short)(offset+Li+Lc+2)];

        if (La != 0) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }

        Curve25519Test applet = new Curve25519Test();
        applet.register();
    }

    private Curve25519Test() {
        publicKey = (Curve25519PublicKey)Curve25519KeyBuilder.buildKey(Curve25519KeyBuilder.ALG_TYPE_EDDSA_PUBLIC, JCSystem.MEMORY_TYPE_PERSISTENT);
        privateKey = (Curve25519PrivateKey)Curve25519KeyBuilder.buildKey(Curve25519KeyBuilder.ALG_TYPE_EDDSA_PRIVATE, JCSystem.MEMORY_TYPE_PERSISTENT);
        x25519PublicKey = (Curve25519PublicKey)Curve25519KeyBuilder.buildKey(Curve25519KeyBuilder.ALG_TYPE_X25519_PUBLIC, JCSystem.MEMORY_TYPE_PERSISTENT);
        x25519RemotePublicKey = (Curve25519PublicKey)Curve25519KeyBuilder.buildKey(Curve25519KeyBuilder.ALG_TYPE_X25519_PUBLIC, JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT);
        x25519PrivateKey = (Curve25519PrivateKey)Curve25519KeyBuilder.buildKey(Curve25519KeyBuilder.ALG_TYPE_X25519_PRIVATE, JCSystem.MEMORY_TYPE_PERSISTENT);
        sigBuff = JCSystem.makeTransientByteArray((short)64, JCSystem.CLEAR_ON_DESELECT);
        secretBuff = JCSystem.makeTransientByteArray((short)32, JCSystem.CLEAR_ON_DESELECT);

        Curve25519KeyBuilder.genKeyPair(privateKey, publicKey);
        Curve25519KeyBuilder.genKeyPair(x25519PrivateKey, x25519PublicKey);

        signature = new Curve25519Signature();
        keyAgreement = new Curve25519KeyAgreement();
    }

    public boolean select() {
        return true;
    }

    public void process(APDU apdu) throws ISOException {
        if(selectingApplet() || reSelectingApplet()) {
            return;
        }

        byte[] buffer = apdu.getBuffer();
        short length = apdu.setIncomingAndReceive();

        if (!apdu.isValidCLA()) {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }

        if (apdu.isCommandChainingCLA()) {
            ISOException.throwIt(ISO7816.SW_COMMAND_CHAINING_NOT_SUPPORTED);
        }

        if (apdu.isISOInterindustryCLA()) {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }

        if (apdu.isSecureMessagingCLA()) {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }

        byte cla = buffer[ISO7816.OFFSET_CLA];
        byte ins = buffer[ISO7816.OFFSET_INS];
        byte p1 = buffer[ISO7816.OFFSET_P1];
        byte p2 = buffer[ISO7816.OFFSET_P2];

        switch (ins) {
        case 0x10:
            if (p1 == 0x00) {
                publicKey.getW(buffer, (short)0);
            } else if (p1 == 0x01) {
                x25519PublicKey.getW(buffer, (short)0);
            } else {
                ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
            }
            apdu.setOutgoingAndSend((short)0, (short)32);
            break;

        case 0x20:
            short sigLength = signature.sign(privateKey, buffer, ISO7816.OFFSET_CDATA, length, sigBuff, (short)0);
            apdu.setOutgoing();
            apdu.setOutgoingLength(sigLength);
            apdu.sendBytesLong(sigBuff, (short)0, sigLength);
            break;

        case 0x30:
            if (length != 32) {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
            x25519RemotePublicKey.setW(buffer, ISO7816.OFFSET_CDATA, (short)32);
            short secretLength = keyAgreement.keyExchange(x25519PrivateKey, x25519RemotePublicKey, buffer, (short)0);
            apdu.setOutgoingAndSend((short)0, secretLength);
            break;

        case 0x40:
            if (length <= 64) {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

                boolean ok = signature.verify(publicKey, buffer, ISO7816.OFFSET_CDATA, (short)(length - 64),
                    buffer, (short)(ISO7816.OFFSET_CDATA + length - 64), (short)64);
                if (!ok) {
                    ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
                }
            }
            break;

        default:
            ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
            break;
        }
    }
}
