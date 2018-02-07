/*
  SmartPGP : JavaCard implementation of OpenPGP card v3 specification
  https://github.com/ANSSI-FR/SmartPGP
  Copyright (C) 2016 ANSSI

  This program is free software; you can redistribute it and/or
  modify it under the terms of the GNU General Public License
  as published by the Free Software Foundation; either version 2
  of the License, or (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

package fr.anssi.smartpgp;

import javacard.framework.*;

public final class InsecurePIN {

    private final byte tryLimit;
    private byte tryCount;
    private boolean isBlocked;

    private final byte[] pin;
    private short pinSize;

    public static final byte USER_PIN = (byte)0x81;
    public static final byte USER_PUK = (byte)0x82;
    public static final byte ADMIN_PIN = (byte)0x83;
    private final byte pinType;

    private final Transients transients;

    public InsecurePIN(byte tryLimit,
                       byte maxSize,
                       byte pinType,
                       final Transients transients) {
        if(tryLimit < 1) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }

        switch(pinType) {
        case USER_PIN:
        case USER_PUK:
        case ADMIN_PIN:
            break;
        default:
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            break;
        }

        this.tryLimit = tryLimit;
        tryCount = 0;
        this.isBlocked = false;
        pin = new byte[maxSize];
        pinSize = 0;
        this.transients = transients;
        this.pinType = pinType;
    }

    private final void setValidated(boolean validated) {
        switch(pinType) {
        case USER_PIN:
            transients.setUserPinValidated(validated);
            break;

        case USER_PUK:
            transients.setUserPukValidated(validated);
            break;

        case ADMIN_PIN:
            transients.setAdminPinValidated(validated);
            break;

        default:
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            break;
        }
    }

    public final boolean isValidated() {
        switch(pinType) {
        case USER_PIN:
            return transients.userPinValidated();

        case USER_PUK:
            return transients.userPukValidated();

        case ADMIN_PIN:
            return transients.adminPinValidated();

        default:
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            return false;
        }
    }

    public final byte getTriesRemaining() {
        return (byte)(tryLimit - tryCount);
    }

    public final boolean check(byte[] pin, short offset, byte length) {
        if((pinSize <= 0) ||
           (length > pin.length) ||
           (tryCount >= tryLimit) || isBlocked) {
            return false;
        }

        ++tryCount;

        if(length != pinSize) {
            return false;
        }

        boolean result = true;

        for(byte i = 0; i < length; ++i) {
            result = result && (pin[(short)(offset + i)] == this.pin[i]);
        }

        if(result) {
            tryCount = 0;
        } else if(getTriesRemaining() <= 0) {
            isBlocked = true;
        }

        setValidated(result);

        return result;
    }

    public final void reset() {
        setValidated(false);
        tryCount = 0;
    }

    public final void resetAndUnblock() {
        reset();
        isBlocked = false;
    }

    public final void update(byte[] newPin, short offset, byte length) {
        if((length <= 0) || (length > pin.length)) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            return;
        }

        Util.arrayFillNonAtomic(pin, (short)0, (short)pin.length, (byte)0);
        Util.arrayCopyNonAtomic(newPin, offset, pin, (short)0, length);
        pinSize = length;

        resetAndUnblock();
    }
}
