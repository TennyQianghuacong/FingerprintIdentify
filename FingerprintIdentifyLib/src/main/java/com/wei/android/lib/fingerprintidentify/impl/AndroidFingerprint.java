package com.wei.android.lib.fingerprintidentify.impl;

import android.annotation.TargetApi;
import android.app.Activity;
import android.content.Context;
import android.content.SharedPreferences;
import android.hardware.fingerprint.FingerprintManager;
import android.os.Build;
import android.preference.PreferenceManager;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyPermanentlyInvalidatedException;
import android.security.keystore.KeyProperties;
import android.support.v4.os.CancellationSignal;
import android.text.TextUtils;
import android.util.Base64;
import android.util.Log;

import com.wei.android.lib.fingerprintidentify.aosp.FingerprintManagerCompat;
import com.wei.android.lib.fingerprintidentify.base.BaseFingerprint;

import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.KeyStore;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import static android.content.ContentValues.TAG;

/**
 * Copyright (c) 2017 Awei
 * <p>
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * <p>
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * <p>
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 * <p>
 * Created by Awei on 2017/2/9.
 */
public class AndroidFingerprint extends BaseFingerprint {

    private CancellationSignal mCancellationSignal;
    private FingerprintManagerCompat mFingerprintManagerCompat;
    private final String KEY_FINGER = "KEY_FINGER_ADNROID";
    private SharedPreferences sp;
    private SharedPreferences.Editor editor;
    private FingerprintManagerCompat.CryptoObject cryptoObject ;
    private KeyStore keyStore;
    private KeyGenerator generator;
    private Cipher cipher;
    private static final String KEY_ALIAS = "sitepoint";
    private static final String KEYSTORE = "AndroidKeyStore";
    private static final String PREFERENCES_KEY_EMAIL = "email";
    private static final String PREFERENCES_KEY_PASS = "pass";
    private static final String PREFERENCES_KEY_IV = "iv";

    public AndroidFingerprint(Activity activity, FingerprintIdentifyExceptionListener exceptionListener) {
        super(activity, exceptionListener);
        sp = PreferenceManager.getDefaultSharedPreferences(activity.getBaseContext());
        editor = sp.edit();

        try {
            mFingerprintManagerCompat = FingerprintManagerCompat.from(activity);
            setHardwareEnable(mFingerprintManagerCompat.isHardwareDetected());
            setRegisteredFingerprint(mFingerprintManagerCompat.hasEnrolledFingerprints());
            getFingerData(activity);

            initCipher(Cipher.ENCRYPT_MODE);
            initCryptObject();

        } catch (Throwable e) {
            onCatchException(e);
        }
    }

    private void getFingerData(Activity activity) {
        String local_str = sp.getString(KEY_FINGER,"");
        FingerprintManager fingerprintManager = (FingerprintManager)activity.getSystemService(Context.FINGERPRINT_SERVICE);
        try {
            Class clz = Class.forName("android.hardware.fingerprint.FingerprintManager");
            Method method = clz.getDeclaredMethod("getEnrolledFingerprints", new Class[]{});
            method.setAccessible(true);
            Object objs = method.invoke(fingerprintManager, null);
            List<Object> list = (List<Object>) objs;
            //本地
            StringBuilder sb = new StringBuilder();
            for (Object obj :list) {
                getObjAttr(sb,obj);
            }

            String new_str = sb.toString();
            editor.putString(KEY_FINGER, new_str);
            editor.commit();
            if (TextUtils.isEmpty(local_str)) {
                setIsFingerDataChange(false);
            } else {
                if (local_str.equals(new_str)) {
                    setIsFingerDataChange(false);
                } else {
                    setIsFingerDataChange(true);
                }
            }

        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        } catch (NoSuchMethodException e) {
            e.printStackTrace();
        } catch (IllegalAccessException e) {
            e.printStackTrace();
        } catch (InvocationTargetException e) {
            e.printStackTrace();
        }
    }

    public static void getObjAttr(StringBuilder sb, Object obj)
    {
        // 获取对象obj的所有属性域
        Field[] fields = obj.getClass().getDeclaredFields();
        for (Field field : fields)
        {
            // 对于每个属性，获取属性名
            String varName = field.getName();
            try
            {
                boolean access = field.isAccessible();
                if(!access) field.setAccessible(true);
                //从obj中获取field变量
                Object o = field.get(obj);
                System.out.println("变量： " + varName + " = " + o);
                if (!varName.equals("CREATOR")){
                    System.out.println("变量： " + varName + " = " + o);
                    sb.append(o);
                    sb.append("-");
                }

                if(!access) field.setAccessible(false);
            }
            catch (Exception ex)
            {
                ex.printStackTrace();
            }
        }
    }

    @TargetApi(Build.VERSION_CODES.M)
    private boolean initCipher(int mode) {
        try {
            keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);
            SecretKey keyspec = (SecretKey)keyStore.getKey(KEY_ALIAS, null);

            if (mode == Cipher.ENCRYPT_MODE) {
                cipher.init(mode, keyspec);

                SharedPreferences.Editor editor = sp.edit();
                editor.putString(PREFERENCES_KEY_IV, Base64.encodeToString(cipher.getIV(), Base64.NO_WRAP));
                editor.commit();
            }
            else {
                byte[] iv = Base64.decode(sp.getString(PREFERENCES_KEY_IV, ""), Base64.NO_WRAP);
                IvParameterSpec ivspec = new IvParameterSpec(iv);
                cipher.init(mode, keyspec, ivspec);
            }

            return true;
        } catch (KeyPermanentlyInvalidatedException e) {
            createNewKey(true); // Retry after clearing entry
        } catch (Exception e) {
        }

        return false;
    }

    @TargetApi(Build.VERSION_CODES.M)
    public boolean createNewKey(boolean forceCreate) {
        try {
            if (forceCreate)
                keyStore.deleteEntry(KEY_ALIAS);

            if (!keyStore.containsAlias(KEY_ALIAS)) {
                generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE);

                generator.init(new KeyGenParameterSpec.Builder (KEY_ALIAS,
                        KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                        .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                        .setUserAuthenticationRequired(true)
                        .build()
                );

                generator.generateKey();
            } else
            return true;
        } catch (Exception e) {
        }

        return false;
    }

    @TargetApi(Build.VERSION_CODES.M)
    private boolean initCryptObject() {
        try {
            cryptoObject = new FingerprintManagerCompat.CryptoObject(cipher);
            return true;
        } catch (Exception ex) {
            Log.d(TAG, "initCryptObject: "+ ex.toString());
        }
        return false;
    }

    @Override
    protected void doIdentify() {
        try {
            mCancellationSignal = new CancellationSignal();
            mFingerprintManagerCompat.authenticate(cryptoObject, 0, mCancellationSignal, new FingerprintManagerCompat.AuthenticationCallback() {
                @Override
                public void onAuthenticationSucceeded(FingerprintManagerCompat.AuthenticationResult result) {
                    super.onAuthenticationSucceeded(result);
                    FingerprintManagerCompat.CryptoObject cryptoObject = result.getCryptoObject();
                    onSucceed();
                }

                @Override
                public void onAuthenticationFailed() {
                    super.onAuthenticationFailed();
                    onNotMatch();
                }

                @Override
                public void onAuthenticationError(int errMsgId, CharSequence errString) {
                    super.onAuthenticationError(errMsgId, errString);
                    onFailed();
                }
            }, null);
        } catch (Throwable e) {
            onCatchException(e);
            onFailed();
        }
    }

    @Override
    protected void doCancelIdentify() {
        try {
            if (mCancellationSignal != null) {
                mCancellationSignal.cancel();
            }
        } catch (Throwable e) {
            onCatchException(e);
        }
    }

    @Override
    protected boolean needToCallDoIdentifyAgainAfterNotMatch() {
        return false;
    }
}