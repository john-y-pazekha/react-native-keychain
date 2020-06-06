package com.oblador.keychain;

import android.util.Log;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.annotation.StringDef;
import androidx.biometric.BiometricPrompt;

import com.facebook.react.bridge.Arguments;
import com.facebook.react.bridge.Promise;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.ReadableMap;
import com.facebook.react.bridge.WritableMap;
import com.oblador.keychain.exceptions.CryptoFailedException;
import com.oblador.keychain.exceptions.EmptyParameterException;
import com.oblador.keychain.exceptions.KeyStoreAccessException;

import java.util.HashMap;
import java.util.Map;

import static com.oblador.keychain.Defaults.*;
import static com.oblador.keychain.KeychainModule.*;

@SuppressWarnings({"unused", "WeakerAccess", "SameParameterValue"})
public class KeychainModuleReactDecorator extends ReactContextBaseJavaModule {
  //region Constants
  public static final String KEYCHAIN_MODULE = "RNKeychainManager";

  @StringDef({AccessControl.NONE
    , AccessControl.USER_PRESENCE
    , AccessControl.BIOMETRY_ANY
    , AccessControl.BIOMETRY_CURRENT_SET
    , AccessControl.DEVICE_PASSCODE
    , AccessControl.APPLICATION_PASSWORD
    , AccessControl.BIOMETRY_ANY_OR_DEVICE_PASSCODE
    , AccessControl.BIOMETRY_CURRENT_SET_OR_DEVICE_PASSCODE})
  @interface AccessControl {
    String NONE = "None";
    String USER_PRESENCE = "UserPresence";
    String BIOMETRY_ANY = "BiometryAny";
    String BIOMETRY_CURRENT_SET = "BiometryCurrentSet";
    String DEVICE_PASSCODE = "DevicePasscode";
    String APPLICATION_PASSWORD = "ApplicationPassword";
    String BIOMETRY_ANY_OR_DEVICE_PASSCODE = "BiometryAnyOrDevicePasscode";
    String BIOMETRY_CURRENT_SET_OR_DEVICE_PASSCODE = "BiometryCurrentSetOrDevicePasscode";
  }

  @interface AuthPromptOptions {
    String TITLE = "title";
    String SUBTITLE = "subtitle";
    String DESCRIPTION = "description";
    String CANCEL = "cancel";
  }

  /** Options mapping keys. */
  @interface Maps {
    String ACCESS_CONTROL = "accessControl";
    String ACCESS_GROUP = "accessGroup";
    String ACCESSIBLE = "accessible";
    String AUTH_PROMPT = "authenticationPrompt";
    String AUTH_TYPE = "authenticationType";
    String SERVICE = "service";
    String SECURITY_LEVEL = "securityLevel";
    String RULES = "rules";

    String USERNAME = "username";
    String PASSWORD = "password";
    String STORAGE = "storage";
  }

  /** Known error codes. */
  @interface Errors {
    String E_EMPTY_PARAMETERS = "E_EMPTY_PARAMETERS";
    String E_CRYPTO_FAILED = "E_CRYPTO_FAILED";
    String E_KEYSTORE_ACCESS_ERROR = "E_KEYSTORE_ACCESS_ERROR";
    String E_SUPPORTED_BIOMETRY_ERROR = "E_SUPPORTED_BIOMETRY_ERROR";
    /** Raised for unexpected errors. */
    String E_UNKNOWN_ERROR = "E_UNKNOWN_ERROR";
  }

  /** Supported ciphers. */
  @StringDef({KnownCiphers.FB, KnownCiphers.AES, KnownCiphers.RSA})
  public @interface KnownCiphers {
    /** Facebook conceal compatibility lib in use. */
    String FB = "FacebookConceal";
    /** AES encryption. */
    String AES = "KeystoreAESCBC";
    /** Biometric + RSA. */
    String RSA = "KeystoreRSAECB";
  }

  /** Secret manipulation rules. */
  @StringDef({Rules.AUTOMATIC_UPGRADE, Rules.NONE})
  @interface Rules {
    String NONE = "none";
    String AUTOMATIC_UPGRADE = "automaticUpgradeToMoreSecuredStorage";
  }
  //endregion

  private KeychainModule impl;

  public KeychainModuleReactDecorator(@NonNull final ReactApplicationContext reactContext, @NonNull final KeychainModule keychainModule) {
    super(reactContext);
    impl = keychainModule;
  }

  //region Overrides

  /** {@inheritDoc} */
  @Override
  @NonNull
  public String getName() {
    return KEYCHAIN_MODULE;
  }

  /** {@inheritDoc} */
  @NonNull
  @Override
  public Map<String, Object> getConstants() {
    final Map<String, Object> constants = new HashMap<>();

    constants.put(SecurityLevel.ANY.jsName(), SecurityLevel.ANY.name());
    constants.put(SecurityLevel.SECURE_SOFTWARE.jsName(), SecurityLevel.SECURE_SOFTWARE.name());
    constants.put(SecurityLevel.SECURE_HARDWARE.jsName(), SecurityLevel.SECURE_HARDWARE.name());

    return constants;
  }
  //endregion


  //region React Methods
  @ReactMethod
  public void setGenericPasswordForOptions(@Nullable final ReadableMap options,
                                           @NonNull final String username,
                                           @NonNull final String password,
                                           @NonNull final Promise promise) {
    final String service = getServiceOrDefault(options);
    setGenericPassword(service, username, password, options, promise);
  }

  @ReactMethod
  public void setInternetCredentialsForServer(@NonNull final String server,
                                              @NonNull final String username,
                                              @NonNull final String password,
                                              @Nullable final ReadableMap options,
                                              @NonNull final Promise promise) {
    setGenericPassword(server, username, password, options, promise);
  }

  @ReactMethod
  public void getInternetCredentialsForServer(@NonNull final String server,
                                              @Nullable final ReadableMap options,
                                              @NonNull final Promise promise) {
    getGenericPassword(server, options, promise);
  }

  @ReactMethod
  public void resetInternetCredentialsForServer(@NonNull final String server,
                                                @NonNull final Promise promise) {
    resetGenericPassword(server, promise);
  }

  protected void setGenericPassword(@NonNull final String alias,
                                    @NonNull final String username,
                                    @NonNull final String password,
                                    @Nullable final ReadableMap options,
                                    @NonNull final Promise promise) {
    try {
      final SecurityLevel level = getSecurityLevelOrDefault(options);
      final String accessControl = getAccessControlOrDefault(options);
      final boolean useBiometry = getUseBiometry(accessControl);
      final String cipherName = getSpecificStorageOrDefault(options);

      String result = impl.setGenericPassword(alias, username, password, level, cipherName, useBiometry);

      final WritableMap results = Arguments.createMap();
      results.putString(Maps.SERVICE, alias);
      results.putString(Maps.STORAGE, result);

      promise.resolve(results);
    } catch (EmptyParameterException e) {
      Log.e(KEYCHAIN_MODULE, e.getMessage(), e);

      promise.reject(Errors.E_EMPTY_PARAMETERS, e);
    } catch (CryptoFailedException e) {
      Log.e(KEYCHAIN_MODULE, e.getMessage(), e);

      promise.reject(Errors.E_CRYPTO_FAILED, e);
    } catch (Throwable fail) {
      Log.e(KEYCHAIN_MODULE, fail.getMessage(), fail);

      promise.reject(Errors.E_UNKNOWN_ERROR, fail);
    }
  }

  @ReactMethod
  public void getGenericPasswordForOptions(@Nullable final ReadableMap options,
                                           @NonNull final Promise promise) {
    final String service = getServiceOrDefault(options);
    getGenericPassword(service, options, promise);
  }

  // TODO Change signature: make options @NonNull. Reason: as options map now contains AUTH_PROMPT which is always required, the options parameter cannot be @Nullable anymore.
  protected void getGenericPassword(@NonNull final String alias,
                                    @Nullable final ReadableMap options,
                                    @NonNull final Promise promise) {
    try {
      // get the best storage
      final String accessControl = getAccessControlOrDefault(options);
      final boolean useBiometry = getUseBiometry(accessControl);
      final String rules = getSecurityRulesOrDefault(options);

      final BiometricPrompt.PromptInfo promptInfo = getPromptInfo(options);

      final DecryptCredentialsResult result = impl.getGenericPassword(alias, rules, promptInfo, useBiometry);

      if (result == null) {
        promise.resolve(false);
      } else {
        final WritableMap credentials = Arguments.createMap();
        credentials.putString(Maps.SERVICE, alias);
        credentials.putString(Maps.USERNAME, result.username);
        credentials.putString(Maps.PASSWORD, result.password);
        credentials.putString(Maps.STORAGE,  result.cipherStorageName);

        promise.resolve(credentials);
      }
    } catch (KeyStoreAccessException e) {
      Log.e(KEYCHAIN_MODULE, e.getMessage());

      promise.reject(Errors.E_KEYSTORE_ACCESS_ERROR, e);
    } catch (CryptoFailedException e) {
      Log.e(KEYCHAIN_MODULE, e.getMessage());

      promise.reject(Errors.E_CRYPTO_FAILED, e);
    } catch (Throwable fail) {
      Log.e(KEYCHAIN_MODULE, fail.getMessage(), fail);

      promise.reject(Errors.E_UNKNOWN_ERROR, fail);
    }
  }

  /** Extract user specified prompt info from options. */
  @NonNull
  private static BiometricPrompt.PromptInfo getPromptInfo(@Nullable final ReadableMap options) {
    final ReadableMap promptInfoOptionsMap = (options != null && options.hasKey(Maps.AUTH_PROMPT)) ? options.getMap(Maps.AUTH_PROMPT) : null;

    final BiometricPrompt.PromptInfo.Builder promptInfoBuilder = new BiometricPrompt.PromptInfo.Builder();
    if (null != promptInfoOptionsMap && promptInfoOptionsMap.hasKey(AuthPromptOptions.TITLE)) {
      String promptInfoTitle = promptInfoOptionsMap.getString(AuthPromptOptions.TITLE);
      promptInfoBuilder.setTitle(promptInfoTitle);
    }
    if (null != promptInfoOptionsMap && promptInfoOptionsMap.hasKey(AuthPromptOptions.SUBTITLE)) {
      String promptInfoSubtitle = promptInfoOptionsMap.getString(AuthPromptOptions.SUBTITLE);
      promptInfoBuilder.setSubtitle(promptInfoSubtitle);
    }
    if (null != promptInfoOptionsMap && promptInfoOptionsMap.hasKey(AuthPromptOptions.DESCRIPTION)) {
      String promptInfoDescription = promptInfoOptionsMap.getString(AuthPromptOptions.DESCRIPTION);
      promptInfoBuilder.setDescription(promptInfoDescription);
    }
    if (null != promptInfoOptionsMap && promptInfoOptionsMap.hasKey(AuthPromptOptions.CANCEL)) {
      String promptInfoNegativeButton = promptInfoOptionsMap.getString(AuthPromptOptions.CANCEL);
      promptInfoBuilder.setNegativeButtonText(promptInfoNegativeButton);
    }
    final BiometricPrompt.PromptInfo promptInfo = promptInfoBuilder.build();

    return promptInfo;
  }

  @ReactMethod
  public void resetGenericPasswordForOptions(@Nullable final ReadableMap options,
                                             @NonNull final Promise promise) {
    final String service = getServiceOrDefault(options);
    resetGenericPassword(service, promise);
  }

  @ReactMethod
  public void hasInternetCredentialsForServer(@NonNull final String server,
                                              @NonNull final Promise promise) {
    final String alias = getAliasOrDefault(server);

    final String cipherStorageName = impl.hasInternetCredentialsForServer(alias);

    if (cipherStorageName == null) {
      promise.resolve(false);
    } else {
      final WritableMap results = Arguments.createMap();
      results.putString(Maps.SERVICE, alias);
      results.putString(Maps.STORAGE, cipherStorageName);

      promise.resolve(results);
    }
  }

  @ReactMethod
  public void getSupportedBiometryType(@NonNull final Promise promise) {
    try {
      final String reply = impl.getSupportedBiometryType();

      promise.resolve(reply);
    } catch (Exception e) {
      Log.e(KEYCHAIN_MODULE, e.getMessage(), e);

      promise.reject(Errors.E_SUPPORTED_BIOMETRY_ERROR, e);
    } catch (Throwable fail) {
      Log.e(KEYCHAIN_MODULE, fail.getMessage(), fail);

      promise.reject(Errors.E_UNKNOWN_ERROR, fail);
    }
  }

  @ReactMethod
  public void getSecurityLevel(@Nullable final ReadableMap options,
                               @NonNull final Promise promise) {
    // DONE (olku): if forced biometry than we should return security level = HARDWARE if it supported
    final String accessControl = getAccessControlOrDefault(options);
    final boolean useBiometry = getUseBiometry(accessControl);

    promise.resolve(impl.getSecurityLevel(useBiometry).name());
  }

  protected void resetGenericPassword(@NonNull final String alias,
                                      @NonNull final Promise promise) {
    try {
      impl.do__resetGenericPassword(alias);

      promise.resolve(true);
    } catch (KeyStoreAccessException e) {
      Log.e(KEYCHAIN_MODULE, e.getMessage());

      promise.reject(Errors.E_KEYSTORE_ACCESS_ERROR, e);
    } catch (Throwable fail) {
      Log.e(KEYCHAIN_MODULE, fail.getMessage(), fail);

      promise.reject(Errors.E_UNKNOWN_ERROR, fail);
    }
  }
}
