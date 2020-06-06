package com.oblador.keychain;

import android.os.Build;
import android.os.Looper;
import android.text.TextUtils;
import android.util.Log;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.biometric.BiometricPrompt;
import androidx.biometric.BiometricPrompt.PromptInfo;
import androidx.fragment.app.FragmentActivity;

import com.facebook.react.bridge.AssertionException;
import com.facebook.react.bridge.ReactApplicationContext;
import com.oblador.keychain.PrefsStorage.ResultSet;
import com.oblador.keychain.cipherStorage.CipherStorage;
import com.oblador.keychain.cipherStorage.CipherStorage.DecryptionContext;
import com.oblador.keychain.cipherStorage.CipherStorage.DecryptionResult;
import com.oblador.keychain.cipherStorage.CipherStorage.DecryptionResultHandler;
import com.oblador.keychain.cipherStorage.CipherStorage.EncryptionResult;
import com.oblador.keychain.cipherStorage.CipherStorageBase;
import com.oblador.keychain.cipherStorage.CipherStorageFacebookConceal;
import com.oblador.keychain.cipherStorage.CipherStorageKeystoreAesCbc;
import com.oblador.keychain.cipherStorage.CipherStorageKeystoreRsaEcb;
import com.oblador.keychain.cipherStorage.CipherStorageKeystoreRsaEcb.NonInteractiveHandler;
import com.oblador.keychain.exceptions.CryptoFailedException;
import com.oblador.keychain.exceptions.EmptyParameterException;
import com.oblador.keychain.exceptions.KeyStoreAccessException;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import javax.crypto.Cipher;

import static com.oblador.keychain.KeychainModuleReactDecorator.*;

public class KeychainModule implements BiometricCapabilitiesHelper.CapabilitiesChangeListener {
  //region Constants
  public static final String KEYCHAIN_MODULE = "RNKeychainManager";
  /**
   * Allow this number of milliseconds for the biometric subsystem to start. If exceeded, the biometry is reported
   * as temporary unavailable but the initialization will continue in background. Once complete, the upper layers
   * get a notification that it can be used now.
   */
  public static final int BIOMETRY_STARTUP_TIMEOUT_MILLIS = 300;

  private static final String LOG_TAG = KeychainModule.class.getSimpleName();
  //endregion

  //region Members
  private final ReactApplicationContext reactContext;
  private final BiometricCapabilitiesHelper biometricCapabilities;
  /** Name-to-instance lookup  map. */
  private final Map<String, CipherStorage> cipherStorageMap = new HashMap<>();
  /** Shared preferences storage. */
  private final PrefsStorage prefsStorage;
  //endregion

  //region Initialization

  /** Default constructor. */
  public KeychainModule(@NonNull final ReactApplicationContext reactContext, @NonNull final BiometricCapabilitiesHelper biometricCapabilitiesHelper) {
    this.reactContext = reactContext;
    this.biometricCapabilities = biometricCapabilitiesHelper;
    prefsStorage = new PrefsStorage(reactContext);

    addCipherStorageToMap(new CipherStorageFacebookConceal(reactContext));
    addCipherStorageToMap(new CipherStorageKeystoreAesCbc());

    // we have a references to newer api that will fail load of app classes in old androids OS
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
      addCipherStorageToMap(new CipherStorageKeystoreRsaEcb());
    }

    biometricCapabilitiesHelper.setCapabilitiesChangeListener(this);
  }

  @Override
  public void onBiometricCapabilitiesChanged(@NonNull final BiometricCapabilitiesHelper helper) {
    // Do nothing (yet)
  }

  /** Allow initialization in chain. */
  public static KeychainModule withWarming(@NonNull final ReactApplicationContext reactContext) {
    final KeychainModule instance = new KeychainModule(reactContext, new BiometricCapabilitiesHelper(reactContext));

    // force initialization of the crypto api in background thread
    final Thread warmingUp = new Thread(instance::internalWarmingBestCipher, "keychain-warming-up");
    warmingUp.setDaemon(true);
    warmingUp.start();

    return instance;
  }

  /** cipher (crypto api) warming up logic. force java load classes and intializations. */
  private void internalWarmingBestCipher() {
    try {
      final long startTime = System.nanoTime();

      Log.v(KEYCHAIN_MODULE, "warming up started at " + startTime);
      final CipherStorageBase best = (CipherStorageBase) getCipherStorageForCurrentAPILevel();
      final Cipher instance = best.getCachedInstance();
      final boolean isSecure = best.supportsSecureHardware();
      final SecurityLevel requiredLevel = isSecure ? SecurityLevel.SECURE_HARDWARE : SecurityLevel.SECURE_SOFTWARE;
      best.generateKeyAndStoreUnderAlias("warmingUp", requiredLevel);
      best.getKeyStoreAndLoad();

      Log.v(KEYCHAIN_MODULE, "warming up takes: " +
        TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startTime) +
        " ms");
    } catch (Throwable ex) {
      Log.e(KEYCHAIN_MODULE, "warming up failed!", ex);
    }
  }

  /** Start with biometry warm-up. */
  public static KeychainModule withBiometryProbing(@NonNull final ReactApplicationContext reactContext) {
    final InhibitableBiometricCapabilitiesHelper helper = new InhibitableBiometricCapabilitiesHelper(reactContext);
    new BiometryKickStarter(helper).tryStartBiometry(BIOMETRY_STARTUP_TIMEOUT_MILLIS);
    return new KeychainModule(reactContext, helper);
  }
  //endregion


  //region React Methods
  public String setGenericPassword(@NonNull final String alias,
                                   @NonNull final String username,
                                   @NonNull final String password,
                                   @NonNull final SecurityLevel level,
                                   @NonNull final String cipherName,
                                   boolean useBiometry) throws CryptoFailedException, EmptyParameterException
  {
    final CipherStorage storage = getSelectedStorage(useBiometry, cipherName);
    return setGenericPassword(alias, username, password, level, storage);
  }

  private String setGenericPassword(@NonNull final String alias,
                                    @NonNull final String username,
                                    @NonNull final String password,
                                    @NonNull SecurityLevel level,
                                    @NonNull CipherStorage storage) throws EmptyParameterException, CryptoFailedException
  {
      throwIfEmptyLoginPassword(username, password);

    throwIfInsufficientLevel(storage, level);

      final EncryptionResult result = storage.encrypt(alias, username, password, level);
      prefsStorage.storeEncryptedEntry(alias, result);
    return storage.getCipherStorageName();
  }

  /** Get Cipher storage instance based on user provided options. */
  @NonNull
  private CipherStorage getSelectedStorage(final boolean useBiometry, @Nullable final String cipherName)
    throws CryptoFailedException {
    CipherStorage result = null;

    if (null != cipherName) {
      result = getCipherStorageByName(cipherName);
    }

    // attempt to access none existing storage will force fallback logic.
    if (null == result) {
      result = getCipherStorageForCurrentAPILevel(useBiometry);
    }

    return result;
  }

  public DecryptCredentialsResult getGenericPassword(@NonNull final String alias,
                                                     @NonNull @Rules final String rules,
                                                     @NonNull final PromptInfo promptInfo,
                                                     final boolean useBiometry) throws CryptoFailedException, KeyStoreAccessException
  {
      final ResultSet resultSet = prefsStorage.getEncryptedEntry(alias);

      if (resultSet == null) {
        Log.e(KEYCHAIN_MODULE, "No entry found for service: " + alias);
      return null;
      }

    final CipherStorage current = getCipherStorageForCurrentAPILevel(useBiometry);
      final DecryptionResult decryptionResult = decryptCredentials(alias, current, resultSet, rules, promptInfo);

    return new DecryptCredentialsResult(decryptionResult.username, decryptionResult.password, current.getCipherStorageName());
  }

  public void do__resetGenericPassword(@NonNull final String alias) throws KeyStoreAccessException {
      // First we clean up the cipher storage (using the cipher storage that was used to store the entry)
      final ResultSet resultSet = prefsStorage.getEncryptedEntry(alias);

      if (resultSet != null) {
        final CipherStorage cipherStorage = getCipherStorageByName(resultSet.cipherStorageName);

        if (cipherStorage != null) {
          cipherStorage.removeKey(alias);
        }
      }
      // And then we remove the entry in the shared preferences
      prefsStorage.removeEntry(alias);
  }

  public String hasInternetCredentialsForServer(@NonNull final String alias) {
    final String res;
    final ResultSet resultSet = prefsStorage.getEncryptedEntry(alias);

    if (resultSet == null) {
      Log.e(KEYCHAIN_MODULE, "No entry found for service: " + alias);
      res = null;
    } else {
      res = resultSet.cipherStorageName;
    }
    return res;
  }

  public String getSupportedBiometryType() {
    return biometricCapabilities.getSupportedBiometryType();
  }
  //endregion

  //region Helpers

  //endregion

  //region Implementation

  /** Is provided access control string matching biometry use request? */
  public static boolean getUseBiometry(@AccessControl @Nullable final String accessControl) {
    return AccessControl.BIOMETRY_ANY.equals(accessControl)
      || AccessControl.BIOMETRY_CURRENT_SET.equals(accessControl)
      || AccessControl.BIOMETRY_ANY_OR_DEVICE_PASSCODE.equals(accessControl)
      || AccessControl.BIOMETRY_CURRENT_SET_OR_DEVICE_PASSCODE.equals(accessControl);
  }

  private void addCipherStorageToMap(@NonNull final CipherStorage cipherStorage) {
    cipherStorageMap.put(cipherStorage.getCipherStorageName(), cipherStorage);
  }

  /**
   * Extract credentials from current storage. In case if current storage is not matching
   * results set then executed migration.
   */
  @NonNull
  private DecryptionResult decryptCredentials(@NonNull final String alias,
                                              @NonNull final CipherStorage current,
                                              @NonNull final ResultSet resultSet,
                                              @Rules @NonNull final String rules,
                                              @NonNull final PromptInfo promptInfo)
    throws CryptoFailedException, KeyStoreAccessException {
    final String storageName = resultSet.cipherStorageName;

    // The encrypted data is encrypted using the current CipherStorage, so we just decrypt and return
    if (storageName.equals(current.getCipherStorageName())) {
      return decryptToResult(alias, current, resultSet, promptInfo);
    }

    // The encrypted data is encrypted using an older CipherStorage, so we need to decrypt the data first,
    // then encrypt it using the current CipherStorage, then store it again and return
    final CipherStorage oldStorage = getCipherStorageByName(storageName);
    if (null == oldStorage) {
      throw new KeyStoreAccessException("Wrong cipher storage name '" + storageName + "' or cipher not available");
    }

    // decrypt using the older cipher storage
    final DecryptionResult decryptionResult = decryptToResult(alias, oldStorage, resultSet, promptInfo);

    if (Rules.AUTOMATIC_UPGRADE.equals(rules)) {
      try {
        // encrypt using the current cipher storage
        migrateCipherStorage(alias, current, oldStorage, decryptionResult);
      } catch (CryptoFailedException e) {
        Log.w(KEYCHAIN_MODULE, "Migrating to a less safe storage is not allowed. Keeping the old one");
      }
    }

    return decryptionResult;
  }

  /** Try to decrypt with provided storage. */
  @NonNull
  private DecryptionResult decryptToResult(@NonNull final String alias,
                                           @NonNull final CipherStorage storage,
                                           @NonNull final ResultSet resultSet,
                                           @NonNull final PromptInfo promptInfo)
    throws CryptoFailedException {
    final DecryptionResultHandler handler = getInteractiveHandler(storage, promptInfo);
    storage.decrypt(handler, alias, resultSet.username, resultSet.password, SecurityLevel.ANY);

    CryptoFailedException.reThrowOnError(handler.getError());

    if (null == handler.getResult()) {
      throw new CryptoFailedException("No decryption results and no error. Something deeply wrong!");
    }

    return handler.getResult();
  }

  /** Get instance of handler that resolves access to the keystore on system request. */
  @NonNull
  protected DecryptionResultHandler getInteractiveHandler(@NonNull final CipherStorage current, @NonNull final PromptInfo promptInfo) {
    if (current.isBiometrySupported() /*&& isFingerprintAuthAvailable()*/) {
      return new InteractiveBiometric(current, promptInfo);
    }

    return new NonInteractiveHandler();
  }

  /** Remove key from old storage and add it to the new storage. */
  /* package */ void migrateCipherStorage(@NonNull final String service,
                                          @NonNull final CipherStorage newCipherStorage,
                                          @NonNull final CipherStorage oldCipherStorage,
                                          @NonNull final DecryptionResult decryptionResult)
    throws KeyStoreAccessException, CryptoFailedException {

    // don't allow to degrade security level when transferring, the new
    // storage should be as safe as the old one.
    final EncryptionResult encryptionResult = newCipherStorage.encrypt(
      service, decryptionResult.username, decryptionResult.password,
      decryptionResult.getSecurityLevel());

    // store the encryption result
    prefsStorage.storeEncryptedEntry(service, encryptionResult);

    // clean up the old cipher storage
    oldCipherStorage.removeKey(service);
  }

  /**
   * The "Current" CipherStorage is the cipherStorage with the highest API level that is
   * lower than or equal to the current API level
   */
  @NonNull
  /* package */ CipherStorage getCipherStorageForCurrentAPILevel() throws CryptoFailedException {
    return getCipherStorageForCurrentAPILevel(true);
  }

  /**
   * The "Current" CipherStorage is the cipherStorage with the highest API level that is
   * lower than or equal to the current API level. Parameter allow to reduce level.
   */
  @NonNull
  /* package */ CipherStorage getCipherStorageForCurrentAPILevel(final boolean useBiometry)
    throws CryptoFailedException {
    final int currentApiLevel = Build.VERSION.SDK_INT;
    final boolean isBiometry = biometricCapabilities.isAnyBiometryAvailable() && useBiometry;
    CipherStorage foundCipher = null;

    for (CipherStorage variant : cipherStorageMap.values()) {
      Log.d(KEYCHAIN_MODULE, "Probe cipher storage: " + variant.getClass().getSimpleName());

      // Is the cipherStorage supported on the current API level?
      final int minApiLevel = variant.getMinSupportedApiLevel();
      final int capabilityLevel = variant.getCapabilityLevel();
      final boolean isSupportedApi = (minApiLevel <= currentApiLevel);

      // API not supported
      if (!isSupportedApi) continue;

      // Is the API level better than the one we previously selected (if any)?
      if (foundCipher != null && capabilityLevel < foundCipher.getCapabilityLevel()) continue;

      // if biometric supported but not configured properly than skip
      if (variant.isBiometrySupported() && !isBiometry) continue;

      // remember storage with the best capabilities
      foundCipher = variant;
    }

    if (foundCipher == null) {
      throw new CryptoFailedException("Unsupported Android SDK " + Build.VERSION.SDK_INT);
    }

    Log.d(KEYCHAIN_MODULE, "Selected storage: " + foundCipher.getClass().getSimpleName());

    return foundCipher;
  }

  /** Throw exception in case of empty credentials providing. */
  public static void throwIfEmptyLoginPassword(@Nullable final String username,
                                               @Nullable final String password)
    throws EmptyParameterException {
    if (TextUtils.isEmpty(username) || TextUtils.isEmpty(password)) {
      throw new EmptyParameterException("you passed empty or null username/password");
    }
  }

  /** Throw exception if required security level does not match storage provided security level. */
  public static void throwIfInsufficientLevel(@NonNull final CipherStorage storage,
                                              @NonNull final SecurityLevel level)
    throws CryptoFailedException {
    if (storage.securityLevel().satisfiesSafetyThreshold(level)) {
      return;
    }

    throw new CryptoFailedException(
      String.format(
        "Cipher Storage is too weak. Required security level is: %s, but only %s is provided",
        level.name(),
        storage.securityLevel().name()));
  }

  /** Extract cipher by it unique name. {@link CipherStorage#getCipherStorageName()}. */
  @Nullable
  /* package */ CipherStorage getCipherStorageByName(@KnownCiphers @NonNull final String knownName) {
    return cipherStorageMap.get(knownName);
  }

  /** True - if fingerprint hardware available and configured, otherwise false. */
  @Deprecated  // Used only in tests! // TODO rectify test so they target BiometricCapabilitiesHelper instead of this class
  /* package */ boolean isFingerprintAuthAvailable() {
    return biometricCapabilities.isFingerprintAuthAvailable();
  }

  /** Is secured hardware a part of current storage or not. */
  /* package */ boolean isSecureHardwareAvailable() {
    try {
      return getCipherStorageForCurrentAPILevel().supportsSecureHardware();
    } catch (CryptoFailedException e) {
      return false;
    }
  }

  /** Resolve storage to security level it provides. */
  @NonNull
  public SecurityLevel getSecurityLevel(final boolean useBiometry) {
    try {
      final CipherStorage storage = getCipherStorageForCurrentAPILevel(useBiometry);

      if (!storage.securityLevel().satisfiesSafetyThreshold(SecurityLevel.SECURE_SOFTWARE)) {
        return SecurityLevel.ANY;
      }

      if (storage.supportsSecureHardware()) {
        return SecurityLevel.SECURE_HARDWARE;
      }

      return SecurityLevel.SECURE_SOFTWARE;
    } catch (CryptoFailedException e) {
      Log.w(KEYCHAIN_MODULE, "Security Level Exception: " + e.getMessage(), e);

      return SecurityLevel.ANY;
    }
  }
  //endregion

  //region Nested declarations

  /** Interactive user questioning for biometric data providing. */
  private class InteractiveBiometric extends BiometricPrompt.AuthenticationCallback implements DecryptionResultHandler {
    private DecryptionResult result;
    private Throwable error;
    private final CipherStorageBase storage;
    private final Executor executor = Executors.newSingleThreadExecutor();
    private DecryptionContext context;
    private PromptInfo promptInfo;

    private InteractiveBiometric(@NonNull final CipherStorage storage, @NonNull final PromptInfo promptInfo) {
      this.storage = (CipherStorageBase) storage;
      this.promptInfo = promptInfo;
    }

    @Override
    public void askAccessPermissions(@NonNull final DecryptionContext context) {
      this.context = context;

      if (!DeviceAvailability.isPermissionsGranted(reactContext)) {
        final CryptoFailedException failure = new CryptoFailedException(
          "Could not start fingerprint Authentication. No permissions granted.");

        onDecrypt(null, failure);
      } else {
        startAuthentication();
      }
    }

    @Override
    public void onDecrypt(@Nullable final DecryptionResult decryptionResult, @Nullable final Throwable error) {
      this.result = decryptionResult;
      this.error = error;

      synchronized (this) {
        notifyAll();
      }
    }

    @Nullable
    @Override
    public DecryptionResult getResult() {
      return result;
    }

    @Nullable
    @Override
    public Throwable getError() {
      return error;
    }

    /** Called when an unrecoverable error has been encountered and the operation is complete. */
    @Override
    public void onAuthenticationError(final int errorCode, @NonNull final CharSequence errString) {
      final CryptoFailedException error = new CryptoFailedException("code: " + errorCode + ", msg: " + errString);

      onDecrypt(null, error);
    }

    /** Called when a biometric is recognized. */
    @Override
    public void onAuthenticationSucceeded(@NonNull final BiometricPrompt.AuthenticationResult result) {
      try {
        if (null == context) throw new NullPointerException("Decrypt context is not assigned yet.");

        final DecryptionResult decrypted = new DecryptionResult(
          storage.decryptBytes(context.key, context.username),
          storage.decryptBytes(context.key, context.password)
        );

        onDecrypt(decrypted, null);
      } catch (Throwable fail) {
        onDecrypt(null, fail);
      }
    }

    /** trigger interactive authentication. */
    public void startAuthentication() {
      final FragmentActivity activity = (FragmentActivity) reactContext.getCurrentActivity();
      if (null == activity) throw new NullPointerException("Not assigned current activity");

      // code can be executed only from MAIN thread
      if (Thread.currentThread() != Looper.getMainLooper().getThread()) {
        activity.runOnUiThread(this::startAuthentication);
        waitResult();
        return;
      }

      final BiometricPrompt prompt = new BiometricPrompt(activity, executor, this);

      prompt.authenticate(this.promptInfo);
    }

    /** Block current NON-main thread and wait for user authentication results. */
    @Override
    public void waitResult() {
      if (Thread.currentThread() == Looper.getMainLooper().getThread())
        throw new AssertionException("method should not be executed from MAIN thread");

      Log.i(KEYCHAIN_MODULE, "blocking thread. waiting for done UI operation.");

      try {
        synchronized (this) {
          wait();
        }
      } catch (InterruptedException ignored) {
        /* shutdown sequence */
      }

      Log.i(KEYCHAIN_MODULE, "unblocking thread.");
    }
  }
  //endregion

  public static class DecryptCredentialsResult {
    public final String username;
    public final String password;
    public final String cipherStorageName;

    public DecryptCredentialsResult(String username, String password, String cipherStorageName) {
      this.username = username;
      this.password = password;
      this.cipherStorageName = cipherStorageName;
    }
  }
}
