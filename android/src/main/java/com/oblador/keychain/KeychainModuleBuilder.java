package com.oblador.keychain;

import com.facebook.react.bridge.ReactApplicationContext;

public class KeychainModuleBuilder {
  public static final boolean DEFAULT_USE_WARM_UP = true;
  public static final boolean DEFAULT_USE_PROBING = false;

  private ReactApplicationContext reactContext;
  private boolean useWarmUp = DEFAULT_USE_WARM_UP;
  private boolean useProbing = DEFAULT_USE_PROBING;

  public KeychainModuleBuilder withReactContext(ReactApplicationContext reactContext) {
    this.reactContext = reactContext;
    return this;
  }

  public KeychainModuleBuilder usingWarmUp() {
    useWarmUp = true;
    return this;
  }

  public KeychainModuleBuilder usingProbingInsteadOfWarmUp() {
    useWarmUp = false;
    useProbing = true;
    return this;
  }

  public KeychainModuleBuilder withoutWarmUp() {
    useWarmUp = false;
    return this;
  }

  public KeychainModule build() {
    validate();
    if (useWarmUp) {
      return KeychainModule.withWarming(reactContext);
    } else {
      if (useProbing) {
        return KeychainModule.withBiometryProbing(reactContext);
      } else {
        return new KeychainModule(reactContext, new BiometricCapabilitiesHelper(reactContext));
      }
    }
  }

  private void validate() {
    if (reactContext == null) {
      throw new Error("React Context was not provided");
    }
  }
}
