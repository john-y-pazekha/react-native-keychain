package com.oblador.keychain;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.facebook.react.bridge.ReadableMap;
import com.oblador.keychain.KeychainModuleReactDecorator.AccessControl;
import com.oblador.keychain.KeychainModuleReactDecorator.Maps;
import com.oblador.keychain.KeychainModuleReactDecorator.Rules;

public class Defaults {
  public static final String EMPTY_STRING = "";

  @NonNull
  public static String getAliasOrDefault(@Nullable final String service) {
    return service == null ? EMPTY_STRING : service;
  }

  /** Get service value from options. */
  @NonNull
  public static String getServiceOrDefault(@Nullable final ReadableMap options) {
    String service = null;

    if (null != options && options.hasKey(Maps.SERVICE)) {
      service = options.getString(Maps.SERVICE);
    }

    return getAliasOrDefault(service);
  }

  /** Get automatic secret manipulation rules, default: Automatic Upgrade. */
  @Rules
  @NonNull
  public static String getSecurityRulesOrDefault(@Nullable final ReadableMap options) {
    return getSecurityRulesOrDefault(options, Rules.AUTOMATIC_UPGRADE);
  }

  /** Get automatic secret manipulation rules. */
  @Rules
  @NonNull
  public static String getSecurityRulesOrDefault(@Nullable final ReadableMap options,
                                                 @Rules @NonNull final String rule) {
    String rules = null;

    if (null != options && options.hasKey(Maps.RULES)) {
      rules = options.getString(Maps.ACCESS_CONTROL);
    }

    if (null == rules) return rule;

    return rules;
  }

  /** Extract user specified storage from options. */
  @KeychainModuleReactDecorator.KnownCiphers
  @Nullable
  public static String getSpecificStorageOrDefault(@Nullable final ReadableMap options) {
    String storageName = null;

    if (null != options && options.hasKey(Maps.STORAGE)) {
      storageName = options.getString(Maps.STORAGE);
    }

    return storageName;
  }

  /** Get access control value from options or fallback to {@link AccessControl#NONE}. */
  @AccessControl
  @NonNull
  public static String getAccessControlOrDefault(@Nullable final ReadableMap options) {
    return getAccessControlOrDefault(options, AccessControl.NONE);
  }

  /** Get access control value from options or fallback to default. */
  @AccessControl
  @NonNull
  public static String getAccessControlOrDefault(@Nullable final ReadableMap options,
                                                 @AccessControl @NonNull final String fallback) {
    String accessControl = null;

    if (null != options && options.hasKey(Maps.ACCESS_CONTROL)) {
      accessControl = options.getString(Maps.ACCESS_CONTROL);
    }

    if (null == accessControl) return fallback;

    return accessControl;
  }


  /** Get security level from options or fallback {@link SecurityLevel#ANY} value. */
  @NonNull
  public static SecurityLevel getSecurityLevelOrDefault(@Nullable final ReadableMap options) {
    return getSecurityLevelOrDefault(options, SecurityLevel.ANY.name());
  }

  /** Get security level from options or fallback to default value. */
  @NonNull
  public static SecurityLevel getSecurityLevelOrDefault(@Nullable final ReadableMap options,
                                                        @NonNull final String fallback) {
    String minimalSecurityLevel = null;

    if (null != options && options.hasKey(Maps.SECURITY_LEVEL)) {
      minimalSecurityLevel = options.getString(Maps.SECURITY_LEVEL);
    }

    if (null == minimalSecurityLevel) minimalSecurityLevel = fallback;

    return SecurityLevel.valueOf(minimalSecurityLevel);
  }

}
