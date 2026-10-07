import 'package:flutter/material.dart';

/// Flutter adaptation of the shipped NEOTH GUI semantic tokens.
/// This is presentation-only; controller and bridge authority stay unchanged.
abstract final class CompanionTheme {
  static const _ink900 = Color(0xff0d0d0d);
  static const _surface1 = Color(0xff121212);
  static const _surface2 = Color(0xff161616);
  static const _textPrimary = Color(0xffffffff);
  static const _textSecondary = Color(0xffaaaaaa);
  static const _borderDefault = Color(0x29ffffff);
  static const _memory = Color(0xff00ff80);
  static const _audit = Color(0xff05d5ff);
  static const _consent = Color(0xffff2a6d);
  static const _warning = Color(0xffffb627);

  static ThemeData neothDark() {
    final colors = const ColorScheme.dark().copyWith(
      primary: _memory,
      onPrimary: _ink900,
      secondary: _audit,
      onSecondary: _ink900,
      error: _consent,
      onError: _ink900,
      surface: _surface1,
      onSurface: _textPrimary,
      surfaceContainerHighest: _surface2,
      onSurfaceVariant: _textSecondary,
      outline: _borderDefault,
    );
    return ThemeData(
      useMaterial3: true,
      colorScheme: colors,
      scaffoldBackgroundColor: _ink900,
      appBarTheme: const AppBarTheme(backgroundColor: _ink900, foregroundColor: _textPrimary),
      dividerColor: _borderDefault,
      inputDecorationTheme: const InputDecorationTheme(border: OutlineInputBorder()),
    );
  }

  static Color outcomeColor(ColorScheme colors, String outcome) => switch (outcome) {
        'accepted' => colors.primary,
        'denied' => colors.error,
        'busy' || 'unavailable' || 'timeout' || 'indeterminate' => _warning,
        _ => colors.onSurfaceVariant,
      };
}
