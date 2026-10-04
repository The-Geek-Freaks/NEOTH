import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import 'companion_controller.dart';
import 'models.dart';
import 'native_bridge.dart';
import 'secure_store.dart';

void main() {
  WidgetsFlutterBinding.ensureInitialized();
  final controller = CompanionController(
    store: SecureCompanionStore(),
    bridgeFactory: FfiNativeBridge.fromProtectedSeed,
  );
  runApp(NeothCompanionApp(controller: controller));
}

class NeothCompanionApp extends StatefulWidget {
  const NeothCompanionApp({super.key, required this.controller});
  final CompanionController controller;

  @override
  State<NeothCompanionApp> createState() => _NeothCompanionAppState();
}

class _NeothCompanionAppState extends State<NeothCompanionApp> with WidgetsBindingObserver {
  static const _links = MethodChannel('neoth_companion/deep_link');
  String? _pendingInvite;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    _links.setMethodCallHandler((call) async {
      if (call.method == 'pairLink' && call.arguments is String && mounted) {
        setState(() => _pendingInvite = call.arguments as String);
      }
    });
    unawaited(_start());
  }

  Future<void> _start() async {
    final initial = await _links.invokeMethod<String>('initialPairLink');
    if (mounted && initial != null) setState(() => _pendingInvite = initial);
    await widget.controller.prepareBridge();
    await widget.controller.restore();
  }

  @override
  void dispose() {
    // The channel is process-global. Drop this State's handler before its
    // controllers so a late platform deep link cannot target a dead widget.
    unawaited(_links.setMethodCallHandler(null));
    WidgetsBinding.instance.removeObserver(this);
    widget.controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'NEOTH Companion',
      theme: ThemeData(colorSchemeSeed: const Color(0xff6b5cff), brightness: Brightness.dark, useMaterial3: true),
      home: CompanionHome(controller: widget.controller, initialInvite: _pendingInvite),
    );
  }
}

class CompanionHome extends StatefulWidget {
  const CompanionHome({super.key, required this.controller, this.initialInvite});
  final CompanionController controller;
  final String? initialInvite;

  @override
  State<CompanionHome> createState() => _CompanionHomeState();
}

class _CompanionHomeState extends State<CompanionHome> {
  late final TextEditingController _invite = TextEditingController(text: widget.initialInvite ?? '');
  final _label = TextEditingController(text: 'My phone');

  @override
  void didUpdateWidget(covariant CompanionHome oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (widget.initialInvite != null && widget.initialInvite != oldWidget.initialInvite) {
      _invite.text = widget.initialInvite!;
    }
  }

  @override
  void dispose() {
    _invite.dispose();
    _label.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return AnimatedBuilder(
      animation: widget.controller,
      builder: (context, _) {
        final state = widget.controller.state;
        final paired = state != CompanionViewState.unpaired;
        return Scaffold(
          appBar: AppBar(title: const Text('NEOTH Companion')),
          body: SafeArea(
            child: ListView(
              padding: const EdgeInsets.all(20),
              children: [
                Text(_title(state), style: Theme.of(context).textTheme.headlineSmall),
                const SizedBox(height: 8),
                Text(_explanation(state)),
                const SizedBox(height: 24),
                if (!paired) ...[
                  TextField(controller: _invite, minLines: 2, maxLines: 4, decoration: const InputDecoration(labelText: 'Pairing invite', hintText: 'neoth://companion/pair?...')),
                  const SizedBox(height: 12),
                  TextField(controller: _label, decoration: const InputDecoration(labelText: 'Device name', helperText: 'Maximum 64 UTF-8 bytes')),
                  FilledButton(
                    onPressed: state == CompanionViewState.pairing
                        ? null
                        : () async {
                            await widget.controller.pair(_invite.text, _label.text);
                            if (mounted) _invite.clear();
                          },
                    child: const Text('Pair this phone'),
                  ),
                ] else ...[
                  if (widget.controller.status case final snapshot?) _StatusCard(snapshot: snapshot),
                  FilledButton.icon(
                    onPressed: state == CompanionViewState.pairing ? null : () => unawaited(widget.controller.refresh()),
                    icon: const Icon(Icons.refresh),
                    label: const Text('Refresh status'),
                  ),
                  const SizedBox(height: 12),
                  TextButton(
                    onPressed: () => unawaited(widget.controller.forgetLocalEnrollment()),
                    child: const Text('Forget local enrollment'),
                  ),
                ],
              ],
            ),
          ),
        );
      },
    );
  }

  String _title(CompanionViewState state) => switch (state) {
        CompanionViewState.unpaired => 'Pair this phone',
        CompanionViewState.pairing => 'Contacting NEOTH',
        CompanionViewState.ready => 'Connected',
        CompanionViewState.offline => 'Phone is paired, NEOTH is offline',
        CompanionViewState.denied => 'Access denied',
        CompanionViewState.revoked => 'This phone was revoked',
        CompanionViewState.failed => 'Could not complete the request',
      };

  String _explanation(CompanionViewState state) => switch (state) {
        CompanionViewState.unpaired => 'Paste a one-time NEOTH v3 invite or open it from a QR code. The invite is never shown again after pairing.',
        CompanionViewState.pairing => 'Waiting for a real encrypted NEOTH response.',
        CompanionViewState.ready => 'This screen shows the daemon’s redacted status only.',
        CompanionViewState.offline => 'Tap Refresh after NEOTH is available. The app does not create a new pairing automatically.',
        CompanionViewState.denied => 'The daemon refused this device. Pairing is not retried automatically.',
        CompanionViewState.revoked => 'NEOTH revoked this device. A person must create a new invite to pair again.',
        CompanionViewState.failed => 'The invitation or response could not be used. No secret is displayed or retained as an error message.',
      };
}

class _StatusCard extends StatelessWidget {
  const _StatusCard({required this.snapshot});
  final CompanionStatus snapshot;

  @override
  Widget build(BuildContext context) => Card(
        child: Padding(
          padding: const EdgeInsets.all(16),
          child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Text('Readiness: ${snapshot.readiness}'),
            Text(snapshot.activeTurns == null ? 'Active turns: unavailable' : 'Active turns: ${snapshot.activeTurns!.length}'),
            Text('Observed: ${DateTime.fromMillisecondsSinceEpoch(snapshot.observedAtUnix * 1000, isUtc: true).toLocal()}'),
          ]),
        ),
      );
}
