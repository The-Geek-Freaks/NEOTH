import 'dart:async';
import 'package:flutter/material.dart';
import 'notification_preview_controller.dart';

class NotificationPreviewPanel extends StatefulWidget {
  const NotificationPreviewPanel({super.key, this.controller});
  final NotificationPreviewController? controller;

  @override
  State<NotificationPreviewPanel> createState() => _NotificationPreviewPanelState();
}

class _NotificationPreviewPanelState extends State<NotificationPreviewPanel> with WidgetsBindingObserver {
  late final NotificationPreviewController _preview = widget.controller ?? NotificationPreviewController();

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    unawaited(_preview.setVisible(WidgetsBinding.instance.lifecycleState == AppLifecycleState.resumed));
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) =>
      unawaited(_preview.setVisible(state == AppLifecycleState.resumed));

  Future<void> _chooseTime(bool start) async {
    final minutes = start ? _preview.quietStart : _preview.quietEnd;
    final result = await showTimePicker(context: context,
      initialTime: TimeOfDay(hour: minutes ~/ 60, minute: minutes % 60));
    if (!mounted || result == null) return;
    final value = result.hour * 60 + result.minute;
    await _preview.setQuietHours(enabled: _preview.quietHours,
      start: start ? value : _preview.quietStart, end: start ? _preview.quietEnd : value);
  }

  String _time(int minutes) => TimeOfDay(hour: minutes ~/ 60, minute: minutes % 60).format(context);

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    if (widget.controller == null) { _preview.dispose(); }
    else { unawaited(_preview.setVisible(false)); }
    super.dispose();
  }

  @override
  Widget build(BuildContext context) => AnimatedBuilder(
    animation: _preview,
    builder: (context, _) => Card(child: Padding(
      padding: const EdgeInsets.all(16),
      child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
        Semantics(header: true, child: Text('Message previews', style: Theme.of(context).textTheme.titleMedium)),
        if (!_preview.supported)
          const Text('Reading other apps’ notifications is available only on Android. NEOTH chats remain separate.')
        else ...[
          SwitchListTile.adaptive(
            contentPadding: EdgeInsets.zero,
            title: const Text('Show previews while NEOTH is open'),
            subtitle: const Text('Off by default each time the app starts. Selected notifications appear here for up to 30 seconds, then disappear. Nothing is forwarded, saved, marked read, or replied to.'),
            value: _preview.enabled,
            onChanged: (value) => unawaited(_preview.setEnabled(value)),
          ),
          if (_preview.enabled) ...[
            const Text('Choose which apps may appear:'),
            for (final package in previewPackages.entries)
              CheckboxListTile(
                contentPadding: EdgeInsets.zero,
                title: Text(package.value),
                value: _preview.packages.contains(package.key),
                onChanged: (value) => unawaited(_preview.setPackage(package.key, value == true)),
              ),
            if (!_preview.systemAccess) ...[
              const Text('Android notification access is not enabled for NEOTH.'),
              OutlinedButton(onPressed: () => unawaited(_preview.openSystemSettings()),
                child: const Text('Open Android notification access')),
            ],
            SwitchListTile.adaptive(
              contentPadding: EdgeInsets.zero,
              title: const Text('Quiet hours'),
              value: _preview.quietHours,
              onChanged: (value) => unawaited(_preview.setQuietHours(enabled: value,
                start: _preview.quietStart, end: _preview.quietEnd)),
            ),
            if (_preview.quietHours) ...[
              Wrap(spacing: 8, runSpacing: 8, children: [
                OutlinedButton(onPressed: () => unawaited(_chooseTime(true)), child: Text('From ${_time(_preview.quietStart)}')),
                OutlinedButton(onPressed: () => unawaited(_chooseTime(false)), child: Text('Until ${_time(_preview.quietEnd)}')),
              ]),
              if (_preview.quietStart == _preview.quietEnd) const Text('Equal times pause previews all day.'),
            ],
          ],
          if (_preview.error case final error?) Text(error),
          if (_preview.current case final notice?) ...[
            const Divider(),
            Text('${notice.channel} · notification preview', style: Theme.of(context).textTheme.labelLarge),
            const SizedBox(height: 8),
            Text(notice.sender, style: Theme.of(context).textTheme.titleSmall),
            const SizedBox(height: 4),
            Text(notice.text),
            Align(alignment: Alignment.centerLeft,
              child: TextButton(onPressed: _preview.dismiss, child: const Text('Hide preview'))),
          ],
        ],
      ]),
    )),
  );
}