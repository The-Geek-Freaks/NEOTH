import 'package:flutter/material.dart';

import 'models.dart';

/// Passive, redacted progress only. It intentionally owns no operation controls.
class CompanionActivityCard extends StatelessWidget {
  const CompanionActivityCard({super.key, required this.snapshot});
  final CompanionChatActivitySnapshot snapshot;

  @override
  Widget build(BuildContext context) {
    final colors = Theme.of(context).colorScheme;
    final events = _latestByOrdinal(snapshot.events);
    return Semantics(
      container: true,
      label: snapshot.incomplete ? 'NEOTH activity, some updates may be missing' : 'NEOTH activity',
      child: Card(
        child: Padding(
          padding: const EdgeInsets.all(16),
          child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Text('NEOTH activity', style: Theme.of(context).textTheme.titleMedium),
            if (snapshot.incomplete) const Padding(padding: EdgeInsets.only(top: 4), child: Text('Some updates may be missing.')),
            const SizedBox(height: 8),
            for (final event in events) Padding(
              padding: const EdgeInsets.only(bottom: 8),
              child: Semantics(
                label: '${_phaseText(event.phase)}: ${event.label}',
                child: DecoratedBox(
                  decoration: BoxDecoration(color: colors.surfaceContainerHighest, borderRadius: BorderRadius.circular(12)),
                  child: Padding(
                    padding: const EdgeInsets.all(12),
                    child: Row(children: [Icon(_icon(event.phase), color: _color(colors, event.phase), semanticLabel: _phaseText(event.phase)), const SizedBox(width: 12), Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [Text(event.label), const SizedBox(height: 2), Text(_phaseText(event.phase), style: Theme.of(context).textTheme.labelMedium)]))]),
                  ),
                ),
              ),
            ),
          ]),
        ),
      ),
    );
  }
}

List<CompanionToolActivityEvent> _latestByOrdinal(List<CompanionToolActivityEvent> events) {
  final latest = <int, CompanionToolActivityEvent>{};
  for (final event in events) { latest[event.ordinal] = event; }
  final ordinals = latest.keys.toList()..sort();
  return List.unmodifiable([for (final ordinal in ordinals) latest[ordinal]!]);
}

String _phaseText(CompanionToolActivityPhase phase) => switch (phase) { CompanionToolActivityPhase.started => 'Started', CompanionToolActivityPhase.succeeded => 'Completed', CompanionToolActivityPhase.failed => 'Failed', CompanionToolActivityPhase.rejected => 'Rejected', CompanionToolActivityPhase.unknown => 'Outcome unknown' };
IconData _icon(CompanionToolActivityPhase phase) => switch (phase) { CompanionToolActivityPhase.started => Icons.hourglass_top_outlined, CompanionToolActivityPhase.succeeded => Icons.check_circle_outline, CompanionToolActivityPhase.failed => Icons.error_outline, CompanionToolActivityPhase.rejected => Icons.block_outlined, CompanionToolActivityPhase.unknown => Icons.info_outline };
Color _color(ColorScheme colors, CompanionToolActivityPhase phase) => switch (phase) { CompanionToolActivityPhase.succeeded => colors.primary, CompanionToolActivityPhase.failed || CompanionToolActivityPhase.rejected => colors.error, _ => colors.secondary };
