import 'package:flutter/material.dart';

import 'companion_theme.dart';
import 'models.dart';

/// Renders the already-validated V3 terminal. It owns no transport or action.
class CompanionTerminalCard extends StatelessWidget {
  const CompanionTerminalCard({super.key, required this.terminal, this.recordsInHistory = false});
  final CompanionChatTerminal terminal;
  final bool recordsInHistory;

  @override
  Widget build(BuildContext context) {
    final colors = Theme.of(context).colorScheme;
    final outcome = _outcomePresentation(terminal.outcome);
    return Semantics(
      container: true,
      explicitChildNodes: true,
      label: 'Chat result: ${terminal.outcome}',
      child: Card(
        clipBehavior: Clip.antiAlias,
        child: Padding(
          padding: const EdgeInsets.all(16),
          child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
              Icon(outcome.icon, color: CompanionTheme.outcomeColor(colors, terminal.outcome), semanticLabel: outcome.iconLabel),
              const SizedBox(width: 12),
              Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                Text('Chat result: ${terminal.outcome}', style: Theme.of(context).textTheme.titleMedium),
                const SizedBox(height: 2),
                Text(outcome.message, style: Theme.of(context).textTheme.bodyMedium),
              ])),
            ]),
            if (terminal.accepted) ...[
              const SizedBox(height: 16),
              _CustodyLine(label: 'Provider', value: terminal.provider!),
              const SizedBox(height: 4),
              _CustodyLine(label: 'Model', value: terminal.model!),
              const SizedBox(height: 16),
              if (recordsInHistory)
                const Text('The confirmed answer is shown in the saved conversation above.')
              else if (terminal.records.isEmpty)
                const Text('NEOTH accepted the request. No terminal records were returned.')
              else
                for (final record in terminal.records) ...[_TerminalRecordRow(record: record), const SizedBox(height: 8)],
            ] else ...[
              const SizedBox(height: 12),
              const Text('No message is retried automatically.'),
            ],
          ]),
        ),
      ),
    );
  }
}

class _CustodyLine extends StatelessWidget {
  const _CustodyLine({required this.label, required this.value});
  final String label;
  final String value;
  @override
  Widget build(BuildContext context) => Text('$label: $value', style: Theme.of(context).textTheme.bodyMedium);
}

class _TerminalRecordRow extends StatelessWidget {
  const _TerminalRecordRow({required this.record});
  final CompanionChatRecord record;
  @override
  Widget build(BuildContext context) {
    final presentation = _recordPresentation(record.kind);
    final colors = Theme.of(context).colorScheme;
    return Semantics(
      container: true,
      explicitChildNodes: true,
      child: DecoratedBox(
        decoration: BoxDecoration(color: colors.surfaceContainerHighest, borderRadius: BorderRadius.circular(12), border: Border.all(color: colors.outline)),
        child: Padding(
          padding: const EdgeInsets.all(12),
          child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Semantics(
              header: true,
              child: Text(presentation.label, style: Theme.of(context).textTheme.labelLarge),
            ),
            const SizedBox(height: 4),
            SelectableText(record.text, style: Theme.of(context).textTheme.bodyMedium),
          ]),
        ),
      ),
    );
  }
}

_OutcomePresentation _outcomePresentation(String outcome) => switch (outcome) {
      'accepted' => const _OutcomePresentation(Icons.check_circle_outline, 'Request completed', 'Completed'),
      'denied' => const _OutcomePresentation(Icons.block_outlined, 'NEOTH denied this request', 'Denied'),
      'busy' => const _OutcomePresentation(Icons.hourglass_top_outlined, 'NEOTH is busy', 'Busy'),
      'unavailable' => const _OutcomePresentation(Icons.cloud_off_outlined, 'NEOTH is unavailable', 'Unavailable'),
      'timeout' => const _OutcomePresentation(Icons.schedule_outlined, 'The request timed out', 'Timed out'),
      'indeterminate' => const _OutcomePresentation(Icons.help_outline, 'The request outcome is indeterminate', 'Indeterminate'),
      _ => const _OutcomePresentation(Icons.help_outline, 'The request outcome is unknown', 'Unknown'),
    };

_RecordPresentation _recordPresentation(String kind) => switch (kind) {
      'stdout' => const _RecordPresentation('Response output'),
      'stderr' => const _RecordPresentation('Diagnostic output'),
      'notice' => const _RecordPresentation('NEOTH notice'),
      _ => const _RecordPresentation('Terminal record'),
    };

class _OutcomePresentation {
  const _OutcomePresentation(this.icon, this.message, this.iconLabel);
  final IconData icon;
  final String message;
  final String iconLabel;
}

class _RecordPresentation {
  const _RecordPresentation(this.label);
  final String label;
}
