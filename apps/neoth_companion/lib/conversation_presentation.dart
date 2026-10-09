import 'package:flutter/material.dart';
import 'conversation_models.dart';

/// A read-only projection. It cannot issue a request or infer a missing turn.
class ConversationHistoryCard extends StatelessWidget {
  const ConversationHistoryCard({super.key, required this.history});
  final ConversationHistory history;

  @override
  Widget build(BuildContext context) => Card(child: Padding(
    padding: const EdgeInsets.all(16),
    child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
      Semantics(header: true, child: Text('Saved conversation', style: Theme.of(context).textTheme.titleMedium)),
      const SizedBox(height: 8),
      if (!history.available)
        Text(switch (history.state) {
          'incognito' => 'Incognito messages are not saved as conversation history.',
          'not_found' => 'No saved conversation was found for this send.',
          _ => 'Saved history is currently unavailable.',
        })
      else ...[
        const Text('Most recent saved messages. Older messages may be outside this view.'),
        if (history.turns.isEmpty) const Padding(padding: EdgeInsets.only(top: 12), child: Text('No saved messages yet.')),
        for (final turn in history.turns) ...[
          const SizedBox(height: 16),
          Text(turn.role == 'operator' ? 'You' : 'NEOTH', style: Theme.of(context).textTheme.labelLarge),
          const SizedBox(height: 4),
          if (turn.text case final text?) SelectableText(text)
          else const Text('This message exceeds the mobile history limit. Its full text remains on NEOTH.'),
        ],
      ],
    ]),
  ));
}
