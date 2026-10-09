import 'package:flutter/material.dart';
import 'package:flutter/rendering.dart' show ScrollDirection;
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

/// Following new text is a presentation choice owned by the reader. The
/// viewport has no networking or conversation authority.
class ConversationViewport extends StatefulWidget {
  const ConversationViewport({super.key, required this.scope, required this.revision, required this.child});
  final String scope;
  final Object revision;
  final Widget child;

  @override
  State<ConversationViewport> createState() => _ConversationViewportState();
}

class _ConversationViewportState extends State<ConversationViewport> {
  final _scroll = ScrollController();
  bool _following = true;
  bool _userMoving = false;
  bool _scheduled = false;
  bool _jumping = false;

  @override
  void initState() {
    super.initState();
    _followAfterLayout();
  }

  @override
  void didUpdateWidget(covariant ConversationViewport oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (oldWidget.scope != widget.scope) {
      _following = true;
      _userMoving = false;
    }
    if (oldWidget.scope != widget.scope || oldWidget.revision != widget.revision) _followAfterLayout();
  }

  void _followAfterLayout() {
    if (_scheduled) return;
    _scheduled = true;
    WidgetsBinding.instance.addPostFrameCallback((_) {
      _scheduled = false;
      if (!mounted || !_following || _userMoving || !_scroll.hasClients) return;
      _jumping = true;
      try { _scroll.jumpTo(_scroll.position.maxScrollExtent); } finally { _jumping = false; }
    });
  }

  bool _observeScroll(ScrollNotification notification) {
    if (notification.depth != 0 || _jumping) return false;
    if (notification is UserScrollNotification) {
      _userMoving = notification.direction != ScrollDirection.idle;
    } else if (notification is! ScrollUpdateNotification) {
      return false;
    }
    final following = notification.metrics.extentAfter <= 24;
    if (following != _following) setState(() => _following = following);
    if (_following && !_userMoving) _followAfterLayout();
    return false;
  }

  @override
  void dispose() {
    _scroll.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) => Column(
    crossAxisAlignment: CrossAxisAlignment.stretch,
    children: [
      ConstrainedBox(
        constraints: const BoxConstraints(maxHeight: 360),
        child: NotificationListener<ScrollMetricsNotification>(
          onNotification: (notification) {
            if (notification.depth == 0) _followAfterLayout();
            return false;
          },
          child: NotificationListener<ScrollNotification>(
            onNotification: _observeScroll,
            child: Scrollbar(
              controller: _scroll,
              child: SingleChildScrollView(
                key: const ValueKey('conversation-viewport-scroll'),
                controller: _scroll,
                child: widget.child,
              ),
            ),
          ),
        ),
      ),
      if (_following)
        const Padding(padding: EdgeInsets.symmetric(vertical: 8), child: Text('Following new messages'))
      else
        OutlinedButton.icon(
          onPressed: () {
            setState(() { _following = true; _userMoving = false; });
            _followAfterLayout();
          },
          icon: const Icon(Icons.arrow_downward),
          label: const Text('Jump to latest'),
        ),
    ],
  );
}
