import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import '../services/sentinel_service.dart';

class AIConsole extends StatefulWidget {
  const AIConsole({super.key});

  @override
  State<AIConsole> createState() => _AIConsoleState();
}

class _AIConsoleState extends State<AIConsole> {
  final ScrollController _scrollController = ScrollController();

  @override
  void dispose() {
    _scrollController.dispose();
    super.dispose();
  }

  void _scrollToBottom() {
    if (_scrollController.hasClients) {
      _scrollController.animateTo(
        _scrollController.position.maxScrollExtent,
        duration: const Duration(milliseconds: 200),
        curve: Curves.easeOut,
      );
    }
  }

  @override
  Widget build(BuildContext context) {
    return Consumer<SentinelService>(
      builder: (context, service, _) {
        WidgetsBinding.instance.addPostFrameCallback((_) => _scrollToBottom());

        return Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Container(
              padding:
                  const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
              child: Row(
                children: [
                  const Icon(Icons.terminal,
                      size: 16, color: Color(0xFF00E5FF)),
                  const SizedBox(width: 8),
                  const Text(
                    'AI CONSOLE',
                    style: TextStyle(
                      fontSize: 11,
                      fontWeight: FontWeight.w600,
                      color: Color(0xFF556677),
                      letterSpacing: 2,
                    ),
                  ),
                  const Spacer(),
                  Container(
                    width: 6,
                    height: 6,
                    decoration: BoxDecoration(
                      shape: BoxShape.circle,
                      color: service.connected
                          ? const Color(0xFF00E676)
                          : const Color(0xFFFF1744),
                    ),
                  ),
                  const SizedBox(width: 6),
                  Text(
                    service.connected ? 'LIVE' : 'DISCONNECTED',
                    style: TextStyle(
                      fontSize: 9,
                      color: service.connected
                          ? const Color(0xFF00E676)
                          : const Color(0xFFFF1744),
                      letterSpacing: 1,
                      fontWeight: FontWeight.w600,
                    ),
                  ),
                ],
              ),
            ),
            Expanded(
              child: Container(
                width: double.infinity,
                color: const Color(0xFF080C14),
                padding: const EdgeInsets.all(12),
                child: ListView.builder(
                  controller: _scrollController,
                  itemCount: service.consoleLogs.length,
                  itemBuilder: (context, index) {
                    final line = service.consoleLogs[index];
                    return Padding(
                      padding: const EdgeInsets.only(bottom: 2),
                      child: Text(
                        line,
                        style: TextStyle(
                          fontSize: 11,
                          fontFamily: 'JetBrains Mono',
                          height: 1.5,
                          color: _colorForLine(line),
                        ),
                      ),
                    );
                  },
                ),
              ),
            ),
          ],
        );
      },
    );
  }

  Color _colorForLine(String line) {
    if (line.contains('[THREAT]') || line.contains('CRITICAL')) {
      return const Color(0xFFFF1744);
    }
    if (line.contains('HIGH') || line.contains('MALICIOUS')) {
      return const Color(0xFFFF9100);
    }
    if (line.contains('[AI]')) {
      return const Color(0xFF00E5FF);
    }
    if (line.contains('[ERR]')) {
      return const Color(0xFFFF1744).withValues(alpha:0.8);
    }
    if (line.contains('[HW]') || line.contains('[SYS]')) {
      return const Color(0xFF00E676).withValues(alpha:0.7);
    }
    return const Color(0xFF556677);
  }
}
