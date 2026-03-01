import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import '../services/sentinel_service.dart';
import 'status_ring.dart';
import 'metrics_panel.dart';
import 'threat_list.dart';
import 'ai_console.dart';

class DashboardScreen extends StatelessWidget {
  const DashboardScreen({super.key});

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: Column(
        children: [
          _buildTopBar(context),
          Expanded(
            child: Row(
              children: [
                // Left panel: Status + Metrics
                SizedBox(
                  width: 380,
                  child: Column(
                    children: [
                      const SizedBox(height: 16),
                      const StatusRing(),
                      const SizedBox(height: 16),
                      const Expanded(child: MetricsPanel()),
                    ],
                  ),
                ),
                const VerticalDivider(
                  width: 1,
                  color: Color(0xFF1E2A45),
                ),
                // Right panel: Threats + AI Console
                Expanded(
                  child: Column(
                    children: [
                      const Expanded(flex: 5, child: ThreatList()),
                      const Divider(
                        height: 1,
                        color: Color(0xFF1E2A45),
                      ),
                      const Expanded(flex: 4, child: AIConsole()),
                    ],
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildTopBar(BuildContext context) {
    return Consumer<SentinelService>(
      builder: (context, service, _) {
        return Container(
          height: 52,
          decoration: const BoxDecoration(
            color: Color(0xFF0D1220),
            border: Border(
              bottom: BorderSide(color: Color(0xFF1E2A45), width: 1),
            ),
          ),
          padding: const EdgeInsets.symmetric(horizontal: 20),
          child: Row(
            children: [
              Container(
                width: 10,
                height: 10,
                decoration: BoxDecoration(
                  shape: BoxShape.circle,
                  color: service.connected
                      ? const Color(0xFF00E676)
                      : const Color(0xFFFF1744),
                  boxShadow: [
                    BoxShadow(
                      color: (service.connected
                              ? const Color(0xFF00E676)
                              : const Color(0xFFFF1744))
                          .withValues(alpha: 0.5),
                      blurRadius: 8,
                      spreadRadius: 2,
                    ),
                  ],
                ),
              ),
              const SizedBox(width: 12),
              Text(
                'RAKSHAK',
                style: TextStyle(
                  color: const Color(0xFF00E5FF),
                  fontSize: 16,
                  fontWeight: FontWeight.w700,
                  letterSpacing: 3,
                ),
              ),
              const SizedBox(width: 8),
              Container(
                padding: const EdgeInsets.symmetric(
                  horizontal: 8,
                  vertical: 2,
                ),
                decoration: BoxDecoration(
                  borderRadius: BorderRadius.circular(4),
                  color: const Color(0xFF1E2A45),
                ),
                child: Text(
                  'MVP',
                  style: TextStyle(
                    color: const Color(0xFF00E5FF).withValues(alpha: 0.7),
                    fontSize: 10,
                    fontWeight: FontWeight.w600,
                    letterSpacing: 1,
                  ),
                ),
              ),
              const Spacer(),
              // Hardware chip
              Container(
                padding: const EdgeInsets.symmetric(
                  horizontal: 10,
                  vertical: 4,
                ),
                decoration: BoxDecoration(
                  borderRadius: BorderRadius.circular(6),
                  border: Border.all(
                    color: const Color(0xFF1E2A45),
                  ),
                ),
                child: Row(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    const Icon(Icons.memory, size: 14, color: Color(0xFF00E5FF)),
                    const SizedBox(width: 6),
                    Text(
                      service.metrics.selectedDevice,
                      style: const TextStyle(
                        fontSize: 11,
                        color: Color(0xFF8899AA),
                      ),
                    ),
                  ],
                ),
              ),
              const SizedBox(width: 12),
              // AI engine chip
              Container(
                padding: const EdgeInsets.symmetric(
                  horizontal: 10,
                  vertical: 4,
                ),
                decoration: BoxDecoration(
                  borderRadius: BorderRadius.circular(6),
                  border: Border.all(
                    color: const Color(0xFF1E2A45),
                  ),
                ),
                child: Row(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    const Icon(Icons.psychology, size: 14, color: Color(0xFF00E676)),
                    const SizedBox(width: 6),
                    Text(
                      service.aiEngine,
                      style: const TextStyle(
                        fontSize: 11,
                        color: Color(0xFF8899AA),
                      ),
                    ),
                  ],
                ),
              ),
              const SizedBox(width: 12),
              // Connection status
              Text(
                service.connected ? 'ONLINE' : 'OFFLINE',
                style: TextStyle(
                  fontSize: 11,
                  fontWeight: FontWeight.w600,
                  letterSpacing: 1.5,
                  color: service.connected
                      ? const Color(0xFF00E676)
                      : const Color(0xFFFF1744),
                ),
              ),
            ],
          ),
        );
      },
    );
  }
}
