import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import '../services/sentinel_service.dart';

class ThreatList extends StatelessWidget {
  const ThreatList({super.key});

  @override
  Widget build(BuildContext context) {
    return Consumer<SentinelService>(
      builder: (context, service, _) {
        return Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            _buildHeader(context, service),
            // Pending patches banner
            if (service.pendingPatches.isNotEmpty)
              _PatchBanner(
                patchCount: service.pendingPatches.length,
                patches: service.pendingPatches,
                onApprove: service.approvePatch,
                onReject: service.rejectPatch,
              ),
            Expanded(
              child: service.threats.isEmpty
                  ? _buildEmptyState()
                  : ListView.builder(
                      padding: const EdgeInsets.symmetric(horizontal: 16),
                      itemCount: service.threats.length,
                      itemBuilder: (context, index) {
                        return _ThreatCard(threat: service.threats[index]);
                      },
                    ),
            ),
          ],
        );
      },
    );
  }

  Widget _buildHeader(BuildContext context, SentinelService service) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
      child: Row(
        children: [
          const Icon(Icons.warning_amber_rounded,
              size: 16, color: Color(0xFFFF9100)),
          const SizedBox(width: 8),
          const Text(
            'THREAT FEED',
            style: TextStyle(
              fontSize: 11,
              fontWeight: FontWeight.w600,
              color: Color(0xFF556677),
              letterSpacing: 2,
            ),
          ),
          const SizedBox(width: 8),
          if (service.threats.isNotEmpty)
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 1),
              decoration: BoxDecoration(
                color: const Color(0xFFFF1744).withValues(alpha: 0.15),
                borderRadius: BorderRadius.circular(4),
              ),
              child: Text(
                '${service.threats.length}',
                style: const TextStyle(
                  fontSize: 10,
                  color: Color(0xFFFF1744),
                  fontWeight: FontWeight.w700,
                ),
              ),
            ),
          const Spacer(),
          if (service.threats.isNotEmpty)
            TextButton(
              onPressed: () => service.clearThreats(),
              style: TextButton.styleFrom(
                padding:
                    const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
                minimumSize: Size.zero,
              ),
              child: const Text(
                'CLEAR',
                style: TextStyle(
                  fontSize: 10,
                  color: Color(0xFF556677),
                  letterSpacing: 1,
                ),
              ),
            ),
        ],
      ),
    );
  }

  Widget _buildEmptyState() {
    return Center(
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(
            Icons.verified_user_outlined,
            size: 48,
            color: const Color(0xFF00E676).withValues(alpha: 0.3),
          ),
          const SizedBox(height: 12),
          Text(
            'No threats detected',
            style: TextStyle(
              fontSize: 13,
              color: const Color(0xFF556677).withValues(alpha: 0.7),
            ),
          ),
          const SizedBox(height: 4),
          Text(
            'Sentinel is actively monitoring',
            style: TextStyle(
              fontSize: 11,
              color: const Color(0xFF556677).withValues(alpha: 0.4),
            ),
          ),
        ],
      ),
    );
  }
}

// ---------------------------------------------------------------------------
// Patch approval banner (ethics layer - human-in-the-loop)
// ---------------------------------------------------------------------------
class _PatchBanner extends StatelessWidget {
  final int patchCount;
  final List<PatchSuggestion> patches;
  final void Function(String) onApprove;
  final void Function(String) onReject;

  const _PatchBanner({
    required this.patchCount,
    required this.patches,
    required this.onApprove,
    required this.onReject,
  });

  @override
  Widget build(BuildContext context) {
    return Container(
      margin: const EdgeInsets.symmetric(horizontal: 16, vertical: 4),
      padding: const EdgeInsets.all(10),
      decoration: BoxDecoration(
        color: const Color(0xFFFF9100).withValues(alpha: 0.08),
        borderRadius: BorderRadius.circular(8),
        border: Border.all(color: const Color(0xFFFF9100).withValues(alpha: 0.25)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              const Icon(Icons.healing, size: 14, color: Color(0xFFFF9100)),
              const SizedBox(width: 6),
              Text(
                '$patchCount PATCH${patchCount == 1 ? '' : 'ES'} AWAITING APPROVAL',
                style: const TextStyle(
                  fontSize: 10,
                  fontWeight: FontWeight.w700,
                  color: Color(0xFFFF9100),
                  letterSpacing: 1,
                ),
              ),
              const Spacer(),
              const Icon(Icons.person_outline, size: 12, color: Color(0xFF556677)),
              const SizedBox(width: 4),
              const Text(
                'Human Required',
                style: TextStyle(fontSize: 9, color: Color(0xFF556677)),
              ),
            ],
          ),
          const SizedBox(height: 8),
          ...patches.take(3).map((p) => _PatchRow(
                patch: p,
                onApprove: () => onApprove(p.id),
                onReject: () => onReject(p.id),
              )),
          if (patches.length > 3)
            Padding(
              padding: const EdgeInsets.only(top: 4),
              child: Text(
                '+ ${patches.length - 3} more patches...',
                style: TextStyle(
                  fontSize: 9,
                  color: const Color(0xFF556677).withValues(alpha: 0.7),
                ),
              ),
            ),
        ],
      ),
    );
  }
}

class _PatchRow extends StatelessWidget {
  final PatchSuggestion patch;
  final VoidCallback onApprove;
  final VoidCallback onReject;

  const _PatchRow({
    required this.patch,
    required this.onApprove,
    required this.onReject,
  });

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 6),
      child: Row(
        children: [
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 4, vertical: 1),
            decoration: BoxDecoration(
              color: _riskColor(patch.riskLevel).withValues(alpha: 0.15),
              borderRadius: BorderRadius.circular(3),
            ),
            child: Text(
              patch.riskLevel,
              style: TextStyle(
                fontSize: 8,
                fontWeight: FontWeight.w700,
                color: _riskColor(patch.riskLevel),
              ),
            ),
          ),
          const SizedBox(width: 6),
          Expanded(
            child: Text(
              '${patch.action}: ${patch.target}',
              style: const TextStyle(fontSize: 10, color: Color(0xFF8899AA)),
              overflow: TextOverflow.ellipsis,
            ),
          ),
          if (patch.reversible)
            Padding(
              padding: const EdgeInsets.only(right: 6),
              child: Icon(Icons.undo, size: 10,
                  color: const Color(0xFF00E5FF).withValues(alpha: 0.5)),
            ),
          SizedBox(
            height: 22,
            child: TextButton(
              onPressed: onApprove,
              style: TextButton.styleFrom(
                padding: const EdgeInsets.symmetric(horizontal: 8),
                minimumSize: Size.zero,
                backgroundColor: const Color(0xFF00E676).withValues(alpha: 0.1),
              ),
              child: const Text(
                'APPROVE',
                style: TextStyle(
                  fontSize: 9,
                  fontWeight: FontWeight.w700,
                  color: Color(0xFF00E676),
                  letterSpacing: 0.5,
                ),
              ),
            ),
          ),
          const SizedBox(width: 4),
          SizedBox(
            height: 22,
            child: TextButton(
              onPressed: onReject,
              style: TextButton.styleFrom(
                padding: const EdgeInsets.symmetric(horizontal: 8),
                minimumSize: Size.zero,
                backgroundColor: const Color(0xFFFF1744).withValues(alpha: 0.1),
              ),
              child: const Text(
                'REJECT',
                style: TextStyle(
                  fontSize: 9,
                  fontWeight: FontWeight.w700,
                  color: Color(0xFFFF1744),
                  letterSpacing: 0.5,
                ),
              ),
            ),
          ),
        ],
      ),
    );
  }

  Color _riskColor(String risk) {
    switch (risk) {
      case 'HIGH':
        return const Color(0xFFFF1744);
      case 'MEDIUM':
        return const Color(0xFFFF9100);
      default:
        return const Color(0xFF00E5FF);
    }
  }
}

// ---------------------------------------------------------------------------
// Threat card with event type badge
// ---------------------------------------------------------------------------
class _ThreatCard extends StatelessWidget {
  final ThreatEvent threat;
  const _ThreatCard({required this.threat});

  @override
  Widget build(BuildContext context) {
    final color = _severityColor(threat.verdict);
    return Container(
      margin: const EdgeInsets.only(bottom: 8),
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.04),
        borderRadius: BorderRadius.circular(8),
        border: Border.all(color: color.withValues(alpha: 0.15)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              // Severity badge
              Container(
                padding:
                    const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                decoration: BoxDecoration(
                  color: color.withValues(alpha: 0.15),
                  borderRadius: BorderRadius.circular(4),
                ),
                child: Text(
                  threat.verdict,
                  style: TextStyle(
                    fontSize: 10,
                    fontWeight: FontWeight.w800,
                    color: color,
                    letterSpacing: 1,
                  ),
                ),
              ),
              const SizedBox(width: 6),
              // Event type badge
              Container(
                padding:
                    const EdgeInsets.symmetric(horizontal: 5, vertical: 2),
                decoration: BoxDecoration(
                  color: _eventTypeColor(threat.eventType).withValues(alpha: 0.12),
                  borderRadius: BorderRadius.circular(4),
                ),
                child: Row(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    Icon(
                      _eventTypeIcon(threat.eventType),
                      size: 9,
                      color: _eventTypeColor(threat.eventType),
                    ),
                    const SizedBox(width: 3),
                    Text(
                      _eventTypeLabel(threat.eventType),
                      style: TextStyle(
                        fontSize: 8,
                        fontWeight: FontWeight.w700,
                        color: _eventTypeColor(threat.eventType),
                        letterSpacing: 0.5,
                      ),
                    ),
                  ],
                ),
              ),
              const SizedBox(width: 8),
              Expanded(
                child: Text(
                  threat.processName,
                  style: const TextStyle(
                    fontSize: 12,
                    fontWeight: FontWeight.w600,
                    color: Color(0xFFCCDDEE),
                  ),
                  overflow: TextOverflow.ellipsis,
                ),
              ),
              if (threat.pid > 0) ...[
                const SizedBox(width: 6),
                Text(
                  'PID:${threat.pid}',
                  style: TextStyle(
                    fontSize: 10,
                    color: const Color(0xFF556677).withValues(alpha: 0.7),
                  ),
                ),
              ],
              const SizedBox(width: 6),
              Text(
                threat.engine,
                style: TextStyle(
                  fontSize: 9,
                  color: const Color(0xFF00E5FF).withValues(alpha: 0.5),
                  letterSpacing: 0.5,
                ),
              ),
            ],
          ),
          const SizedBox(height: 8),
          Text(
            threat.explanation,
            style: const TextStyle(
              fontSize: 11,
              color: Color(0xFF8899AA),
              height: 1.4,
            ),
            maxLines: 3,
            overflow: TextOverflow.ellipsis,
          ),
          if (threat.recommendation.isNotEmpty) ...[
            const SizedBox(height: 6),
            Row(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Icon(Icons.arrow_forward,
                    size: 12, color: color.withValues(alpha: 0.6)),
                const SizedBox(width: 4),
                Expanded(
                  child: Text(
                    threat.recommendation,
                    style: TextStyle(
                      fontSize: 10,
                      color: color.withValues(alpha: 0.7),
                      fontStyle: FontStyle.italic,
                    ),
                  ),
                ),
              ],
            ),
          ],
        ],
      ),
    );
  }

  Color _severityColor(String severity) {
    switch (severity) {
      case 'CRITICAL':
        return const Color(0xFFFF1744);
      case 'HIGH':
      case 'MALICIOUS':
        return const Color(0xFFFF9100);
      case 'MEDIUM':
        return const Color(0xFFFFEA00);
      default:
        return const Color(0xFF00E5FF);
    }
  }

  Color _eventTypeColor(String type) {
    switch (type) {
      case 'behavioral':
        return const Color(0xFF7C4DFF);
      case 'scan_finding':
        return const Color(0xFF00BCD4);
      default:
        return const Color(0xFFFF9100);
    }
  }

  IconData _eventTypeIcon(String type) {
    switch (type) {
      case 'behavioral':
        return Icons.timeline;
      case 'scan_finding':
        return Icons.search;
      default:
        return Icons.warning_amber;
    }
  }

  String _eventTypeLabel(String type) {
    switch (type) {
      case 'behavioral':
        return 'BEHAVIOR';
      case 'scan_finding':
        return 'SCAN';
      default:
        return 'THREAT';
    }
  }
}
