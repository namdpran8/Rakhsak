import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import 'package:fl_chart/fl_chart.dart';
import '../services/sentinel_service.dart';

class MetricsPanel extends StatelessWidget {
  const MetricsPanel({super.key});

  @override
  Widget build(BuildContext context) {
    return Consumer<SentinelService>(
      builder: (context, service, _) {
        final m = service.metrics;
        return Padding(
          padding: const EdgeInsets.symmetric(horizontal: 16),
          child: SingleChildScrollView(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const _SectionHeader(title: 'SYSTEM VITALS'),
                const SizedBox(height: 12),
                SizedBox(
                  height: 80,
                  child: _CpuChart(data: service.cpuHistory),
                ),
                const SizedBox(height: 12),
                _MetricRow(
                  icon: Icons.developer_board,
                  label: 'CPU',
                  value: '${m.cpuPercent.toStringAsFixed(1)}%',
                  color: _colorForPercent(m.cpuPercent),
                ),
                const SizedBox(height: 6),
                _MetricRow(
                  icon: Icons.memory,
                  label: 'RAM',
                  value:
                      '${m.memoryUsedGb.toStringAsFixed(1)} / ${m.memoryTotalGb.toStringAsFixed(1)} GB',
                  color: _colorForPercent(m.memoryPercent),
                  percent: m.memoryPercent,
                ),
                const SizedBox(height: 6),
                _MetricRow(
                  icon: Icons.storage,
                  label: 'DISK',
                  value: '${m.diskPercent.toStringAsFixed(1)}%',
                  color: _colorForPercent(m.diskPercent),
                  percent: m.diskPercent,
                ),
                const SizedBox(height: 6),
                _MetricRow(
                  icon: Icons.lan,
                  label: 'NET',
                  value: 'TX ${m.netSentMb.toStringAsFixed(0)} / RX ${m.netRecvMb.toStringAsFixed(0)} MB',
                  color: const Color(0xFF00E5FF),
                ),
                const SizedBox(height: 6),
                _MetricRow(
                  icon: Icons.apps,
                  label: 'PROCS',
                  value: '${m.processCount}',
                  color: const Color(0xFF8899AA),
                ),

                // Defense engines section
                const SizedBox(height: 20),
                const _SectionHeader(title: 'DEFENSE ENGINES'),
                const SizedBox(height: 10),

                // Behavioral engine stats
                _DefenseRow(
                  icon: Icons.timeline,
                  label: 'Behavioral',
                  color: const Color(0xFF7C4DFF),
                  stats: '${m.behavioralScans} scans | '
                      '${m.behavioralAnomalies} anomalies | '
                      '${m.trackedProcesses} tracked',
                ),
                const SizedBox(height: 6),

                // Code scanner stats
                _DefenseRow(
                  icon: Icons.search,
                  label: 'Scanner',
                  color: const Color(0xFF00BCD4),
                  stats: '${m.scannerFilesScanned} files | '
                      '${m.scannerFindings} findings',
                ),
                const SizedBox(height: 6),

                // Patch engine stats
                _DefenseRow(
                  icon: Icons.healing,
                  label: 'Patches',
                  color: const Color(0xFFFF9100),
                  stats: '${m.patchesSuggested} suggested | '
                      '${m.patchesApproved} approved | '
                      '${m.patchesPending} pending',
                ),
                const SizedBox(height: 6),

                // Uptime
                _MetricRow(
                  icon: Icons.timer_outlined,
                  label: 'UPTIME',
                  value: m.uptimeFormatted,
                  color: const Color(0xFF00E676),
                ),

                const SizedBox(height: 16),
              ],
            ),
          ),
        );
      },
    );
  }

  static Color _colorForPercent(double pct) {
    if (pct > 90) return const Color(0xFFFF1744);
    if (pct > 70) return const Color(0xFFFF9100);
    if (pct > 50) return const Color(0xFFFFEA00);
    return const Color(0xFF00E676);
  }
}

class _SectionHeader extends StatelessWidget {
  final String title;
  const _SectionHeader({required this.title});

  @override
  Widget build(BuildContext context) {
    return Text(
      title,
      style: const TextStyle(
        fontSize: 11,
        fontWeight: FontWeight.w600,
        color: Color(0xFF556677),
        letterSpacing: 2,
      ),
    );
  }
}

class _MetricRow extends StatelessWidget {
  final IconData icon;
  final String label;
  final String value;
  final Color color;
  final double? percent;

  const _MetricRow({
    required this.icon,
    required this.label,
    required this.value,
    required this.color,
    this.percent,
  });

  @override
  Widget build(BuildContext context) {
    return Row(
      children: [
        Icon(icon, size: 16, color: color.withValues(alpha: 0.7)),
        const SizedBox(width: 8),
        SizedBox(
          width: 48,
          child: Text(
            label,
            style: const TextStyle(
              fontSize: 11,
              color: Color(0xFF556677),
              fontWeight: FontWeight.w600,
              letterSpacing: 1,
            ),
          ),
        ),
        if (percent != null) ...[
          Expanded(
            child: ClipRRect(
              borderRadius: BorderRadius.circular(2),
              child: LinearProgressIndicator(
                value: percent! / 100,
                backgroundColor: const Color(0xFF1E2A45),
                valueColor: AlwaysStoppedAnimation<Color>(color),
                minHeight: 4,
              ),
            ),
          ),
          const SizedBox(width: 8),
        ] else
          const Spacer(),
        Text(
          value,
          style: TextStyle(
            fontSize: 11,
            color: color,
            fontWeight: FontWeight.w500,
          ),
        ),
      ],
    );
  }
}

class _DefenseRow extends StatelessWidget {
  final IconData icon;
  final String label;
  final Color color;
  final String stats;

  const _DefenseRow({
    required this.icon,
    required this.label,
    required this.color,
    required this.stats,
  });

  @override
  Widget build(BuildContext context) {
    return Row(
      children: [
        Icon(icon, size: 14, color: color),
        const SizedBox(width: 6),
        SizedBox(
          width: 72,
          child: Text(
            label,
            style: TextStyle(
              fontSize: 10,
              color: color,
              fontWeight: FontWeight.w600,
            ),
          ),
        ),
        Expanded(
          child: Text(
            stats,
            style: TextStyle(
              fontSize: 10,
              color: const Color(0xFF8899AA).withValues(alpha: 0.8),
            ),
            overflow: TextOverflow.ellipsis,
          ),
        ),
      ],
    );
  }
}

class _CpuChart extends StatelessWidget {
  final List<double> data;
  const _CpuChart({required this.data});

  @override
  Widget build(BuildContext context) {
    return LineChart(
      LineChartData(
        gridData: FlGridData(
          show: true,
          drawVerticalLine: false,
          horizontalInterval: 25,
          getDrawingHorizontalLine: (value) => FlLine(
            color: const Color(0xFF1E2A45),
            strokeWidth: 1,
          ),
        ),
        titlesData: const FlTitlesData(show: false),
        borderData: FlBorderData(show: false),
        minY: 0,
        maxY: 100,
        lineTouchData: const LineTouchData(enabled: false),
        lineBarsData: [
          LineChartBarData(
            spots: data
                .asMap()
                .entries
                .map((e) => FlSpot(e.key.toDouble(), e.value))
                .toList(),
            isCurved: true,
            curveSmoothness: 0.3,
            color: const Color(0xFF00E5FF),
            barWidth: 2,
            isStrokeCapRound: true,
            dotData: const FlDotData(show: false),
            belowBarData: BarAreaData(
              show: true,
              color: const Color(0xFF00E5FF).withValues(alpha: 0.08),
            ),
          ),
        ],
      ),
      duration: const Duration(milliseconds: 300),
    );
  }
}
