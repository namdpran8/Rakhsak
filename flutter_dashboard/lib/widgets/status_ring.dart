import 'dart:math' as math;
import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import '../services/sentinel_service.dart';

class StatusRing extends StatefulWidget {
  const StatusRing({super.key});

  @override
  State<StatusRing> createState() => _StatusRingState();
}

class _StatusRingState extends State<StatusRing>
    with SingleTickerProviderStateMixin {
  late AnimationController _controller;

  @override
  void initState() {
    super.initState();
    _controller = AnimationController(
      vsync: this,
      duration: const Duration(seconds: 4),
    )..repeat();
  }

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Consumer<SentinelService>(
      builder: (context, service, _) {
        final hasThreats = service.hasActiveThreats;
        final connected = service.connected;

        Color ringColor;
        String statusText;
        String subText;

        if (!connected) {
          ringColor = const Color(0xFF555555);
          statusText = 'OFFLINE';
          subText = 'Sentinel disconnected';
        } else if (hasThreats) {
          ringColor = const Color(0xFFFF1744);
          statusText = 'THREAT';
          subText = '${service.threats.length} alert(s) detected';
        } else {
          ringColor = const Color(0xFF00E676);
          statusText = 'SECURE';
          subText = 'All systems nominal';
        }

        return SizedBox(
          width: 220,
          height: 220,
          child: AnimatedBuilder(
            animation: _controller,
            builder: (context, child) {
              return CustomPaint(
                painter: _StatusRingPainter(
                  progress: _controller.value,
                  color: ringColor,
                  isAlert: hasThreats,
                ),
                child: child,
              );
            },
            child: Center(
              child: Column(
                mainAxisSize: MainAxisSize.min,
                children: [
                  Icon(
                    hasThreats
                        ? Icons.shield
                        : connected
                            ? Icons.verified_user
                            : Icons.shield_outlined,
                    size: 36,
                    color: ringColor,
                  ),
                  const SizedBox(height: 8),
                  Text(
                    statusText,
                    style: TextStyle(
                      fontSize: 22,
                      fontWeight: FontWeight.w800,
                      color: ringColor,
                      letterSpacing: 4,
                    ),
                  ),
                  const SizedBox(height: 4),
                  Text(
                    subText,
                    style: TextStyle(
                      fontSize: 10,
                      color: ringColor.withValues(alpha: 0.6),
                      letterSpacing: 1,
                    ),
                  ),
                ],
              ),
            ),
          ),
        );
      },
    );
  }
}

class _StatusRingPainter extends CustomPainter {
  final double progress;
  final Color color;
  final bool isAlert;

  _StatusRingPainter({
    required this.progress,
    required this.color,
    required this.isAlert,
  });

  @override
  void paint(Canvas canvas, Size size) {
    final center = Offset(size.width / 2, size.height / 2);
    final radius = size.width / 2 - 12;

    // Outer faint ring
    final bgPaint = Paint()
      ..color = color.withValues(alpha: 0.08)
      ..style = PaintingStyle.stroke
      ..strokeWidth = 3;
    canvas.drawCircle(center, radius, bgPaint);

    // Inner faint ring
    canvas.drawCircle(center, radius - 15, bgPaint);

    // Animated arc - main ring
    final arcPaint = Paint()
      ..color = color.withValues(alpha: isAlert ? 0.9 : 0.6)
      ..style = PaintingStyle.stroke
      ..strokeWidth = 3
      ..strokeCap = StrokeCap.round;

    final startAngle = progress * 2 * math.pi;
    canvas.drawArc(
      Rect.fromCircle(center: center, radius: radius),
      startAngle,
      math.pi * 1.2,
      false,
      arcPaint,
    );

    // Second arc (counter-rotating)
    final arcPaint2 = Paint()
      ..color = color.withValues(alpha: 0.3)
      ..style = PaintingStyle.stroke
      ..strokeWidth = 2
      ..strokeCap = StrokeCap.round;

    canvas.drawArc(
      Rect.fromCircle(center: center, radius: radius - 15),
      -startAngle * 0.7,
      math.pi * 0.8,
      false,
      arcPaint2,
    );

    // Glow dot on main ring
    final dotAngle = startAngle + math.pi * 1.2;
    final dotX = center.dx + radius * math.cos(dotAngle);
    final dotY = center.dy + radius * math.sin(dotAngle);
    final dotPaint = Paint()
      ..color = color
      ..maskFilter = const MaskFilter.blur(BlurStyle.normal, 4);
    canvas.drawCircle(Offset(dotX, dotY), 4, dotPaint);
  }

  @override
  bool shouldRepaint(covariant _StatusRingPainter oldDelegate) {
    return oldDelegate.progress != progress ||
        oldDelegate.color != color ||
        oldDelegate.isAlert != isAlert;
  }
}
