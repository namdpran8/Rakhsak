import 'dart:async';
import 'dart:convert';
import 'package:flutter/foundation.dart';
import 'package:web_socket_channel/web_socket_channel.dart';

class ThreatEvent {
  final String timestamp;
  final int pid;
  final String processName;
  final String reason;
  final String severity;
  final String eventType; // 'threat', 'behavioral', 'scan_finding'
  final Map<String, dynamic> details;
  final Map<String, dynamic> analysis;
  final List<Map<String, dynamic>> patches;

  ThreatEvent({
    required this.timestamp,
    required this.pid,
    required this.processName,
    required this.reason,
    required this.severity,
    required this.eventType,
    required this.details,
    required this.analysis,
    this.patches = const [],
  });

  factory ThreatEvent.fromJson(Map<String, dynamic> json) {
    final event = json['event'] as Map<String, dynamic>? ?? {};
    final type = (json['type'] ?? 'threat').toString();
    final name = (event['process_name'] ?? event['file_path'] ?? event['rule_name'] ?? 'unknown').toString();
    final reason = (event['reason'] ?? event['description'] ?? event['anomaly_type'] ?? '').toString();

    final rawPatches = json['patches'];
    final patchList = <Map<String, dynamic>>[];
    if (rawPatches is List) {
      for (final p in rawPatches) {
        if (p is Map) patchList.add(Map<String, dynamic>.from(p));
      }
    }

    return ThreatEvent(
      timestamp: (event['timestamp'] ?? '').toString(),
      pid: (event['pid'] is int) ? event['pid'] : 0,
      processName: name,
      reason: reason,
      severity: (event['severity'] ?? 'LOW').toString(),
      eventType: type,
      details: (event['details'] is Map)
          ? Map<String, dynamic>.from(event['details'])
          : {},
      analysis: (json['analysis'] is Map)
          ? Map<String, dynamic>.from(json['analysis'])
          : {},
      patches: patchList,
    );
  }

  String get verdict => (analysis['verdict'] ?? severity).toString();
  String get explanation => (analysis['explanation'] ?? reason).toString();
  String get recommendation => (analysis['recommendation'] ?? '').toString();
  String get engine => (analysis['engine'] ?? 'unknown').toString();
}

class PatchSuggestion {
  final String id;
  final String action;
  final String target;
  final String description;
  final String riskLevel;
  final String severity;
  final bool reversible;
  String status;

  PatchSuggestion({
    required this.id,
    required this.action,
    required this.target,
    required this.description,
    required this.riskLevel,
    required this.severity,
    required this.reversible,
    this.status = 'pending',
  });

  factory PatchSuggestion.fromJson(Map<String, dynamic> json) {
    return PatchSuggestion(
      id: (json['id'] ?? '').toString(),
      action: (json['action'] ?? '').toString(),
      target: (json['target'] ?? '').toString(),
      description: (json['description'] ?? '').toString(),
      riskLevel: (json['risk_level'] ?? 'LOW').toString(),
      severity: (json['severity'] ?? 'LOW').toString(),
      reversible: json['reversible'] == true,
      status: (json['status'] ?? 'pending').toString(),
    );
  }
}

class SystemMetrics {
  final double cpuPercent;
  final double memoryPercent;
  final double memoryUsedGb;
  final double memoryTotalGb;
  final double diskPercent;
  final double netSentMb;
  final double netRecvMb;
  final int processCount;
  final String selectedDevice;
  final int uptimeSeconds;
  final int behavioralScans;
  final int behavioralAnomalies;
  final int trackedProcesses;
  final int scannerFilesScanned;
  final int scannerFindings;
  final int patchesSuggested;
  final int patchesApproved;
  final int patchesRejected;
  final int patchesPending;

  SystemMetrics({
    this.cpuPercent = 0,
    this.memoryPercent = 0,
    this.memoryUsedGb = 0,
    this.memoryTotalGb = 0,
    this.diskPercent = 0,
    this.netSentMb = 0,
    this.netRecvMb = 0,
    this.processCount = 0,
    this.selectedDevice = 'Detecting...',
    this.uptimeSeconds = 0,
    this.behavioralScans = 0,
    this.behavioralAnomalies = 0,
    this.trackedProcesses = 0,
    this.scannerFilesScanned = 0,
    this.scannerFindings = 0,
    this.patchesSuggested = 0,
    this.patchesApproved = 0,
    this.patchesRejected = 0,
    this.patchesPending = 0,
  });

  factory SystemMetrics.fromJson(Map<String, dynamic> json) {
    final hw = (json['hardware'] is Map)
        ? Map<String, dynamic>.from(json['hardware'])
        : <String, dynamic>{};
    final beh = (json['behavioral'] is Map)
        ? Map<String, dynamic>.from(json['behavioral'])
        : <String, dynamic>{};
    final scan = (json['scanner'] is Map)
        ? Map<String, dynamic>.from(json['scanner'])
        : <String, dynamic>{};
    final patches = (json['patches'] is Map)
        ? Map<String, dynamic>.from(json['patches'])
        : <String, dynamic>{};

    return SystemMetrics(
      cpuPercent: _toDouble(json['cpu_percent']),
      memoryPercent: _toDouble(json['memory_percent']),
      memoryUsedGb: _toDouble(json['memory_used_gb']),
      memoryTotalGb: _toDouble(json['memory_total_gb']),
      diskPercent: _toDouble(json['disk_percent']),
      netSentMb: _toDouble(json['net_sent_mb']),
      netRecvMb: _toDouble(json['net_recv_mb']),
      processCount: _toInt(json['process_count']),
      selectedDevice: (hw['selected_device'] ?? 'Unknown').toString(),
      uptimeSeconds: _toInt(json['uptime_seconds']),
      behavioralScans: _toInt(beh['total_scans']),
      behavioralAnomalies: _toInt(beh['total_anomalies']),
      trackedProcesses: _toInt(beh['tracked_processes']),
      scannerFilesScanned: _toInt(scan['total_files_scanned']),
      scannerFindings: _toInt(scan['total_findings']),
      patchesSuggested: _toInt(patches['total_suggested']),
      patchesApproved: _toInt(patches['total_approved']),
      patchesRejected: _toInt(patches['total_rejected']),
      patchesPending: _toInt(patches['pending_count']),
    );
  }

  static double _toDouble(dynamic v) {
    if (v is double) return v;
    if (v is int) return v.toDouble();
    if (v is String) return double.tryParse(v) ?? 0;
    return 0;
  }

  static int _toInt(dynamic v) {
    if (v is int) return v;
    if (v is double) return v.toInt();
    if (v is String) return int.tryParse(v) ?? 0;
    return 0;
  }

  String get uptimeFormatted {
    final h = uptimeSeconds ~/ 3600;
    final m = (uptimeSeconds % 3600) ~/ 60;
    final s = uptimeSeconds % 60;
    if (h > 0) return '${h}h ${m}m';
    if (m > 0) return '${m}m ${s}s';
    return '${s}s';
  }
}

class SentinelService extends ChangeNotifier {
  WebSocketChannel? _channel;
  Timer? _reconnectTimer;
  bool _connected = false;
  String _aiEngine = 'Connecting...';
  SystemMetrics _metrics = SystemMetrics();
  final List<ThreatEvent> _threats = [];
  final List<PatchSuggestion> _pendingPatches = [];
  final List<String> _consoleLogs = [];
  final List<double> _cpuHistory = List<double>.generate(30, (_) => 0.0);

  bool get connected => _connected;
  String get aiEngine => _aiEngine;
  SystemMetrics get metrics => _metrics;
  List<ThreatEvent> get threats => List.unmodifiable(_threats);
  List<PatchSuggestion> get pendingPatches => List.unmodifiable(_pendingPatches);
  List<String> get consoleLogs => List.unmodifiable(_consoleLogs);
  List<double> get cpuHistory => List.unmodifiable(_cpuHistory);
  bool get hasActiveThreats => _threats.any((t) =>
      t.verdict == 'CRITICAL' || t.verdict == 'HIGH' || t.verdict == 'MALICIOUS');

  SentinelService() {
    _connect();
  }

  void _connect() {
    _channel?.sink.close();
    _channel = null;

    try {
      _channel = WebSocketChannel.connect(Uri.parse('ws://127.0.0.1:8765'));
      _log('[SYS] Connecting to Rakshak sentinel...');

      _channel!.stream.listen(
        _onMessage,
        onError: (error) {
          _log('[ERR] Connection error: $error');
          _onDisconnect();
        },
        onDone: _onDisconnect,
        cancelOnError: true,
      );
    } catch (e) {
      _log('[ERR] Failed to connect: $e');
      _scheduleReconnect();
    }
  }

  void _onMessage(dynamic raw) {
    try {
      final rawStr = raw.toString();
      final data = jsonDecode(rawStr);
      if (data is! Map<String, dynamic>) {
        _log('[ERR] Unexpected message format');
        return;
      }
      final type = data['type']?.toString();

      switch (type) {
        case 'init':
          _connected = true;
          _aiEngine = (data['engine'] ?? 'unknown').toString();
          final hw = (data['hardware'] is Map)
              ? Map<String, dynamic>.from(data['hardware'])
              : <String, dynamic>{};
          _log('[SYS] Connected to Rakshak v${data['server_version']}');
          _log('[HW]  Device: ${hw['selected_device'] ?? 'Unknown'}');
          _log('[AI]  Engine: $_aiEngine');
          final features = data['features'];
          if (features is List) {
            _log('[SYS] Features: ${features.join(', ')}');
          }
          break;

        case 'metrics':
          _metrics = SystemMetrics.fromJson(data);
          _cpuHistory.removeAt(0);
          _cpuHistory.add(_metrics.cpuPercent);
          break;

        case 'threat':
          final threat = ThreatEvent.fromJson(data);
          _threats.insert(0, threat);
          if (_threats.length > 100) _threats.removeLast();
          _log('[THREAT] ${threat.verdict} | ${threat.processName}: ${threat.reason}');
          _log('[AI] ${threat.explanation}');
          _collectPatches(data);
          break;

        case 'behavioral':
          final beh = ThreatEvent.fromJson(data);
          _threats.insert(0, beh);
          if (_threats.length > 100) _threats.removeLast();
          _log('[BEHAVIORAL] ${beh.verdict} | ${beh.processName}: ${beh.reason}');
          _log('[AI] ${beh.explanation}');
          _collectPatches(data);
          break;

        case 'scan_finding':
          final scan = ThreatEvent.fromJson(data);
          _threats.insert(0, scan);
          if (_threats.length > 100) _threats.removeLast();
          _log('[SCAN] ${scan.verdict} | ${scan.processName}: ${scan.reason}');
          _log('[AI] ${scan.explanation}');
          _collectPatches(data);
          break;

        case 'patch_response':
          final patchId = (data['patch_id'] ?? '').toString();
          if (data['approved'] == true) {
            _log('[PATCH] $patchId approved successfully');
            _pendingPatches.removeWhere((p) => p.id == patchId);
          } else if (data['rejected'] == true) {
            _log('[PATCH] $patchId rejected');
            _pendingPatches.removeWhere((p) => p.id == patchId);
          }
          break;

        case 'patches_list':
          final list = data['patches'];
          if (list is List) {
            _pendingPatches.clear();
            for (final p in list) {
              if (p is Map) {
                _pendingPatches.add(PatchSuggestion.fromJson(Map<String, dynamic>.from(p)));
              }
            }
          }
          break;

        case 'pong':
          break;
      }
      notifyListeners();
    } catch (e, stack) {
      _log('[ERR] Parse error: $e');
      debugPrint('SentinelService parse error: $e\n$stack');
      notifyListeners();
    }
  }

  void _collectPatches(Map<String, dynamic> data) {
    final patches = data['patches'];
    if (patches is List && patches.isNotEmpty) {
      for (final p in patches) {
        if (p is Map) {
          final patch = PatchSuggestion.fromJson(Map<String, dynamic>.from(p));
          _log('[PATCH] ${patch.id} | ${patch.action} -> ${patch.target}');
          if (patch.status == 'pending') {
            _pendingPatches.add(patch);
          }
        }
      }
    }
  }

  void _onDisconnect() {
    if (!_connected && _reconnectTimer != null) return;
    _connected = false;
    _log('[SYS] Disconnected from sentinel.');
    notifyListeners();
    _scheduleReconnect();
  }

  void _scheduleReconnect() {
    _reconnectTimer?.cancel();
    _reconnectTimer = Timer(const Duration(seconds: 3), () {
      _log('[SYS] Attempting reconnection...');
      _connect();
    });
  }

  void _log(String message) {
    final ts = DateTime.now().toIso8601String().substring(11, 19);
    _consoleLogs.add('[$ts] $message');
    if (_consoleLogs.length > 500) _consoleLogs.removeAt(0);
  }

  void clearThreats() {
    _threats.clear();
    _log('[SYS] Threat log cleared.');
    notifyListeners();
  }

  void approvePatch(String patchId) {
    _channel?.sink.add(jsonEncode({'type': 'approve_patch', 'patch_id': patchId}));
    _log('[PATCH] Sending approval for $patchId...');
    _pendingPatches.removeWhere((p) => p.id == patchId);
    notifyListeners();
  }

  void rejectPatch(String patchId) {
    _channel?.sink.add(jsonEncode({'type': 'reject_patch', 'patch_id': patchId}));
    _log('[PATCH] Sending rejection for $patchId...');
    _pendingPatches.removeWhere((p) => p.id == patchId);
    notifyListeners();
  }

  void requestPatches() {
    _channel?.sink.add(jsonEncode({'type': 'get_patches'}));
  }

  @override
  void dispose() {
    _reconnectTimer?.cancel();
    _channel?.sink.close();
    super.dispose();
  }
}
